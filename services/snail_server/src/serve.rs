//! Async TCP servers that drive the (synchronous) protocol sessions over
//! sockets, plus the listener orchestration with graceful shutdown.
//!
//! Framing is UTF-8 line based; binary message bodies are a future enhancement.

use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::{Duration, SystemTime};

use access::{
    ImapCommand, ImapResponse, ImapSession, MsaSession, Pop3Session, PopCommand, PopReply,
    TaggedCommand,
};
use mail::{InboundCollector, SmtpCommand, SmtpSession};
use security::Decision;
use std::future::Future;

use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader, ReadBuf};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Notify, Semaphore};
use tokio_rustls::server::TlsStream;

use crate::dmarc_report::{REPORT_WINDOW, spawn_report_worker};
use crate::received::{
    MAX_RECEIVED_HOPS, authentication_results_header, received_header, received_spf_header,
};
use crate::server::{RelayAuthorization, Server};
use crate::worker::spawn_relay_worker;

/// How often the relay worker scans the spool for due messages.
const RELAY_WORKER_TICK: Duration = Duration::from_secs(30);

/// Maximum bytes in a single protocol line, including its terminator. A line over
/// this is rejected and the connection closed — an unbounded `read_line` on the
/// public port is a memory-exhaustion DoS (one enormous line with no newline).
const MAX_LINE_LENGTH: usize = 64 * 1024;

/// Outcome of a length-capped line read.
enum LineRead {
    /// A full line (terminator included) was read into the buffer as raw bytes.
    Read,
    /// The peer closed the connection.
    Eof,
    /// The line exceeded [`MAX_LINE_LENGTH`] before a newline arrived.
    TooLong,
}

/// Read one line (up to and including `\n`) into `buf` as **raw bytes**, never
/// buffering more than `max` bytes. On overflow it stops and returns
/// [`LineRead::TooLong`] **without draining the rest** — the caller closes the
/// connection, so the unread bytes are abandoned with the socket (draining would
/// re-introduce the unbounded read we are closing).
///
/// Bytes are kept verbatim (no UTF-8 decode): command lines are decoded leniently
/// at the call site for parsing, while `DATA` body lines are fed to the collector
/// as raw bytes so 8-bit/binary message content and DKIM signatures survive intact.
async fn read_line_capped<R: AsyncBufReadExt + Unpin>(
    reader: &mut R,
    buf: &mut Vec<u8>,
    max: usize,
) -> std::io::Result<LineRead> {
    buf.clear();
    loop {
        let chunk = reader.fill_buf().await?;
        if chunk.is_empty() {
            if buf.is_empty() {
                return Ok(LineRead::Eof);
            }
            // EOF mid-line (no trailing newline): take what arrived.
            return Ok(LineRead::Read);
        }
        let newline = chunk.iter().position(|&b| b == b'\n');
        let take = newline.map_or(chunk.len(), |p| p + 1);
        if buf.len() + take > max {
            let room = max - buf.len();
            buf.extend_from_slice(&chunk[..room]);
            reader.consume(room);
            return Ok(LineRead::TooLong);
        }
        buf.extend_from_slice(&chunk[..take]);
        reader.consume(take);
        if newline.is_some() {
            return Ok(LineRead::Read);
        }
    }
}

/// Per-listener cap on concurrently-served connections. Each listener has its own
/// budget so a flood on the unauthenticated inbound port cannot starve the
/// authenticated submission/POP3/IMAP listeners (a single global cap could).
/// Tune down on memory-constrained hosts; `0` effectively disables a listener.
#[derive(Debug, Clone, Copy)]
pub struct ConcurrencyLimits {
    /// Max concurrent submission connections.
    pub submission: usize,
    /// Max concurrent POP3 connections.
    pub pop3: usize,
    /// Max concurrent IMAP connections.
    pub imap: usize,
    /// Max concurrent inbound-MX connections (the unauthenticated public port).
    pub inbound: usize,
}

impl Default for ConcurrencyLimits {
    fn default() -> Self {
        // Authenticated ports: generous for a personal server. Inbound (public,
        // unauthenticated): a larger budget so legit MX-to-MX exchanges are not
        // squeezed, but still bounded.
        Self {
            submission: 256,
            pop3: 256,
            imap: 256,
            inbound: 512,
        }
    }
}

/// Bind addresses for the protocol listeners, plus their concurrency caps.
#[derive(Debug, Clone)]
pub struct Listeners {
    /// Authenticated submission (SMTP+AUTH), e.g. `127.0.0.1:587`.
    pub submission: String,
    /// POP3, e.g. `127.0.0.1:110`.
    pub pop3: String,
    /// IMAP, e.g. `127.0.0.1:143`.
    pub imap: String,
    /// Inbound MX reception (no-auth SMTP), e.g. `127.0.0.1:25` (`:2525` in dev).
    pub inbound: String,
    /// Per-listener concurrent-connection caps.
    pub limits: ConcurrencyLimits,
}

/// Bind all listeners and serve connections until Ctrl-C, spawning a task per
/// accepted connection.
///
/// # Errors
/// [`std::io::Error`] if a listener cannot bind.
pub async fn run(server: Arc<Server>, listeners: &Listeners) -> std::io::Result<()> {
    let submission = TcpListener::bind(&listeners.submission).await?;
    let pop3 = TcpListener::bind(&listeners.pop3).await?;
    let imap = TcpListener::bind(&listeners.imap).await?;
    let inbound = TcpListener::bind(&listeners.inbound).await?;
    tracing::info!(
        submission = %listeners.submission,
        pop3 = %listeners.pop3,
        imap = %listeners.imap,
        inbound = %listeners.inbound,
        relay = server.relay_context().is_some(),
        "snail-server listening"
    );

    // The relay worker and the DMARC aggregate-report worker both run only when
    // outbound relay is configured (reports are relayed to the rua address). Each
    // gets its own shutdown Notify so a single `notify_one` reaches it.
    let shutdown = Arc::new(Notify::new());
    let worker = server.relay_context().is_some().then(|| {
        spawn_relay_worker(
            Arc::clone(&server),
            Arc::clone(&shutdown),
            RELAY_WORKER_TICK,
        )
    });
    let report_shutdown = Arc::new(Notify::new());
    let report_worker = server.relay_context().is_some().then(|| {
        spawn_report_worker(
            Arc::clone(&server),
            Arc::clone(&report_shutdown),
            REPORT_WINDOW,
        )
    });

    // One bounded accept loop per listener (each with its own concurrency budget),
    // so the public inbound port cannot exhaust tasks/sockets nor starve the
    // authenticated listeners.
    let limits = listeners.limits;
    let loops = [
        tokio::spawn(accept_loop(
            "submission",
            submission,
            Arc::new(Semaphore::new(limits.submission)),
            Arc::clone(&server),
            serve_submission,
        )),
        tokio::spawn(accept_loop(
            "pop3",
            pop3,
            Arc::new(Semaphore::new(limits.pop3)),
            Arc::clone(&server),
            serve_pop,
        )),
        tokio::spawn(accept_loop(
            "imap",
            imap,
            Arc::new(Semaphore::new(limits.imap)),
            Arc::clone(&server),
            serve_imap,
        )),
        tokio::spawn(accept_loop(
            "inbound",
            inbound,
            Arc::new(Semaphore::new(limits.inbound)),
            Arc::clone(&server),
            serve_inbound_firewalled,
        )),
    ];

    tokio::signal::ctrl_c().await?;
    tracing::info!("shutdown signal received");

    // Stop accepting (abort is race-free; in-flight connection handlers are
    // independent tasks and finish or are dropped on process exit), then stop the
    // relay worker and let it finish its current tick.
    for handle in &loops {
        handle.abort();
    }
    for handle in loops {
        let _ = handle.await;
    }
    shutdown.notify_one();
    report_shutdown.notify_one();
    if let Some(worker) = worker {
        let _ = worker.await;
    }
    if let Some(report_worker) = report_worker {
        let _ = report_worker.await;
    }
    Ok(())
}

/// Accept connections on `listener` forever, serving each with `handler`, but
/// never more than the `sem` budget concurrently. A permit is acquired **before**
/// `accept` — at the cap the loop stalls here and stops accepting, so excess
/// connections back up in the OS queue (true backpressure) rather than spawning
/// unbounded tasks. The permit is held for the connection's lifetime.
async fn accept_loop<H, F>(
    name: &'static str,
    listener: TcpListener,
    sem: Arc<Semaphore>,
    server: Arc<Server>,
    handler: H,
) where
    H: Fn(TcpStream, SocketAddr, Arc<Server>) -> F + Send + 'static,
    F: Future<Output = std::io::Result<()>> + Send + 'static,
{
    loop {
        let Ok(permit) = Arc::clone(&sem).acquire_owned().await else {
            break; // semaphore closed
        };
        let (stream, peer) = match listener.accept().await {
            Ok(accepted) => accepted,
            Err(error) => {
                tracing::warn!(listener = name, %error, "accept failed");
                continue;
            }
        };
        let fut = handler(stream, peer, Arc::clone(&server));
        tokio::spawn(async move {
            let _permit = permit; // released when the connection handler ends
            if let Err(error) = fut.await {
                tracing::warn!(listener = name, %error, "connection handler ended with error");
            }
        });
    }
}

/// Firewall-gated entry to the public inbound port: rate-limited or blocklisted
/// peers get `421` and are dropped before any mail transaction; everyone else
/// is handed to [`serve_inbound`].
///
/// # Errors
/// [`std::io::Error`] on socket failure.
pub async fn serve_inbound_firewalled(
    stream: TcpStream,
    peer: SocketAddr,
    server: Arc<Server>,
) -> std::io::Result<()> {
    match server.firewall().check(peer.ip()) {
        Decision::Allow => serve_inbound(stream, peer, server).await,
        Decision::Deny(reason) => {
            tracing::warn!(peer = %peer, ?reason, "inbound connection denied by firewall");
            let (_read, mut write) = stream.into_split();
            write.write_all(b"421 Service not available\r\n").await?;
            Ok(())
        }
    }
}

/// Serve one authenticated-submission (SMTP) connection.
///
/// # Errors
/// [`std::io::Error`] on socket failure.
pub async fn serve_submission(
    stream: TcpStream,
    peer: SocketAddr,
    server: Arc<Server>,
) -> std::io::Result<()> {
    let has_tls = server.tls_config().is_some();
    let mut conn = BufReader::new(MaybeTlsStream::Plain(stream));
    let mut msa = MsaSession::new(server.authenticator());
    let mut collecting: Option<InboundCollector> = None;

    conn.write_all(b"220 Snail ESMTP ready\r\n").await?;
    let mut buf: Vec<u8> = Vec::new();
    loop {
        match read_line_capped(&mut conn, &mut buf, MAX_LINE_LENGTH).await? {
            LineRead::Read => {}
            LineRead::Eof => break,
            LineRead::TooLong => {
                conn.write_all(b"500 line too long; closing\r\n").await?;
                break;
            }
        }

        // DATA body mode: accumulate raw bytes (verbatim) until the lone "." line.
        if let Some(collector) = collecting.as_mut() {
            let done = collector.push_line(&buf);
            if collector.size_exceeded() {
                conn.write_all(b"552 message exceeds the maximum size; closing\r\n")
                    .await?;
                break;
            }
            if done {
                let collector = collecting.take().expect("collecting was Some");
                let helo = msa.helo().unwrap_or("unknown").to_string();
                let proto = if matches!(conn.get_ref(), MaybeTlsStream::Tls(_)) {
                    "ESMTPSA"
                } else {
                    "ESMTPA"
                };
                let reply = match msa.smtp_mut().take_envelope() {
                    Some(envelope) => match collector.into_message(envelope) {
                        Ok(mut message) => {
                            if message.received_header_count() >= MAX_RECEIVED_HOPS {
                                "554 too many Received headers; possible mail loop\r\n"
                            } else {
                                // Stamp the trace hop, then submit. Relaying to
                                // remote recipients is permitted on this path.
                                message.prepend_header(&received_header(
                                    &helo,
                                    server.host_name(),
                                    proto,
                                    SystemTime::now(),
                                ));
                                let _ =
                                    server.accept_inbound(message, RelayAuthorization::Permitted);
                                "250 OK message accepted\r\n"
                            }
                        }
                        Err(_) => "554 message parse error\r\n",
                    },
                    None => "554 no valid recipients\r\n",
                };
                conn.write_all(reply.as_bytes()).await?;
            }
            continue;
        }

        // Command mode: SMTP commands are ASCII, so a lenient decode is safe here
        // (only DATA body bytes, handled verbatim above, must never be re-encoded).
        let line = String::from_utf8_lossy(&buf);
        let trimmed = line.trim_end();

        // SASL PLAIN, initial-response form: `AUTH PLAIN <base64>`. When TLS is
        // on offer, refuse it in cleartext so credentials never cross unencrypted
        // (RFC 3207 §4; equivalent to Dovecot's `disable_plaintext_auth`).
        if let Some(rest) = strip_prefix_ci(trimmed, "AUTH PLAIN") {
            if has_tls && matches!(conn.get_ref(), MaybeTlsStream::Plain(_)) {
                conn.write_all(b"530 Must issue a STARTTLS command first\r\n")
                    .await?;
                continue;
            }
            // This attempt actually checks credentials, so it is subject to the
            // brute-force throttle. A locked-out IP is refused and disconnected.
            if !server.auth_throttle().check(peer.ip()) {
                conn.write_all(
                    b"421 4.7.0 too many failed authentication attempts; try again later\r\n",
                )
                .await?;
                break;
            }
            let reply = match rest.trim() {
                "" => SmtpReplyText::new(501, "AUTH PLAIN requires an initial response"),
                b64 => {
                    let r = msa.authenticate_plain(b64);
                    SmtpReplyText::new(r.code, &r.text)
                }
            };
            match reply.code {
                235 => server.auth_throttle().record_success(peer.ip()),
                535 => server.auth_throttle().record_failure(peer.ip()),
                _ => {} // malformed response (501): not a credential guess
            }
            conn.write_all(reply.to_wire().as_bytes()).await?;
            continue;
        }

        match SmtpCommand::parse(&line) {
            // STARTTLS: validated through the command parser (so `STARTTLS junk` is
            // a 500, not a silent upgrade) and the session state machine (so it is
            // refused mid-transaction). On success, upgrade the socket and reset the
            // session — the client re-issues EHLO over the encrypted channel.
            Ok(SmtpCommand::StartTls) => match server.tls_config() {
                Some(config) if matches!(conn.get_ref(), MaybeTlsStream::Plain(_)) => {
                    let reply = msa.handle(SmtpCommand::StartTls);
                    if reply.code != 220 {
                        conn.write_all(format!("{} {}\r\n", reply.code, reply.text).as_bytes())
                            .await?;
                    } else if !conn.buffer().is_empty() {
                        conn.write_all(b"503 no pipelining before STARTTLS\r\n")
                            .await?;
                    } else {
                        conn.write_all(b"220 Ready to start TLS\r\n").await?;
                        conn = accept_tls(conn, config).await?;
                        msa = MsaSession::new(server.authenticator());
                    }
                }
                _ => {
                    conn.write_all(b"502 STARTTLS not available\r\n").await?;
                }
            },
            // EHLO/HELO: advertise STARTTLS while plaintext with TLS available, or
            // AUTH once the channel is encrypted; a plain greeting when no TLS is
            // configured at all (so existing plaintext-only deployments still work).
            Ok(command @ (SmtpCommand::Ehlo(_) | SmtpCommand::Helo(_))) => {
                let reply = msa.handle(command);
                let is_plain = matches!(conn.get_ref(), MaybeTlsStream::Plain(_));
                if has_tls && is_plain {
                    conn.write_all(format!("250-{}\r\n250 STARTTLS\r\n", reply.text).as_bytes())
                        .await?;
                } else if !is_plain {
                    conn.write_all(format!("250-{}\r\n250 AUTH PLAIN\r\n", reply.text).as_bytes())
                        .await?;
                } else {
                    conn.write_all(format!("{} {}\r\n", reply.code, reply.text).as_bytes())
                        .await?;
                }
            }
            Ok(command) => {
                let is_quit = matches!(command, SmtpCommand::Quit);
                let reply = msa.handle(command);
                conn.write_all(format!("{} {}\r\n", reply.code, reply.text).as_bytes())
                    .await?;
                if reply.code == 354 {
                    collecting = Some(InboundCollector::with_max_size(server.max_message_size()));
                }
                if is_quit {
                    break;
                }
            }
            Err(error) => {
                conn.write_all(format!("500 {error}\r\n").as_bytes())
                    .await?;
            }
        }
    }
    Ok(())
}

/// Serve one inbound MX connection: a no-auth SMTP *receiver* on the public
/// port. Accepts mail from external senders to **local** recipients only — a
/// `RCPT` to a non-local mailbox is refused (`550`) so Snail is never an open
/// relay. When the server has TLS configured, `STARTTLS` is advertised in EHLO
/// and upgrades the connection before the mail transaction.
///
/// # Errors
/// [`std::io::Error`] on socket failure or a failed TLS handshake.
pub async fn serve_inbound(
    stream: TcpStream,
    peer: SocketAddr,
    server: Arc<Server>,
) -> std::io::Result<()> {
    let tls = server.tls_config();
    let mut conn = BufReader::new(MaybeTlsStream::Plain(stream));
    let mut session = SmtpSession::new();
    let mut collecting: Option<InboundCollector> = None;

    conn.write_all(b"220 Snail ESMTP ready\r\n").await?;
    let mut buf: Vec<u8> = Vec::new();
    loop {
        match read_line_capped(&mut conn, &mut buf, MAX_LINE_LENGTH).await? {
            LineRead::Read => {}
            LineRead::Eof => break,
            LineRead::TooLong => {
                conn.write_all(b"500 line too long; closing\r\n").await?;
                break;
            }
        }

        // DATA body mode: accumulate raw bytes (verbatim) until the lone "." line,
        // then deliver.
        if let Some(collector) = collecting.as_mut() {
            let done = collector.push_line(&buf);
            if collector.size_exceeded() {
                conn.write_all(b"552 message exceeds the maximum size; closing\r\n")
                    .await?;
                break;
            }
            if done {
                let collector = collecting.take().expect("collecting was Some");
                let helo = session.helo().unwrap_or("unknown").to_string();
                let proto = if matches!(conn.get_ref(), MaybeTlsStream::Tls(_)) {
                    "ESMTPS"
                } else {
                    "ESMTP"
                };
                let reply: &str = match session.take_envelope() {
                    None => "554 no valid recipients\r\n",
                    Some(envelope) => {
                        let mail_from = envelope
                            .sender
                            .as_ref()
                            .map(ToString::to_string)
                            .unwrap_or_default();
                        match collector.into_message(envelope) {
                            Err(_) => "554 message parse error\r\n",
                            Ok(message) if message.received_header_count() >= MAX_RECEIVED_HOPS => {
                                // RFC 5321 §6.3 loop breaker: refuse a looping message
                                // rather than deliver/relay it. (`message` is dropped.)
                                let _ = message;
                                "554 too many Received headers; possible mail loop\r\n"
                            }
                            Ok(mut message) => {
                                // Inbound authentication (when a resolver is configured).
                                let resolver = server.resolver();
                                // SPF (RFC 7208): connecting IP vs the MAIL FROM identity.
                                let spf = match &resolver {
                                    Some(r) => Some(
                                        network::evaluate_spf(
                                            r.as_ref(),
                                            peer.ip(),
                                            &helo,
                                            &mail_from,
                                        )
                                        .await,
                                    ),
                                    None => None,
                                };
                                if matches!(spf, Some(network::SpfResult::Fail))
                                    && server.spf_enforce()
                                {
                                    tracing::warn!(peer = %peer, %mail_from, "SPF fail; rejecting (enforcement enabled)");
                                    "550 5.7.23 SPF validation failed\r\n"
                                } else {
                                    // DKIM (RFC 6376 / RFC 8463): verify over the bytes
                                    // AS RECEIVED, before we prepend any trace headers.
                                    let dkim = match &resolver {
                                        Some(r) => {
                                            network::verify_dkim(r.as_ref(), &message.to_bytes())
                                                .await
                                        }
                                        None => Vec::new(),
                                    };

                                    // DMARC (RFC 7489): align the From: domain against the
                                    // SPF/DKIM results under the domain's published policy.
                                    let from_domain = message
                                        .headers
                                        .get("From")
                                        .and_then(from_header_domain)
                                        .unwrap_or_default();
                                    let spf_result = spf.unwrap_or(network::SpfResult::None);
                                    let spf_domain = mail_from
                                        .rsplit_once('@')
                                        .map_or(helo.as_str(), |(_, d)| d);
                                    let dkim_pass: Vec<&str> = dkim
                                        .iter()
                                        .filter(|o| o.result == network::DkimResult::Pass)
                                        .map(|o| o.domain.as_str())
                                        .collect();
                                    let dmarc = match &resolver {
                                        Some(r) if !from_domain.is_empty() => Some(
                                            network::evaluate_dmarc(
                                                r.as_ref(),
                                                &from_domain,
                                                spf_result,
                                                spf_domain,
                                                &dkim_pass,
                                            )
                                            .await,
                                        ),
                                        _ => None,
                                    };
                                    // Fold this result into the aggregate report (all
                                    // results, pass or fail, including rejected ones).
                                    if let Some(result) = dmarc.as_ref() {
                                        let dkim_report: Vec<(String, String)> = dkim
                                            .iter()
                                            .map(|o| {
                                                (o.domain.clone(), o.result.as_str().to_string())
                                            })
                                            .collect();
                                        server.dmarc_aggregator().record(
                                            result,
                                            peer.ip(),
                                            &from_domain,
                                            spf_domain,
                                            spf_result.as_str(),
                                            &dkim_report,
                                        );
                                    }
                                    let dmarc_reject = server.dmarc_enforce()
                                        && matches!(
                                            dmarc.as_ref().map(|d| d.disposition),
                                            Some(network::DmarcDisposition::Reject)
                                        );

                                    if dmarc_reject {
                                        tracing::warn!(peer = %peer, %from_domain, "DMARC reject; refusing (enforcement enabled)");
                                        "550 5.7.1 DMARC policy: message rejected\r\n"
                                    } else {
                                        // A quarantine disposition is recorded (and logged)
                                        // but still delivered: Snail has no separate junk
                                        // store, so the Authentication-Results header is how
                                        // a client filters it. Routing to a junk folder is a
                                        // future MDA enhancement.
                                        if server.dmarc_enforce()
                                            && matches!(
                                                dmarc.as_ref().map(|d| d.disposition),
                                                Some(network::DmarcDisposition::Quarantine)
                                            )
                                        {
                                            tracing::warn!(peer = %peer, %from_domain, "DMARC quarantine (delivered; marked in Authentication-Results)");
                                        }
                                        // Stamp Authentication-Results (SPF + DKIM + DMARC),
                                        // then Received-SPF, then the trace hop on top. No-auth
                                        // inbound: recipients were vetted local at RCPT time and
                                        // relay is forbidden here, so this delivers locally only.
                                        message.prepend_header(&authentication_results_header(
                                            server.host_name(),
                                            spf,
                                            &mail_from,
                                            &dkim,
                                            dmarc.as_ref().map(network::DmarcResult::as_str),
                                            &from_domain,
                                        ));
                                        if let Some(result) = spf {
                                            message.prepend_header(&received_spf_header(
                                                result.as_str(),
                                                server.host_name(),
                                                &peer.ip().to_string(),
                                                &mail_from,
                                                &helo,
                                            ));
                                        }
                                        message.prepend_header(&received_header(
                                            &helo,
                                            server.host_name(),
                                            proto,
                                            SystemTime::now(),
                                        ));
                                        let _ = server
                                            .accept_inbound(message, RelayAuthorization::Forbidden);
                                        "250 OK message accepted\r\n"
                                    }
                                }
                            }
                        }
                    }
                };
                conn.write_all(reply.as_bytes()).await?;
            }
            continue;
        }

        // Command mode: SMTP commands are ASCII, so a lenient decode is safe here
        // (only DATA body bytes, handled verbatim above, must never be re-encoded).
        let line = String::from_utf8_lossy(&buf);
        match SmtpCommand::parse(&line) {
            // STARTTLS: validated through the command parser (so `STARTTLS junk` is
            // a 500, not a silent upgrade) and the session state machine (so it is
            // refused mid-transaction). On success, upgrade the socket and reset the
            // session — the client re-issues EHLO over the encrypted channel.
            Ok(SmtpCommand::StartTls) => match &tls {
                Some(config) if matches!(conn.get_ref(), MaybeTlsStream::Plain(_)) => {
                    let reply = session.handle(SmtpCommand::StartTls);
                    if reply.code != 220 {
                        conn.write_all(reply.to_wire().as_bytes()).await?;
                    } else if !conn.buffer().is_empty() {
                        conn.write_all(b"503 no pipelining before STARTTLS\r\n")
                            .await?;
                    } else {
                        conn.write_all(b"220 Ready to start TLS\r\n").await?;
                        conn = accept_tls(conn, Arc::clone(config)).await?;
                        session = SmtpSession::new();
                    }
                }
                _ => {
                    conn.write_all(b"502 STARTTLS not available\r\n").await?;
                }
            },
            // EHLO/HELO: advertise STARTTLS as a multiline reply while still in
            // plaintext with TLS available; otherwise a plain greeting.
            Ok(command @ (SmtpCommand::Ehlo(_) | SmtpCommand::Helo(_))) => {
                let reply = session.handle(command);
                if tls.is_some() && matches!(conn.get_ref(), MaybeTlsStream::Plain(_)) {
                    conn.write_all(format!("250-{}\r\n250 STARTTLS\r\n", reply.text).as_bytes())
                        .await?;
                } else {
                    conn.write_all(reply.to_wire().as_bytes()).await?;
                }
            }
            // No open relay: refuse RCPT to recipients we do not host.
            Ok(SmtpCommand::RcptTo(rcpt)) if !server.is_local(&rcpt) => {
                conn.write_all(format!("550 <{rcpt}> relay not permitted\r\n").as_bytes())
                    .await?;
            }
            Ok(command) => {
                let is_quit = matches!(command, SmtpCommand::Quit);
                let reply = session.handle(command);
                conn.write_all(reply.to_wire().as_bytes()).await?;
                if reply.code == 354 {
                    collecting = Some(InboundCollector::with_max_size(server.max_message_size()));
                }
                if is_quit {
                    break;
                }
            }
            Err(error) => {
                conn.write_all(format!("500 {error}\r\n").as_bytes())
                    .await?;
            }
        }
    }
    Ok(())
}

/// A client-facing stream that may be upgraded from plaintext to TLS mid-session
/// by `STARTTLS` (SMTP/IMAP) or `STLS` (POP3). Shared by all four protocol loops.
/// Both variants are `Unpin`, so the delegating poll impls need no `pin-project`.
pub enum MaybeTlsStream {
    /// Plaintext TCP (before the TLS upgrade).
    Plain(TcpStream),
    /// TLS, after a successful upgrade.
    Tls(Box<TlsStream<TcpStream>>),
}

impl AsyncRead for MaybeTlsStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            MaybeTlsStream::Plain(s) => Pin::new(s).poll_read(cx, buf),
            MaybeTlsStream::Tls(s) => Pin::new(&mut **s).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for MaybeTlsStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        match self.get_mut() {
            MaybeTlsStream::Plain(s) => Pin::new(s).poll_write(cx, buf),
            MaybeTlsStream::Tls(s) => Pin::new(&mut **s).poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            MaybeTlsStream::Plain(s) => Pin::new(s).poll_flush(cx),
            MaybeTlsStream::Tls(s) => Pin::new(&mut **s).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            MaybeTlsStream::Plain(s) => Pin::new(s).poll_shutdown(cx),
            MaybeTlsStream::Tls(s) => Pin::new(&mut **s).poll_shutdown(cx),
        }
    }
}

/// Complete the server-side TLS handshake on a connection that has just sent its
/// protocol "ready" reply, returning the upgraded connection.
///
/// Preconditions the caller MUST have established:
/// 1. the protocol "ready to start TLS" reply has already been written,
/// 2. the connection is still [`MaybeTlsStream::Plain`] (not already TLS), and
/// 3. the read buffer is empty (no client data was pipelined before the upgrade).
async fn accept_tls(
    conn: BufReader<MaybeTlsStream>,
    config: Arc<rustls::ServerConfig>,
) -> std::io::Result<BufReader<MaybeTlsStream>> {
    let MaybeTlsStream::Plain(tcp) = conn.into_inner() else {
        unreachable!("caller guaranteed a plaintext connection")
    };
    let upgraded = network::tls::accept(config, tcp)
        .await
        .map_err(std::io::Error::other)?;
    Ok(BufReader::new(MaybeTlsStream::Tls(Box::new(upgraded))))
}

/// Whether an auth command on this connection will actually verify credentials,
/// rather than being refused by the TLS-required policy (LOGINDISABLED / pre-STLS
/// / pre-STARTTLS). Only credential-checking attempts are counted toward the
/// brute-force throttle, so a client that merely ignores the "encrypt first"
/// policy is not locked out.
fn credentials_checked(has_tls: bool, conn: &BufReader<MaybeTlsStream>) -> bool {
    !has_tls || matches!(conn.get_ref(), MaybeTlsStream::Tls(_))
}

/// Serve one POP3 connection.
///
/// # Errors
/// [`std::io::Error`] on socket failure.
pub async fn serve_pop(
    stream: TcpStream,
    peer: SocketAddr,
    server: Arc<Server>,
) -> std::io::Result<()> {
    let has_tls = server.tls_config().is_some();
    let mut conn = BufReader::new(MaybeTlsStream::Plain(stream));
    let mut session = if has_tls {
        Pop3Session::with_tls(server.authenticator(), server.store(), false)
    } else {
        Pop3Session::new(server.authenticator(), server.store())
    };

    conn.write_all(b"+OK Snail POP3 ready\r\n").await?;
    let mut buf: Vec<u8> = Vec::new();
    loop {
        match read_line_capped(&mut conn, &mut buf, MAX_LINE_LENGTH).await? {
            LineRead::Read => {}
            LineRead::Eof => break,
            LineRead::TooLong => {
                conn.write_all(b"-ERR line too long; closing\r\n").await?;
                break;
            }
        }
        // POP3 commands are ASCII; a lenient decode is safe. (Message bytes flow
        // the other way — see `write_pop_reply`, which emits them verbatim.)
        let line = String::from_utf8_lossy(&buf);
        let is_quit = line.trim_end().eq_ignore_ascii_case("QUIT");
        match PopCommand::parse(&line) {
            // STLS: upgrade the socket, then resume in a fresh (encrypted)
            // authorization phase (RFC 2595).
            Ok(PopCommand::Stls) => {
                if !conn.buffer().is_empty() {
                    conn.write_all(b"-ERR no pipelining before STLS\r\n")
                        .await?;
                    continue;
                }
                let is_plain = matches!(conn.get_ref(), MaybeTlsStream::Plain(_));
                let reply = session.handle(PopCommand::Stls);
                write_pop_reply(&mut conn, &reply).await?;
                if reply.ok
                    && is_plain
                    && let Some(config) = server.tls_config()
                {
                    conn = accept_tls(conn, config).await?;
                    session = Pop3Session::with_tls(server.authenticator(), server.store(), true);
                }
                continue;
            }
            // PASS is the credential guess. When it actually checks credentials
            // (i.e. not refused by the pre-STLS policy), it is throttled per IP.
            Ok(command @ PopCommand::Pass(_)) if credentials_checked(has_tls, &conn) => {
                if !server.auth_throttle().check(peer.ip()) {
                    conn.write_all(b"-ERR [AUTH] too many failed attempts; try again later\r\n")
                        .await?;
                    break;
                }
                let reply = session.handle(command);
                if reply.ok {
                    server.auth_throttle().record_success(peer.ip());
                } else {
                    server.auth_throttle().record_failure(peer.ip());
                }
                write_pop_reply(&mut conn, &reply).await?;
            }
            Ok(command) => {
                let reply = session.handle(command);
                write_pop_reply(&mut conn, &reply).await?;
            }
            Err(error) => {
                conn.write_all(format!("-ERR {error}\r\n").as_bytes())
                    .await?;
            }
        }
        if is_quit {
            break;
        }
    }
    Ok(())
}

async fn write_pop_reply<W: AsyncWrite + Unpin>(
    write: &mut W,
    reply: &PopReply,
) -> std::io::Result<()> {
    let status = if reply.ok { "+OK" } else { "-ERR" };
    write
        .write_all(format!("{status} {}\r\n", reply.message).as_bytes())
        .await?;
    if !reply.ok {
        return Ok(());
    }
    if let Some(body) = &reply.body {
        // RETR: emit the raw message bytes verbatim, dot-stuffed and terminated
        // (`mail::dot_stuff` appends the final `.\r\n`). No lossy re-encoding.
        write.write_all(&mail::dot_stuff(body)).await?;
    } else if !reply.lines.is_empty() {
        for line in &reply.lines {
            if line.starts_with('.') {
                write.write_all(b".").await?; // dot-stuffing
            }
            write.write_all(line.as_bytes()).await?;
            write.write_all(b"\r\n").await?;
        }
        write.write_all(b".\r\n").await?;
    }
    Ok(())
}

/// Serve one IMAP connection.
///
/// # Errors
/// [`std::io::Error`] on socket failure.
pub async fn serve_imap(
    stream: TcpStream,
    peer: SocketAddr,
    server: Arc<Server>,
) -> std::io::Result<()> {
    let has_tls = server.tls_config().is_some();
    let mut conn = BufReader::new(MaybeTlsStream::Plain(stream));
    let mut session = if has_tls {
        ImapSession::with_tls(server.authenticator(), server.store(), false)
    } else {
        ImapSession::new(server.authenticator(), server.store())
    };

    conn.write_all(b"* OK Snail IMAP4rev1 ready\r\n").await?;
    let mut buf: Vec<u8> = Vec::new();
    loop {
        match read_line_capped(&mut conn, &mut buf, MAX_LINE_LENGTH).await? {
            LineRead::Read => {}
            LineRead::Eof => break,
            LineRead::TooLong => {
                conn.write_all(b"* BAD line too long; closing\r\n").await?;
                break;
            }
        }
        // IMAP command lines are ASCII; a lenient decode is safe. (FETCH literals
        // flow out as raw bytes — see `write_imap_response`.)
        let line = String::from_utf8_lossy(&buf);
        match TaggedCommand::parse(&line) {
            // STARTTLS: upgrade the socket, then resume in a fresh (encrypted)
            // session — the client re-issues commands over TLS (RFC 2595).
            Ok(tagged) if matches!(tagged.command, ImapCommand::StartTls) => {
                if !conn.buffer().is_empty() {
                    conn.write_all(
                        format!(
                            "{} BAD pipelining not allowed before STARTTLS\r\n",
                            tagged.tag
                        )
                        .as_bytes(),
                    )
                    .await?;
                    continue;
                }
                let is_plain = matches!(conn.get_ref(), MaybeTlsStream::Plain(_));
                let response = session.handle(tagged);
                write_imap_response(&mut conn, &response).await?;
                if is_plain && let Some(config) = server.tls_config() {
                    conn = accept_tls(conn, config).await?;
                    session = ImapSession::with_tls(server.authenticator(), server.store(), true);
                }
            }
            // LOGIN is the credential guess. When it actually checks credentials
            // (i.e. not refused by LOGINDISABLED), it is throttled per IP.
            Ok(tagged)
                if matches!(tagged.command, ImapCommand::Login { .. })
                    && credentials_checked(has_tls, &conn) =>
            {
                let tag = tagged.tag.clone();
                if !server.auth_throttle().check(peer.ip()) {
                    conn.write_all(
                        format!(
                            "{tag} NO [UNAVAILABLE] too many failed attempts; try again later\r\n"
                        )
                        .as_bytes(),
                    )
                    .await?;
                    break;
                }
                let response = session.handle(tagged);
                // The tagged status is `<tag> OK ...` on success, `<tag> NO ...` on
                // a credential mismatch.
                if response.status.split_whitespace().nth(1) == Some("OK") {
                    server.auth_throttle().record_success(peer.ip());
                } else {
                    server.auth_throttle().record_failure(peer.ip());
                }
                write_imap_response(&mut conn, &response).await?;
            }
            Ok(tagged) => {
                let is_logout = matches!(tagged.command, ImapCommand::Logout);
                let response = session.handle(tagged);
                write_imap_response(&mut conn, &response).await?;
                if is_logout {
                    break;
                }
            }
            Err(error) => {
                conn.write_all(format!("* BAD {error}\r\n").as_bytes())
                    .await?;
            }
        }
    }
    Ok(())
}

/// Write an IMAP response: each untagged line as `* <line>`, then an optional
/// binary `FETCH` literal (emitted verbatim, with the announced `{N}` length
/// equal to the bytes written), then the tagged status line.
async fn write_imap_response<W: AsyncWrite + Unpin>(
    write: &mut W,
    response: &ImapResponse,
) -> std::io::Result<()> {
    for untagged in &response.untagged {
        write
            .write_all(format!("* {untagged}\r\n").as_bytes())
            .await?;
    }
    if let Some(lit) = &response.fetch_literal {
        // RFC 3501 literal: `* <seq> FETCH (RFC822 {<len>}\r\n<octets>)\r\n`. The
        // octets are written raw, so the declared length matches exactly and 8-bit
        // content is never corrupted.
        write
            .write_all(
                format!("* {} FETCH (RFC822 {{{}}}\r\n", lit.seq, lit.octets.len()).as_bytes(),
            )
            .await?;
        write.write_all(&lit.octets).await?;
        write.write_all(b")\r\n").await?;
    }
    write
        .write_all(format!("{}\r\n", response.status).as_bytes())
        .await?;
    Ok(())
}

/// A tiny SMTP reply formatter for AUTH replies (the MSA returns a `mail::SmtpReply`).
struct SmtpReplyText {
    code: u16,
    text: String,
}
impl SmtpReplyText {
    fn new(code: u16, text: &str) -> Self {
        Self {
            code,
            text: text.to_string(),
        }
    }
    fn to_wire(&self) -> String {
        format!("{} {}\r\n", self.code, self.text)
    }
}

/// Extract the domain of the address in an RFC 5322 `From:` header value — the
/// DMARC identifier. Handles both `Display Name <addr@domain>` and a bare
/// `addr@domain`. Returns the lowercased domain, or `None` if no address is found.
fn from_header_domain(value: &str) -> Option<String> {
    let addr = match (value.rfind('<'), value.rfind('>')) {
        (Some(l), Some(r)) if l < r => &value[l + 1..r],
        _ => value.trim(),
    };
    let domain = addr.rsplit_once('@')?.1.trim().trim_end_matches('>').trim();
    (!domain.is_empty()).then(|| domain.to_ascii_lowercase())
}

/// Case-insensitive `strip_prefix`.
fn strip_prefix_ci<'a>(s: &'a str, prefix: &str) -> Option<&'a str> {
    if s.len() >= prefix.len() && s[..prefix.len()].eq_ignore_ascii_case(prefix) {
        Some(&s[prefix.len()..])
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ServerConfig;
    use base64::Engine as _;
    use base64::engine::general_purpose::STANDARD as BASE64;
    use mail::MailStore;

    /// Read a single CRLF-terminated line from the client side.
    async fn read_line<R: tokio::io::AsyncBufRead + Unpin>(r: &mut R) -> String {
        let mut buf = String::new();
        r.read_line(&mut buf).await.unwrap();
        buf.trim_end().to_string()
    }

    #[tokio::test]
    async fn tcp_submit_then_pop_retrieve() {
        // Compose a server with one local user.
        let mut server = Server::new(&ServerConfig::new(["example.com".to_string()]));
        server.register_user("bob@example.com", "pw").unwrap();
        let server = Arc::new(server);

        // Bind submission + POP on ephemeral ports; serve one connection each.
        let sub = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let pop = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let sub_addr = sub.local_addr().unwrap();
        let pop_addr = pop.local_addr().unwrap();
        {
            let srv = Arc::clone(&server);
            tokio::spawn(async move {
                let (s, peer) = sub.accept().await.unwrap();
                serve_submission(s, peer, srv).await.unwrap();
            });
        }
        {
            let srv = Arc::clone(&server);
            tokio::spawn(async move {
                let (s, peer) = pop.accept().await.unwrap();
                serve_pop(s, peer, srv).await.unwrap();
            });
        }

        // ---- Submit a message over SMTP+AUTH ----
        let client = TcpStream::connect(sub_addr).await.unwrap();
        let (cr, mut cw) = client.into_split();
        let mut cr = BufReader::new(cr);
        assert!(read_line(&mut cr).await.starts_with("220"));
        let auth = BASE64.encode("\0bob@example.com\0pw");
        for (cmd, expect) in [
            ("EHLO client".to_string(), "250"),
            (format!("AUTH PLAIN {auth}"), "235"),
            ("MAIL FROM:<bob@example.com>".to_string(), "250"),
            ("RCPT TO:<bob@example.com>".to_string(), "250"),
            ("DATA".to_string(), "354"),
        ] {
            cw.write_all(format!("{cmd}\r\n").as_bytes()).await.unwrap();
            assert!(read_line(&mut cr).await.starts_with(expect), "cmd {cmd}");
        }
        cw.write_all(b"Subject: TCP test\r\n\r\nhello over tcp\r\n.\r\n")
            .await
            .unwrap();
        assert!(read_line(&mut cr).await.starts_with("250")); // message accepted
        cw.write_all(b"QUIT\r\n").await.unwrap();

        // ---- Retrieve it over POP3 ----
        let client = TcpStream::connect(pop_addr).await.unwrap();
        let (cr, mut cw) = client.into_split();
        let mut cr = BufReader::new(cr);
        assert!(read_line(&mut cr).await.starts_with("+OK"));
        cw.write_all(b"USER bob@example.com\r\n").await.unwrap();
        assert!(read_line(&mut cr).await.starts_with("+OK"));
        cw.write_all(b"PASS pw\r\n").await.unwrap();
        assert!(read_line(&mut cr).await.starts_with("+OK"));
        cw.write_all(b"RETR 1\r\n").await.unwrap();
        // Status line then the message lines then ".".
        assert!(read_line(&mut cr).await.starts_with("+OK"));
        let mut body = String::new();
        loop {
            let line = read_line(&mut cr).await;
            if line == "." {
                break;
            }
            body.push_str(&line);
            body.push('\n');
        }
        assert!(body.contains("Subject: TCP test"));
        assert!(body.contains("hello over tcp"));
        cw.write_all(b"QUIT\r\n").await.unwrap();
        let _ = cw.shutdown().await;
    }

    #[tokio::test]
    async fn tcp_inbound_delivers_local_and_refuses_relay() {
        // example.com is hosted here; elsewhere.org is not.
        let server = Arc::new(Server::new(&ServerConfig::new(["example.com".to_string()])));
        let inbound = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = inbound.local_addr().unwrap();
        {
            let srv = Arc::clone(&server);
            tokio::spawn(async move {
                let (s, peer) = inbound.accept().await.unwrap();
                serve_inbound(s, peer, srv).await.unwrap();
            });
        }

        let client = TcpStream::connect(addr).await.unwrap();
        let (cr, mut cw) = client.into_split();
        let mut cr = BufReader::new(cr);
        assert!(read_line(&mut cr).await.starts_with("220"));

        // An external sender delivers to a local recipient; an open-relay attempt
        // to a non-local recipient in the same session is refused (550).
        for (cmd, expect) in [
            ("EHLO mx.remote.net", "250"),
            ("MAIL FROM:<alice@remote.net>", "250"),
            ("RCPT TO:<bob@example.com>", "250"),
            ("RCPT TO:<eve@elsewhere.org>", "550"),
            ("DATA", "354"),
        ] {
            cw.write_all(format!("{cmd}\r\n").as_bytes()).await.unwrap();
            assert!(read_line(&mut cr).await.starts_with(expect), "cmd {cmd}");
        }
        cw.write_all(b"Subject: external\r\n\r\nhi bob\r\n.\r\n")
            .await
            .unwrap();
        assert!(read_line(&mut cr).await.starts_with("250")); // accepted
        cw.write_all(b"QUIT\r\n").await.unwrap();

        // bob (local) received the mail; eve (relay-refused) did not.
        assert_eq!(server.store().count("bob@example.com"), 1);
        assert_eq!(server.store().count("eve@elsewhere.org"), 0);
    }

    #[tokio::test]
    async fn tcp_inbound_starttls_then_deliver() {
        // Self-signed cert for `localhost`; enable STARTTLS on the receiver.
        let ck = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
        let cert_pem = ck.cert.pem();
        let certs = mail::MailCerts::new(cert_pem.clone(), ck.key_pair.serialize_pem()).unwrap();
        let server = Arc::new(
            Server::new(&ServerConfig::new(["example.com".to_string()]))
                .with_tls(&certs)
                .unwrap(),
        );
        let inbound = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = inbound.local_addr().unwrap();
        {
            let srv = Arc::clone(&server);
            tokio::spawn(async move {
                let (s, peer) = inbound.accept().await.unwrap();
                serve_inbound(s, peer, srv).await.unwrap();
            });
        }

        // Plaintext: greeting, then EHLO advertises STARTTLS as a multiline reply.
        let tcp = TcpStream::connect(addr).await.unwrap();
        let (r, mut w) = tcp.into_split();
        let mut r = BufReader::new(r);
        assert!(read_line(&mut r).await.starts_with("220"));
        w.write_all(b"EHLO client\r\n").await.unwrap();
        assert!(read_line(&mut r).await.starts_with("250-")); // continuation line
        assert!(read_line(&mut r).await.contains("STARTTLS")); // final capability
        w.write_all(b"STARTTLS\r\n").await.unwrap();
        assert!(read_line(&mut r).await.starts_with("220")); // ready to start TLS

        // Upgrade the client side: rejoin the split halves and handshake.
        let tcp = r.into_inner().reunite(w).unwrap();
        let client_config = network::TlsConfig::client_trusting_pem(&cert_pem).unwrap();
        let tls = network::tls::connect(client_config, "localhost", tcp)
            .await
            .unwrap();
        let (tr, mut tw) = tokio::io::split(tls);
        let mut tr = BufReader::new(tr);

        // Re-EHLO and run the full transaction over the encrypted channel.
        for (cmd, expect) in [
            ("EHLO client", "250"),
            ("MAIL FROM:<alice@remote.net>", "250"),
            ("RCPT TO:<bob@example.com>", "250"),
            ("DATA", "354"),
        ] {
            tw.write_all(format!("{cmd}\r\n").as_bytes()).await.unwrap();
            assert!(read_line(&mut tr).await.starts_with(expect), "cmd {cmd}");
        }
        tw.write_all(b"Subject: secure\r\n\r\nover tls\r\n.\r\n")
            .await
            .unwrap();
        assert!(read_line(&mut tr).await.starts_with("250")); // accepted over TLS
        tw.write_all(b"QUIT\r\n").await.unwrap();

        assert_eq!(server.store().count("bob@example.com"), 1);
    }

    #[tokio::test]
    async fn inbound_firewall_rate_limits_a_flood() {
        use governor::Quota;
        use security::FirewallConfig;
        use std::num::NonZeroU32;

        // A tight per-IP burst of 2: the first connections from a peer are
        // greeted, further rapid ones are refused with 421.
        let config = FirewallConfig {
            quota: Quota::per_minute(NonZeroU32::new(2).unwrap()),
            ..FirewallConfig::default()
        };
        let server = Arc::new(
            Server::new(&ServerConfig::new(["example.com".to_string()])).with_firewall(&config),
        );
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        {
            let srv = Arc::clone(&server);
            tokio::spawn(async move {
                loop {
                    let (stream, peer) = listener.accept().await.unwrap();
                    let srv = Arc::clone(&srv);
                    tokio::spawn(async move {
                        let _ = serve_inbound_firewalled(stream, peer, srv).await;
                    });
                }
            });
        }

        // All connections originate from the one loopback IP, so after the burst
        // the firewall answers 421 in place of the 220 greeting.
        let mut greetings = Vec::new();
        for _ in 0..6 {
            let client = TcpStream::connect(addr).await.unwrap();
            let (cr, _cw) = client.into_split();
            let mut cr = BufReader::new(cr);
            greetings.push(read_line(&mut cr).await);
        }
        let greeted = greetings.iter().filter(|g| g.starts_with("220")).count();
        let denied = greetings.iter().filter(|g| g.starts_with("421")).count();
        assert!(
            greeted >= 1,
            "burst should admit the first peers: {greetings:?}"
        );
        assert!(
            denied >= 1,
            "flood beyond burst must be rate-limited: {greetings:?}"
        );
    }

    /// A self-signed cert for `localhost`: the PEM (for the test client to trust)
    /// and the `MailCerts` (for the server's STARTTLS config).
    fn localhost_certs() -> (String, mail::MailCerts) {
        let ck = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
        let cert_pem = ck.cert.pem();
        let certs = mail::MailCerts::new(cert_pem.clone(), ck.key_pair.serialize_pem()).unwrap();
        (cert_pem, certs)
    }

    /// Deliver one message into `mailbox`'s store so POP/IMAP have something to
    /// retrieve over TLS.
    fn seed_message(server: &Server, mailbox: &str, body: &str) {
        let msg = mail::Message::parse(
            mail::Envelope::new(None, vec![mail::Mailbox::parse(mailbox).unwrap()]),
            format!("Subject: secret\r\n\r\n{body}").as_bytes(),
        )
        .unwrap();
        server.store().deliver(mailbox, msg);
    }

    #[tokio::test]
    async fn tcp_submission_refuses_plaintext_auth_then_sends_over_starttls() {
        let (cert_pem, certs) = localhost_certs();
        let mut server = Server::new(&ServerConfig::new(["example.com".to_string()]))
            .with_tls(&certs)
            .unwrap();
        server.register_user("bob@example.com", "pw").unwrap();
        let server = Arc::new(server);

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        {
            let srv = Arc::clone(&server);
            tokio::spawn(async move {
                let (s, peer) = listener.accept().await.unwrap();
                serve_submission(s, peer, srv).await.unwrap();
            });
        }

        let tcp = TcpStream::connect(addr).await.unwrap();
        let (r, mut w) = tcp.into_split();
        let mut r = BufReader::new(r);
        assert!(read_line(&mut r).await.starts_with("220"));

        // Plaintext EHLO advertises STARTTLS.
        w.write_all(b"EHLO client\r\n").await.unwrap();
        assert!(read_line(&mut r).await.starts_with("250-"));
        assert!(read_line(&mut r).await.contains("STARTTLS"));

        // Plaintext AUTH is refused — credentials must not cross unencrypted.
        let auth = BASE64.encode("\0bob@example.com\0pw");
        w.write_all(format!("AUTH PLAIN {auth}\r\n").as_bytes())
            .await
            .unwrap();
        assert!(read_line(&mut r).await.starts_with("530"));

        // Upgrade.
        w.write_all(b"STARTTLS\r\n").await.unwrap();
        assert!(read_line(&mut r).await.starts_with("220"));
        let tcp = r.into_inner().reunite(w).unwrap();
        let client_config = network::TlsConfig::client_trusting_pem(&cert_pem).unwrap();
        let tls = network::tls::connect(client_config, "localhost", tcp)
            .await
            .unwrap();
        let (tr, mut tw) = tokio::io::split(tls);
        let mut tr = BufReader::new(tr);

        // Over TLS, EHLO advertises AUTH and the authenticated transaction works.
        tw.write_all(b"EHLO client\r\n").await.unwrap();
        assert!(read_line(&mut tr).await.starts_with("250-"));
        assert!(read_line(&mut tr).await.contains("AUTH"));
        for (cmd, expect) in [
            (format!("AUTH PLAIN {auth}"), "235"),
            ("MAIL FROM:<bob@example.com>".to_string(), "250"),
            ("RCPT TO:<bob@example.com>".to_string(), "250"),
            ("DATA".to_string(), "354"),
        ] {
            tw.write_all(format!("{cmd}\r\n").as_bytes()).await.unwrap();
            assert!(read_line(&mut tr).await.starts_with(expect), "cmd {cmd}");
        }
        tw.write_all(b"Subject: secure\r\n\r\nsubmitted over tls\r\n.\r\n")
            .await
            .unwrap();
        assert!(read_line(&mut tr).await.starts_with("250"));
        tw.write_all(b"QUIT\r\n").await.unwrap();

        assert_eq!(server.store().count("bob@example.com"), 1);
    }

    #[tokio::test]
    async fn tcp_pop_refuses_plaintext_auth_then_retrieves_over_stls() {
        let (cert_pem, certs) = localhost_certs();
        let mut server = Server::new(&ServerConfig::new(["example.com".to_string()]))
            .with_tls(&certs)
            .unwrap();
        server.register_user("bob@example.com", "pw").unwrap();
        seed_message(&server, "bob@example.com", "pop over tls");
        let server = Arc::new(server);

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        {
            let srv = Arc::clone(&server);
            tokio::spawn(async move {
                let (s, peer) = listener.accept().await.unwrap();
                serve_pop(s, peer, srv).await.unwrap();
            });
        }

        let tcp = TcpStream::connect(addr).await.unwrap();
        let (r, mut w) = tcp.into_split();
        let mut r = BufReader::new(r);
        assert!(read_line(&mut r).await.starts_with("+OK"));

        // CAPA advertises STLS; plaintext USER is refused before the upgrade.
        w.write_all(b"CAPA\r\n").await.unwrap();
        assert!(read_line(&mut r).await.starts_with("+OK"));
        let mut saw_stls = false;
        loop {
            let l = read_line(&mut r).await;
            if l == "." {
                break;
            }
            if l == "STLS" {
                saw_stls = true;
            }
        }
        assert!(saw_stls, "CAPA must advertise STLS before TLS");
        w.write_all(b"USER bob@example.com\r\n").await.unwrap();
        assert!(read_line(&mut r).await.starts_with("-ERR"));

        // Upgrade.
        w.write_all(b"STLS\r\n").await.unwrap();
        assert!(read_line(&mut r).await.starts_with("+OK"));
        let tcp = r.into_inner().reunite(w).unwrap();
        let client_config = network::TlsConfig::client_trusting_pem(&cert_pem).unwrap();
        let tls = network::tls::connect(client_config, "localhost", tcp)
            .await
            .unwrap();
        let (tr, mut tw) = tokio::io::split(tls);
        let mut tr = BufReader::new(tr);

        // Over TLS: authenticate and retrieve.
        for (cmd, expect) in [("USER bob@example.com", "+OK"), ("PASS pw", "+OK")] {
            tw.write_all(format!("{cmd}\r\n").as_bytes()).await.unwrap();
            assert!(read_line(&mut tr).await.starts_with(expect), "cmd {cmd}");
        }
        tw.write_all(b"RETR 1\r\n").await.unwrap();
        assert!(read_line(&mut tr).await.starts_with("+OK"));
        let mut body = String::new();
        loop {
            let l = read_line(&mut tr).await;
            if l == "." {
                break;
            }
            body.push_str(&l);
            body.push('\n');
        }
        assert!(body.contains("pop over tls"), "{body}");
        tw.write_all(b"QUIT\r\n").await.unwrap();
    }

    #[tokio::test]
    async fn tcp_imap_refuses_plaintext_login_then_fetches_over_starttls() {
        let (cert_pem, certs) = localhost_certs();
        let mut server = Server::new(&ServerConfig::new(["example.com".to_string()]))
            .with_tls(&certs)
            .unwrap();
        server.register_user("bob@example.com", "pw").unwrap();
        seed_message(&server, "bob@example.com", "imap over tls");
        let server = Arc::new(server);

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        {
            let srv = Arc::clone(&server);
            tokio::spawn(async move {
                let (s, peer) = listener.accept().await.unwrap();
                serve_imap(s, peer, srv).await.unwrap();
            });
        }

        let tcp = TcpStream::connect(addr).await.unwrap();
        let (r, mut w) = tcp.into_split();
        let mut r = BufReader::new(r);
        assert!(read_line(&mut r).await.starts_with("* OK"));

        // CAPABILITY advertises STARTTLS + LOGINDISABLED before the upgrade.
        w.write_all(b"A0 CAPABILITY\r\n").await.unwrap();
        let caps = read_line(&mut r).await;
        assert!(
            caps.contains("STARTTLS") && caps.contains("LOGINDISABLED"),
            "{caps}"
        );
        assert!(read_line(&mut r).await.contains("OK"));

        // Plaintext LOGIN is refused.
        w.write_all(b"A1 LOGIN bob@example.com pw\r\n")
            .await
            .unwrap();
        let refused = read_line(&mut r).await;
        assert!(
            refused.contains("NO") && refused.contains("PRIVACYREQUIRED"),
            "{refused}"
        );

        // Upgrade.
        w.write_all(b"A2 STARTTLS\r\n").await.unwrap();
        assert!(read_line(&mut r).await.contains("OK"));
        let tcp = r.into_inner().reunite(w).unwrap();
        let client_config = network::TlsConfig::client_trusting_pem(&cert_pem).unwrap();
        let tls = network::tls::connect(client_config, "localhost", tcp)
            .await
            .unwrap();
        let (tr, mut tw) = tokio::io::split(tls);
        let mut tr = BufReader::new(tr);

        // Over TLS: LOGIN, SELECT, FETCH.
        tw.write_all(b"A3 LOGIN bob@example.com pw\r\n")
            .await
            .unwrap();
        assert!(read_line(&mut tr).await.contains("OK"));
        tw.write_all(b"A4 SELECT INBOX\r\n").await.unwrap();
        loop {
            let l = read_line(&mut tr).await;
            if l.starts_with("A4 ") {
                assert!(l.contains("OK"), "{l}");
                break;
            }
        }
        tw.write_all(b"A5 FETCH 1 RFC822\r\n").await.unwrap();
        let mut fetched = String::new();
        loop {
            let l = read_line(&mut tr).await;
            if l.starts_with("A5 ") {
                assert!(l.contains("OK"), "{l}");
                break;
            }
            fetched.push_str(&l);
            fetched.push('\n');
        }
        assert!(fetched.contains("imap over tls"), "{fetched}");
        tw.write_all(b"A6 LOGOUT\r\n").await.unwrap();
    }

    #[tokio::test]
    async fn tcp_inbound_rejects_bare_lf_smuggling() {
        // SMTP-smuggling regression: a sender tries to split DATA on a bare-LF
        // "." and inject a second message. With the genuine <CRLF>.<CRLF>
        // terminator the injected commands stay in the first message's body, so
        // exactly ONE message is delivered (not two).
        let server = Arc::new(Server::new(&ServerConfig::new(["example.com".to_string()])));
        let inbound = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = inbound.local_addr().unwrap();
        {
            let srv = Arc::clone(&server);
            tokio::spawn(async move {
                let (s, peer) = inbound.accept().await.unwrap();
                serve_inbound(s, peer, srv).await.unwrap();
            });
        }

        let client = TcpStream::connect(addr).await.unwrap();
        let (cr, mut cw) = client.into_split();
        let mut cr = BufReader::new(cr);
        assert!(read_line(&mut cr).await.starts_with("220"));
        for (cmd, expect) in [
            ("EHLO mx.attacker.test", "250"),
            ("MAIL FROM:<attacker@attacker.test>", "250"),
            ("RCPT TO:<victim@example.com>", "250"),
            ("DATA", "354"),
        ] {
            cw.write_all(format!("{cmd}\r\n").as_bytes()).await.unwrap();
            assert!(read_line(&mut cr).await.starts_with(expect), "cmd {cmd}");
        }

        // Note the bare LF (`\n`, not `\r\n`) before the smuggled `.`: a strict
        // server treats only <CRLF>.<CRLF> as end-of-data, so everything here is
        // one message body. A vulnerable server would end DATA at the bare-LF
        // "." and parse the following lines as a second injected transaction.
        cw.write_all(
            b"Subject: hello\r\n\r\nbody\r\n.\nMAIL FROM:<spoofed@example.com>\r\n\
              RCPT TO:<victim@example.com>\r\nDATA\r\nInjected message\r\n.\r\n",
        )
        .await
        .unwrap();
        assert!(read_line(&mut cr).await.starts_with("250")); // single accept
        cw.write_all(b"QUIT\r\n").await.unwrap();

        // Exactly one message reached the victim, and the smuggled commands are
        // body text inside it — they never became a second transaction.
        let stored = server.store().list("victim@example.com");
        assert_eq!(
            stored.len(),
            1,
            "bare-LF smuggling must not inject a second message"
        );
        let bytes = stored[0].message.to_bytes();
        let body = String::from_utf8_lossy(&bytes);
        assert!(body.contains("Injected message"), "{body}");
        assert!(body.contains("MAIL FROM:<spoofed@example.com>"), "{body}");
    }

    #[tokio::test]
    async fn tcp_inbound_rejects_oversize_message() {
        // A tiny message cap; an inbound DATA body larger than it must be refused
        // with 552 and the connection closed — never buffered to OOM.
        let server = Arc::new(
            Server::new(&ServerConfig::new(["example.com".to_string()]))
                .with_max_message_size(1024),
        );
        let inbound = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = inbound.local_addr().unwrap();
        {
            let srv = Arc::clone(&server);
            tokio::spawn(async move {
                let (s, peer) = inbound.accept().await.unwrap();
                serve_inbound(s, peer, srv).await.unwrap();
            });
        }

        let client = TcpStream::connect(addr).await.unwrap();
        let (cr, mut cw) = client.into_split();
        let mut cr = BufReader::new(cr);
        assert!(read_line(&mut cr).await.starts_with("220"));
        for (cmd, expect) in [
            ("EHLO mx.test", "250"),
            ("MAIL FROM:<a@remote.test>", "250"),
            ("RCPT TO:<bob@example.com>", "250"),
            ("DATA", "354"),
        ] {
            cw.write_all(format!("{cmd}\r\n").as_bytes()).await.unwrap();
            assert!(read_line(&mut cr).await.starts_with(expect), "cmd {cmd}");
        }
        // ~4 KiB of body across many short lines, well over the 1 KiB cap.
        cw.write_all(b"Subject: big\r\n\r\n").await.unwrap();
        for _ in 0..64 {
            cw.write_all(format!("{}\r\n", "x".repeat(64)).as_bytes())
                .await
                .unwrap();
        }
        cw.write_all(b".\r\n").await.unwrap();
        // Drain replies until the 552 lands (earlier writes may have been answered).
        let mut saw_552 = false;
        for _ in 0..200 {
            let line = read_line(&mut cr).await;
            if line.is_empty() {
                break; // connection closed
            }
            if line.starts_with("552") {
                saw_552 = true;
                break;
            }
        }
        assert!(saw_552, "an oversize message must be refused with 552");
        assert_eq!(
            server.store().count("bob@example.com"),
            0,
            "the oversize message must not be delivered"
        );
    }

    #[tokio::test]
    async fn tcp_inbound_rejects_overlong_line() {
        // A single line longer than MAX_LINE_LENGTH with no newline must be
        // refused (500) and the connection closed — never buffered unbounded.
        let server = Arc::new(Server::new(&ServerConfig::new(["example.com".to_string()])));
        let inbound = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = inbound.local_addr().unwrap();
        {
            let srv = Arc::clone(&server);
            tokio::spawn(async move {
                let (s, peer) = inbound.accept().await.unwrap();
                serve_inbound(s, peer, srv).await.unwrap();
            });
        }

        let client = TcpStream::connect(addr).await.unwrap();
        let (cr, mut cw) = client.into_split();
        let mut cr = BufReader::new(cr);
        assert!(read_line(&mut cr).await.starts_with("220"));

        // One oversize line (no CRLF): MAX_LINE_LENGTH + slack bytes.
        let blast = vec![b'A'; MAX_LINE_LENGTH + 4096];
        cw.write_all(&blast).await.unwrap();
        let reply = read_line(&mut cr).await;
        assert!(
            reply.starts_with("500"),
            "an over-long line must be refused with 500, got {reply:?}"
        );
    }

    #[tokio::test]
    async fn pop_locks_out_after_repeated_auth_failures() {
        use security::ThrottleConfig;
        use std::time::Duration;

        // A tight throttle: two failed credential guesses from an IP lock it out.
        let mut server = Server::new(&ServerConfig::new(["example.com".to_string()]))
            .with_auth_throttle(ThrottleConfig {
                max_failures: 2,
                lockout: Duration::from_secs(900),
            });
        server.register_user("bob@example.com", "pw").unwrap();
        let server = Arc::new(server);

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        {
            let srv = Arc::clone(&server);
            tokio::spawn(async move {
                let (s, peer) = listener.accept().await.unwrap();
                serve_pop(s, peer, srv).await.unwrap();
            });
        }

        let client = TcpStream::connect(addr).await.unwrap();
        let (cr, mut cw) = client.into_split();
        let mut cr = BufReader::new(cr);
        assert!(read_line(&mut cr).await.starts_with("+OK"));

        // Two wrong-password guesses are answered with -ERR (and counted).
        for _ in 0..2 {
            cw.write_all(b"USER bob@example.com\r\n").await.unwrap();
            assert!(read_line(&mut cr).await.starts_with("+OK"));
            cw.write_all(b"PASS wrong\r\n").await.unwrap();
            assert!(read_line(&mut cr).await.starts_with("-ERR"));
        }

        // The IP is now locked out: the next guess is refused with the lockout
        // message (and the connection is closed), even though USER still answers.
        cw.write_all(b"USER bob@example.com\r\n").await.unwrap();
        assert!(read_line(&mut cr).await.starts_with("+OK"));
        cw.write_all(b"PASS wrong\r\n").await.unwrap();
        let locked = read_line(&mut cr).await;
        assert!(
            locked.starts_with("-ERR") && locked.contains("too many"),
            "expected a lockout reply, got {locked:?}"
        );
    }

    #[tokio::test]
    async fn accept_loop_caps_concurrent_connections() {
        use tokio::time::{Duration, timeout};

        let server = Arc::new(Server::new(&ServerConfig::new(["example.com".to_string()])));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        // A budget of 2 concurrent connections.
        let handle = tokio::spawn(accept_loop(
            "submission",
            listener,
            Arc::new(Semaphore::new(2)),
            Arc::clone(&server),
            serve_submission,
        ));

        // Two connections take both permits; each handler greets then blocks in
        // read_line awaiting a command we never send — so both permits stay held.
        let hold1 = TcpStream::connect(addr).await.unwrap();
        let (h1r, h1w) = hold1.into_split();
        let mut h1r = BufReader::new(h1r);
        assert!(read_line(&mut h1r).await.starts_with("220"));
        let hold2 = TcpStream::connect(addr).await.unwrap();
        let (h2r, _h2w) = hold2.into_split();
        let mut h2r = BufReader::new(h2r);
        assert!(read_line(&mut h2r).await.starts_with("220"));

        // A third connection: the OS completes the handshake, but the loop is
        // stalled on acquire_owned (no permit) and never calls accept, so no
        // handler runs and no greeting arrives.
        let third = TcpStream::connect(addr).await.unwrap();
        let (t3r, _t3w) = third.into_split();
        let mut t3r = BufReader::new(t3r);
        assert!(
            timeout(Duration::from_millis(300), read_line(&mut t3r))
                .await
                .is_err(),
            "the third connection must not be served while the cap is full"
        );

        // Free a permit: dropping the first connection makes its handler see EOF
        // and end, releasing its permit → the loop accepts the third → it greets.
        drop(h1r);
        drop(h1w);
        let greeting = timeout(Duration::from_secs(2), read_line(&mut t3r)).await;
        assert!(
            matches!(&greeting, Ok(g) if g.starts_with("220")),
            "the third connection should be served once a permit frees, got {greeting:?}"
        );

        handle.abort();
    }

    #[tokio::test]
    async fn tcp_pop_rejects_overlong_line() {
        // A single line longer than MAX_LINE_LENGTH (no newline) must be refused
        // (-ERR) and the connection closed — never buffered whole into the parser.
        let server = Arc::new(Server::new(&ServerConfig::new(["example.com".to_string()])));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        {
            let srv = Arc::clone(&server);
            tokio::spawn(async move {
                let (s, peer) = listener.accept().await.unwrap();
                serve_pop(s, peer, srv).await.unwrap();
            });
        }
        let client = TcpStream::connect(addr).await.unwrap();
        let (cr, mut cw) = client.into_split();
        let mut cr = BufReader::new(cr);
        assert!(read_line(&mut cr).await.starts_with("+OK"));
        cw.write_all(&vec![b'A'; MAX_LINE_LENGTH + 4096])
            .await
            .unwrap();
        let reply = read_line(&mut cr).await;
        assert!(
            reply.starts_with("-ERR"),
            "POP3 over-long line must be refused with -ERR, got {reply:?}"
        );
    }

    #[tokio::test]
    async fn tcp_imap_rejects_overlong_line() {
        // Likewise for IMAP: an over-long line is refused (* BAD) and closed.
        let server = Arc::new(Server::new(&ServerConfig::new(["example.com".to_string()])));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        {
            let srv = Arc::clone(&server);
            tokio::spawn(async move {
                let (s, peer) = listener.accept().await.unwrap();
                serve_imap(s, peer, srv).await.unwrap();
            });
        }
        let client = TcpStream::connect(addr).await.unwrap();
        let (cr, mut cw) = client.into_split();
        let mut cr = BufReader::new(cr);
        assert!(read_line(&mut cr).await.starts_with("* OK"));
        cw.write_all(&vec![b'A'; MAX_LINE_LENGTH + 4096])
            .await
            .unwrap();
        let reply = read_line(&mut cr).await;
        assert!(
            reply.starts_with("* BAD"),
            "IMAP over-long line must be refused with * BAD, got {reply:?}"
        );
    }

    #[tokio::test]
    async fn tcp_inbound_then_pop_preserves_non_utf8_body_verbatim() {
        use tokio::io::AsyncReadExt;

        // End-to-end byte fidelity (#4): an 8-bit/binary body submitted over the
        // wire must be stored and retrieved byte-for-byte — never lossily decoded
        // (which would replace 0xE9/0xFF/0xFE with U+FFFD = EF BF BD and break DKIM).
        let mut server = Server::new(&ServerConfig::new(["example.com".to_string()]));
        server.register_user("bob@example.com", "pw").unwrap();
        let server = Arc::new(server);

        let inbound = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let pop = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let inbound_addr = inbound.local_addr().unwrap();
        let pop_addr = pop.local_addr().unwrap();
        {
            let srv = Arc::clone(&server);
            tokio::spawn(async move {
                let (s, peer) = inbound.accept().await.unwrap();
                serve_inbound(s, peer, srv).await.unwrap();
            });
        }
        {
            let srv = Arc::clone(&server);
            tokio::spawn(async move {
                let (s, peer) = pop.accept().await.unwrap();
                serve_pop(s, peer, srv).await.unwrap();
            });
        }

        // Deliver a message with a deliberately non-UTF-8 body over the inbound port.
        let nonutf8: &[u8] = b"caf\xe9 \xff\xfe binary";
        let client = TcpStream::connect(inbound_addr).await.unwrap();
        let (cr, mut cw) = client.into_split();
        let mut cr = BufReader::new(cr);
        assert!(read_line(&mut cr).await.starts_with("220"));
        for (cmd, expect) in [
            ("EHLO mx.remote.net", "250"),
            ("MAIL FROM:<alice@remote.net>", "250"),
            ("RCPT TO:<bob@example.com>", "250"),
            ("DATA", "354"),
        ] {
            cw.write_all(format!("{cmd}\r\n").as_bytes()).await.unwrap();
            assert!(read_line(&mut cr).await.starts_with(expect), "cmd {cmd}");
        }
        cw.write_all(b"Subject: bin\r\n\r\n").await.unwrap();
        cw.write_all(nonutf8).await.unwrap();
        cw.write_all(b"\r\n.\r\n").await.unwrap();
        assert!(read_line(&mut cr).await.starts_with("250"));
        cw.write_all(b"QUIT\r\n").await.unwrap();

        // Retrieve it over POP3, reading the RETR response as RAW bytes.
        let client = TcpStream::connect(pop_addr).await.unwrap();
        let (cr, mut cw) = client.into_split();
        let mut cr = BufReader::new(cr);
        assert!(read_line(&mut cr).await.starts_with("+OK"));
        cw.write_all(b"USER bob@example.com\r\n").await.unwrap();
        assert!(read_line(&mut cr).await.starts_with("+OK"));
        cw.write_all(b"PASS pw\r\n").await.unwrap();
        assert!(read_line(&mut cr).await.starts_with("+OK"));
        cw.write_all(b"RETR 1\r\nQUIT\r\n").await.unwrap();

        // Read everything remaining as bytes (status line + body + terminator + bye).
        let mut raw = Vec::new();
        cr.read_to_end(&mut raw).await.unwrap();
        assert!(
            !raw.windows(3).any(|w| w == [0xEF, 0xBF, 0xBD]),
            "no U+FFFD replacement bytes — the body must not have been lossily decoded"
        );
        assert!(
            raw.windows(nonutf8.len()).any(|w| w == nonutf8),
            "the verbatim 8-bit body must appear in the RETR response"
        );
    }

    #[tokio::test]
    async fn tcp_inbound_prepends_received_trace_header() {
        // #2: every accepted inbound message gets a `Received:` trace header
        // stamped at the top, naming the HELO sender and this host.
        let server = Arc::new(Server::new(&ServerConfig::new(["example.com".to_string()])));
        let inbound = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = inbound.local_addr().unwrap();
        {
            let srv = Arc::clone(&server);
            tokio::spawn(async move {
                let (s, peer) = inbound.accept().await.unwrap();
                serve_inbound(s, peer, srv).await.unwrap();
            });
        }
        let client = TcpStream::connect(addr).await.unwrap();
        let (cr, mut cw) = client.into_split();
        let mut cr = BufReader::new(cr);
        assert!(read_line(&mut cr).await.starts_with("220"));
        for (cmd, expect) in [
            ("EHLO mx.remote.net", "250"),
            ("MAIL FROM:<alice@remote.net>", "250"),
            ("RCPT TO:<bob@example.com>", "250"),
            ("DATA", "354"),
        ] {
            cw.write_all(format!("{cmd}\r\n").as_bytes()).await.unwrap();
            assert!(read_line(&mut cr).await.starts_with(expect), "cmd {cmd}");
        }
        cw.write_all(b"Subject: hi\r\n\r\nbody\r\n.\r\n")
            .await
            .unwrap();
        assert!(read_line(&mut cr).await.starts_with("250")); // store now updated

        let stored = server.store().list("bob@example.com");
        assert_eq!(stored.len(), 1);
        let text = String::from_utf8_lossy(&stored[0].message.to_bytes()).into_owned();
        assert!(
            text.starts_with("Received: from mx.remote.net by example.com with ESMTP;"),
            "expected a Received trace header at the top, got: {text:?}"
        );
        // The original content is preserved after the prepended hop.
        assert!(text.contains("Subject: hi"));
        assert!(text.contains("body"));
    }

    #[tokio::test]
    async fn tcp_inbound_rejects_message_exceeding_hop_limit() {
        // #2: a message arriving with >= MAX_RECEIVED_HOPS Received headers is a
        // mail loop and must be refused (554), not delivered/relayed onward.
        let server = Arc::new(Server::new(&ServerConfig::new(["example.com".to_string()])));
        let inbound = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = inbound.local_addr().unwrap();
        {
            let srv = Arc::clone(&server);
            tokio::spawn(async move {
                let (s, peer) = inbound.accept().await.unwrap();
                serve_inbound(s, peer, srv).await.unwrap();
            });
        }
        let client = TcpStream::connect(addr).await.unwrap();
        let (cr, mut cw) = client.into_split();
        let mut cr = BufReader::new(cr);
        assert!(read_line(&mut cr).await.starts_with("220"));
        for (cmd, expect) in [
            ("EHLO mx.loop.test", "250"),
            ("MAIL FROM:<a@loop.test>", "250"),
            ("RCPT TO:<bob@example.com>", "250"),
            ("DATA", "354"),
        ] {
            cw.write_all(format!("{cmd}\r\n").as_bytes()).await.unwrap();
            assert!(read_line(&mut cr).await.starts_with(expect), "cmd {cmd}");
        }
        // Build a DATA body already carrying MAX_RECEIVED_HOPS Received headers.
        let mut data = String::new();
        for i in 0..MAX_RECEIVED_HOPS {
            data.push_str(&format!("Received: by hop{i}.test; loop\r\n"));
        }
        data.push_str("Subject: looping\r\n\r\nbody\r\n.\r\n");
        cw.write_all(data.as_bytes()).await.unwrap();
        assert!(
            read_line(&mut cr).await.starts_with("554"),
            "a message exceeding the hop limit must be refused with 554"
        );
        assert_eq!(
            server.store().count("bob@example.com"),
            0,
            "a looping message must not be delivered"
        );
    }

    /// A canned-TXT resolver for SPF integration tests.
    struct SpfMock {
        txt: std::collections::BTreeMap<String, Vec<String>>,
    }

    #[async_trait::async_trait]
    impl network::DnsResolver for SpfMock {
        async fn lookup_mx(&self, _d: &str) -> network::Result<Vec<network::MxRecord>> {
            Ok(vec![])
        }
        async fn lookup_ip(&self, _h: &str) -> network::Result<Vec<network::AddressRecord>> {
            Ok(vec![])
        }
        async fn lookup_txt(&self, name: &str) -> network::Result<Vec<network::TxtRecord>> {
            Ok(self
                .txt
                .get(name)
                .map(|v| v.iter().cloned().map(network::TxtRecord).collect())
                .unwrap_or_default())
        }
        async fn reverse_lookup(
            &self,
            _ip: std::net::IpAddr,
        ) -> network::Result<Vec<network::PtrRecord>> {
            Ok(vec![])
        }
    }

    fn spf_mock(domain: &str, record: &str) -> Arc<SpfMock> {
        let mut txt = std::collections::BTreeMap::new();
        txt.insert(domain.to_string(), vec![record.to_string()]);
        Arc::new(SpfMock { txt })
    }

    /// A resolver with several canned TXT records (e.g. an SPF record plus a
    /// `_dmarc.<domain>` record), for the DMARC integration tests.
    fn auth_mock(records: &[(&str, &str)]) -> Arc<SpfMock> {
        let mut txt = std::collections::BTreeMap::new();
        for (name, value) in records {
            txt.insert((*name).to_string(), vec![(*value).to_string()]);
        }
        Arc::new(SpfMock { txt })
    }

    /// Deliver one inbound message over a fresh `serve_inbound` connection and
    /// return the verbatim stored bytes for `rcpt` plus the final SMTP reply.
    async fn deliver_inbound(
        server: Arc<Server>,
        mail_from: &str,
        rcpt: &str,
        from_header: &str,
        body: &str,
    ) -> (String, String) {
        let inbound = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = inbound.local_addr().unwrap();
        {
            let srv = Arc::clone(&server);
            tokio::spawn(async move {
                let (s, peer) = inbound.accept().await.unwrap();
                serve_inbound(s, peer, srv).await.unwrap();
            });
        }
        let client = TcpStream::connect(addr).await.unwrap();
        let (cr, mut cw) = client.into_split();
        let mut cr = BufReader::new(cr);
        assert!(read_line(&mut cr).await.starts_with("220"));
        for (cmd, expect) in [
            ("EHLO mx.test".to_string(), "250"),
            (format!("MAIL FROM:<{mail_from}>"), "250"),
            (format!("RCPT TO:<{rcpt}>"), "250"),
            ("DATA".to_string(), "354"),
        ] {
            cw.write_all(format!("{cmd}\r\n").as_bytes()).await.unwrap();
            assert!(read_line(&mut cr).await.starts_with(expect), "cmd {cmd}");
        }
        cw.write_all(
            format!("From: {from_header}\r\nSubject: hi\r\n\r\n{body}\r\n.\r\n").as_bytes(),
        )
        .await
        .unwrap();
        let reply = read_line(&mut cr).await;
        let stored = if reply.starts_with("250") {
            String::from_utf8_lossy(&server.store().list(rcpt)[0].message.to_bytes()).into_owned()
        } else {
            String::new()
        };
        (reply, stored)
    }

    #[tokio::test]
    async fn tcp_inbound_stamps_received_spf_when_resolver_present() {
        // The sender domain authorizes the loopback connection → SPF pass, stamped
        // as a Received-SPF header (stamp-only: the message is still delivered).
        let server = Arc::new(
            Server::new(&ServerConfig::new(["example.com".to_string()]))
                .with_resolver(spf_mock("sender.test", "v=spf1 ip4:127.0.0.1/32 -all")),
        );
        let inbound = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = inbound.local_addr().unwrap();
        {
            let srv = Arc::clone(&server);
            tokio::spawn(async move {
                let (s, peer) = inbound.accept().await.unwrap();
                serve_inbound(s, peer, srv).await.unwrap();
            });
        }
        let client = TcpStream::connect(addr).await.unwrap();
        let (cr, mut cw) = client.into_split();
        let mut cr = BufReader::new(cr);
        assert!(read_line(&mut cr).await.starts_with("220"));
        for (cmd, expect) in [
            ("EHLO mx.sender.test", "250"),
            ("MAIL FROM:<alice@sender.test>", "250"),
            ("RCPT TO:<bob@example.com>", "250"),
            ("DATA", "354"),
        ] {
            cw.write_all(format!("{cmd}\r\n").as_bytes()).await.unwrap();
            assert!(read_line(&mut cr).await.starts_with(expect), "cmd {cmd}");
        }
        cw.write_all(b"Subject: hi\r\n\r\nbody\r\n.\r\n")
            .await
            .unwrap();
        assert!(read_line(&mut cr).await.starts_with("250"));

        let stored = server.store().list("bob@example.com");
        assert_eq!(stored.len(), 1);
        let text = String::from_utf8_lossy(&stored[0].message.to_bytes()).into_owned();
        assert!(
            text.contains("Received-SPF: pass"),
            "expected a Received-SPF: pass header, got: {text:?}"
        );
        // The DKIM verification path also runs: with no signature on this message,
        // the stamped Authentication-Results records spf=pass and dkim=none.
        assert!(
            text.contains("Authentication-Results:")
                && text.contains("spf=pass")
                && text.contains("dkim=none"),
            "expected Authentication-Results with spf=pass; dkim=none, got: {text:?}"
        );
    }

    #[tokio::test]
    async fn tcp_inbound_rejects_on_spf_fail_when_enforcing() {
        // The sender domain authorizes only 10.0.0.0/8, so the loopback connection
        // is an SPF fail; with enforcement on, the message is refused (550).
        let server = Arc::new(
            Server::new(&ServerConfig::new(["example.com".to_string()]))
                .with_resolver(spf_mock("sender.test", "v=spf1 ip4:10.0.0.0/8 -all"))
                .with_spf_enforcement(true),
        );
        let inbound = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = inbound.local_addr().unwrap();
        {
            let srv = Arc::clone(&server);
            tokio::spawn(async move {
                let (s, peer) = inbound.accept().await.unwrap();
                serve_inbound(s, peer, srv).await.unwrap();
            });
        }
        let client = TcpStream::connect(addr).await.unwrap();
        let (cr, mut cw) = client.into_split();
        let mut cr = BufReader::new(cr);
        assert!(read_line(&mut cr).await.starts_with("220"));
        for (cmd, expect) in [
            ("EHLO mx.sender.test", "250"),
            ("MAIL FROM:<alice@sender.test>", "250"),
            ("RCPT TO:<bob@example.com>", "250"),
            ("DATA", "354"),
        ] {
            cw.write_all(format!("{cmd}\r\n").as_bytes()).await.unwrap();
            assert!(read_line(&mut cr).await.starts_with(expect), "cmd {cmd}");
        }
        cw.write_all(b"Subject: spoof\r\n\r\nbody\r\n.\r\n")
            .await
            .unwrap();
        assert!(
            read_line(&mut cr).await.starts_with("550"),
            "an SPF fail under enforcement must be rejected with 550"
        );
        assert_eq!(
            server.store().count("bob@example.com"),
            0,
            "a rejected message must not be delivered"
        );
    }

    #[tokio::test]
    async fn tcp_inbound_dmarc_pass_via_aligned_spf_is_stamped() {
        // example.com publishes SPF (authorizing loopback) and a DMARC reject
        // policy. A From: @example.com message whose MAIL FROM aligns passes DMARC.
        let server = Arc::new(
            Server::new(&ServerConfig::new(["example.com".to_string()])).with_resolver(auth_mock(
                &[
                    ("example.com", "v=spf1 ip4:127.0.0.1/32 -all"),
                    ("_dmarc.example.com", "v=DMARC1; p=reject"),
                ],
            )),
        );
        let (reply, stored) = deliver_inbound(
            server,
            "alice@example.com",
            "bob@example.com",
            "Alice <alice@example.com>",
            "hi",
        )
        .await;
        assert!(
            reply.starts_with("250"),
            "aligned mail is delivered: {reply}"
        );
        assert!(
            stored.contains("dmarc=pass header.from=example.com"),
            "expected dmarc=pass in Authentication-Results, got: {stored:?}"
        );
    }

    #[tokio::test]
    async fn tcp_inbound_dmarc_reject_when_enforcing() {
        // A spoofer at evil.test passes SPF for ITS OWN domain but sets
        // From: @example.com. DMARC finds neither SPF nor DKIM aligned with the
        // From domain; example.com's p=reject + enforcement refuses the message.
        let server = Arc::new(
            Server::new(&ServerConfig::new(["example.com".to_string()]))
                .with_resolver(auth_mock(&[
                    ("evil.test", "v=spf1 ip4:127.0.0.1/32 -all"),
                    ("_dmarc.example.com", "v=DMARC1; p=reject"),
                ]))
                .with_dmarc_enforcement(true),
        );
        let (reply, _) = deliver_inbound(
            Arc::clone(&server),
            "attacker@evil.test",
            "bob@example.com",
            "alice@example.com", // spoofed From
            "phish",
        )
        .await;
        assert!(
            reply.starts_with("550"),
            "an unaligned message under a DMARC reject policy must be refused: {reply}"
        );
        assert_eq!(
            server.store().count("bob@example.com"),
            0,
            "a DMARC-rejected message must not be delivered"
        );
    }

    #[tokio::test]
    async fn inbound_starttls_refused_with_args_and_mid_transaction() {
        // STARTTLS now flows through the command parser + session state machine:
        // a trailing argument is malformed (500), and STARTTLS once a transaction
        // is underway is refused (503) — never a silent upgrade in either case.
        let (_cert_pem, certs) = localhost_certs();
        let server = Arc::new(
            Server::new(&ServerConfig::new(["example.com".to_string()]))
                .with_tls(&certs)
                .unwrap(),
        );
        let inbound = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = inbound.local_addr().unwrap();
        {
            let srv = Arc::clone(&server);
            tokio::spawn(async move {
                let (s, peer) = inbound.accept().await.unwrap();
                serve_inbound(s, peer, srv).await.unwrap();
            });
        }

        let client = TcpStream::connect(addr).await.unwrap();
        let (cr, mut cw) = client.into_split();
        let mut cr = BufReader::new(cr);
        assert!(read_line(&mut cr).await.starts_with("220"));

        // EHLO advertises STARTTLS (TLS is configured).
        cw.write_all(b"EHLO mx.test\r\n").await.unwrap();
        assert!(read_line(&mut cr).await.starts_with("250-"));
        assert!(read_line(&mut cr).await.contains("STARTTLS"));

        // `STARTTLS now` is malformed → 500, and the connection stays plaintext.
        cw.write_all(b"STARTTLS now\r\n").await.unwrap();
        assert!(read_line(&mut cr).await.starts_with("500"));

        // Open a transaction, then STARTTLS must be refused with 503.
        cw.write_all(b"MAIL FROM:<a@remote.test>\r\n")
            .await
            .unwrap();
        assert!(read_line(&mut cr).await.starts_with("250"));
        cw.write_all(b"STARTTLS\r\n").await.unwrap();
        assert!(read_line(&mut cr).await.starts_with("503"));
        cw.write_all(b"QUIT\r\n").await.unwrap();
    }
}
