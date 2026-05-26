//! Async TCP servers that drive the (synchronous) protocol sessions over
//! sockets, plus the listener orchestration with graceful shutdown.
//!
//! Framing is UTF-8 line based; binary message bodies are a future enhancement.

use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use access::{
    ImapCommand, ImapResponse, ImapSession, MsaSession, Pop3Session, PopCommand, PopReply,
    TaggedCommand,
};
use mail::{InboundCollector, SmtpCommand, SmtpSession};
use security::Decision;
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader, ReadBuf};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Notify;
use tokio_rustls::server::TlsStream;

use crate::server::Server;
use crate::worker::spawn_relay_worker;

/// How often the relay worker scans the spool for due messages.
const RELAY_WORKER_TICK: Duration = Duration::from_secs(30);

/// Bind addresses for the protocol listeners.
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

    // The relay worker runs only when outbound relay is configured.
    let shutdown = Arc::new(Notify::new());
    let worker = server.relay_context().is_some().then(|| {
        spawn_relay_worker(
            Arc::clone(&server),
            Arc::clone(&shutdown),
            RELAY_WORKER_TICK,
        )
    });

    loop {
        tokio::select! {
            Ok((stream, _)) = submission.accept() => spawn(serve_submission(stream, Arc::clone(&server))),
            Ok((stream, _)) = pop3.accept() => spawn(serve_pop(stream, Arc::clone(&server))),
            Ok((stream, _)) = imap.accept() => spawn(serve_imap(stream, Arc::clone(&server))),
            Ok((stream, peer)) = inbound.accept() => spawn(serve_inbound_firewalled(stream, peer, Arc::clone(&server))),
            _ = tokio::signal::ctrl_c() => {
                tracing::info!("shutdown signal received");
                break;
            }
        }
    }

    // Stop the relay worker and wait for it to finish its current tick.
    shutdown.notify_one();
    if let Some(worker) = worker {
        let _ = worker.await;
    }
    Ok(())
}

fn spawn(fut: impl std::future::Future<Output = std::io::Result<()>> + Send + 'static) {
    tokio::spawn(async move {
        if let Err(error) = fut.await {
            tracing::warn!(%error, "connection handler ended with error");
        }
    });
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
        Decision::Allow => serve_inbound(stream, server).await,
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
pub async fn serve_submission(stream: TcpStream, server: Arc<Server>) -> std::io::Result<()> {
    let has_tls = server.tls_config().is_some();
    let mut conn = BufReader::new(MaybeTlsStream::Plain(stream));
    let mut msa = MsaSession::new(server.authenticator());
    let mut collecting: Option<InboundCollector> = None;

    conn.write_all(b"220 Snail ESMTP ready\r\n").await?;
    let mut line = String::new();
    loop {
        line.clear();
        if conn.read_line(&mut line).await? == 0 {
            break;
        }

        // DATA body mode: accumulate until the lone "." line.
        if let Some(collector) = collecting.as_mut() {
            if collector.push_line(&line) {
                let collector = collecting.take().expect("collecting was Some");
                let reply = match msa.smtp_mut().take_envelope() {
                    Some(envelope) => match collector.into_message(envelope) {
                        Ok(message) => {
                            let _ = server.accept_inbound(message);
                            "250 OK message accepted\r\n"
                        }
                        Err(_) => "554 message parse error\r\n",
                    },
                    None => "554 no valid recipients\r\n",
                };
                conn.write_all(reply.as_bytes()).await?;
            }
            continue;
        }

        let trimmed = line.trim_end();

        // STARTTLS: upgrade the socket and reset the session (the client must
        // re-issue EHLO over the encrypted channel, per RFC 3207).
        if trimmed.eq_ignore_ascii_case("STARTTLS") {
            match server.tls_config() {
                Some(config) if matches!(conn.get_ref(), MaybeTlsStream::Plain(_)) => {
                    if !conn.buffer().is_empty() {
                        conn.write_all(b"503 no pipelining before STARTTLS\r\n")
                            .await?;
                        continue;
                    }
                    conn.write_all(b"220 Ready to start TLS\r\n").await?;
                    conn = accept_tls(conn, config).await?;
                    msa = MsaSession::new(server.authenticator());
                }
                _ => {
                    conn.write_all(b"502 STARTTLS not available\r\n").await?;
                }
            }
            continue;
        }

        // SASL PLAIN, initial-response form: `AUTH PLAIN <base64>`. When TLS is
        // on offer, refuse it in cleartext so credentials never cross unencrypted
        // (RFC 3207 §4; equivalent to Dovecot's `disable_plaintext_auth`).
        if let Some(rest) = strip_prefix_ci(trimmed, "AUTH PLAIN") {
            if has_tls && matches!(conn.get_ref(), MaybeTlsStream::Plain(_)) {
                conn.write_all(b"530 Must issue a STARTTLS command first\r\n")
                    .await?;
                continue;
            }
            let reply = match rest.trim() {
                "" => SmtpReplyText::new(501, "AUTH PLAIN requires an initial response"),
                b64 => {
                    let r = msa.authenticate_plain(b64);
                    SmtpReplyText::new(r.code, &r.text)
                }
            };
            conn.write_all(reply.to_wire().as_bytes()).await?;
            continue;
        }

        match SmtpCommand::parse(&line) {
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
                    collecting = Some(InboundCollector::new());
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
pub async fn serve_inbound(stream: TcpStream, server: Arc<Server>) -> std::io::Result<()> {
    let tls = server.tls_config();
    let mut conn = BufReader::new(MaybeTlsStream::Plain(stream));
    let mut session = SmtpSession::new();
    let mut collecting: Option<InboundCollector> = None;

    conn.write_all(b"220 Snail ESMTP ready\r\n").await?;
    let mut line = String::new();
    loop {
        line.clear();
        if conn.read_line(&mut line).await? == 0 {
            break;
        }

        // DATA body mode: accumulate until the lone "." line, then deliver.
        if let Some(collector) = collecting.as_mut() {
            if collector.push_line(&line) {
                let collector = collecting.take().expect("collecting was Some");
                let reply = match session.take_envelope() {
                    Some(envelope) => match collector.into_message(envelope) {
                        Ok(message) => {
                            // Recipients were vetted as local at RCPT time, so this
                            // delivers locally and never relays.
                            let _ = server.accept_inbound(message);
                            "250 OK message accepted\r\n"
                        }
                        Err(_) => "554 message parse error\r\n",
                    },
                    None => "554 no valid recipients\r\n",
                };
                conn.write_all(reply.as_bytes()).await?;
            }
            continue;
        }

        // STARTTLS: upgrade the socket, then reset the session (the client must
        // re-issue EHLO over the encrypted channel, per RFC 3207).
        if line.trim_end().eq_ignore_ascii_case("STARTTLS") {
            match &tls {
                Some(config) if matches!(conn.get_ref(), MaybeTlsStream::Plain(_)) => {
                    if !conn.buffer().is_empty() {
                        conn.write_all(b"503 no pipelining before STARTTLS\r\n")
                            .await?;
                        continue;
                    }
                    conn.write_all(b"220 Ready to start TLS\r\n").await?;
                    conn = accept_tls(conn, Arc::clone(config)).await?;
                    session = SmtpSession::new();
                }
                _ => {
                    conn.write_all(b"502 STARTTLS not available\r\n").await?;
                }
            }
            continue;
        }

        match SmtpCommand::parse(&line) {
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
                    collecting = Some(InboundCollector::new());
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

/// Serve one POP3 connection.
///
/// # Errors
/// [`std::io::Error`] on socket failure.
pub async fn serve_pop(stream: TcpStream, server: Arc<Server>) -> std::io::Result<()> {
    let mut conn = BufReader::new(MaybeTlsStream::Plain(stream));
    let mut session = if server.tls_config().is_some() {
        Pop3Session::with_tls(server.authenticator(), server.store(), false)
    } else {
        Pop3Session::new(server.authenticator(), server.store())
    };

    conn.write_all(b"+OK Snail POP3 ready\r\n").await?;
    let mut line = String::new();
    loop {
        line.clear();
        if conn.read_line(&mut line).await? == 0 {
            break;
        }
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
    if reply.ok && !reply.lines.is_empty() {
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
pub async fn serve_imap(stream: TcpStream, server: Arc<Server>) -> std::io::Result<()> {
    let mut conn = BufReader::new(MaybeTlsStream::Plain(stream));
    let mut session = if server.tls_config().is_some() {
        ImapSession::with_tls(server.authenticator(), server.store(), false)
    } else {
        ImapSession::new(server.authenticator(), server.store())
    };

    conn.write_all(b"* OK Snail IMAP4rev1 ready\r\n").await?;
    let mut line = String::new();
    loop {
        line.clear();
        if conn.read_line(&mut line).await? == 0 {
            break;
        }
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

/// Write an IMAP response: each untagged line as `* <line>`, then the tagged
/// status line.
async fn write_imap_response<W: AsyncWrite + Unpin>(
    write: &mut W,
    response: &ImapResponse,
) -> std::io::Result<()> {
    for untagged in &response.untagged {
        write
            .write_all(format!("* {untagged}\r\n").as_bytes())
            .await?;
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
                let (s, _) = sub.accept().await.unwrap();
                serve_submission(s, srv).await.unwrap();
            });
        }
        {
            let srv = Arc::clone(&server);
            tokio::spawn(async move {
                let (s, _) = pop.accept().await.unwrap();
                serve_pop(s, srv).await.unwrap();
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
                let (s, _) = inbound.accept().await.unwrap();
                serve_inbound(s, srv).await.unwrap();
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
                let (s, _) = inbound.accept().await.unwrap();
                serve_inbound(s, srv).await.unwrap();
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
                let (s, _) = listener.accept().await.unwrap();
                serve_submission(s, srv).await.unwrap();
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
                let (s, _) = listener.accept().await.unwrap();
                serve_pop(s, srv).await.unwrap();
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
                let (s, _) = listener.accept().await.unwrap();
                serve_imap(s, srv).await.unwrap();
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
                let (s, _) = inbound.accept().await.unwrap();
                serve_inbound(s, srv).await.unwrap();
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
}
