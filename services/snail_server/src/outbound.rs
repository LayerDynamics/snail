//! Outbound relay: the SMTP *client* socket dialog. Drives the protocol script
//! built by [`mail::transport::relay_script`] over a TCP connection to a
//! downstream server, reading the (possibly multiline) replies and classifying
//! the result for the retry spool. MX resolution lives in [`crate::relay`]; this
//! is the single-target transmit.

use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use mail::Message;
use mail::transport::relay_script;
use network::{DnsResolver, MtaStsMode, MtaStsPolicy, MtaStsResolver, MxRecord};
use rustls::ClientConfig;
use tokio::io::{
    AsyncBufRead, AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader, ReadBuf,
};
use tokio::net::TcpStream;
use tokio_rustls::client::TlsStream as ClientTlsStream;

/// The outcome of one relay attempt to one downstream server.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RelayReport {
    /// Final 2xx — the message was accepted by the server.
    Delivered,
    /// Transient failure (4xx, or could not connect / read a reply) — retry later.
    Deferred {
        /// The SMTP code (`0` when we never got one, e.g. connect failure).
        code: u16,
        /// Diagnostic context.
        text: String,
    },
    /// Permanent failure (5xx, or a protocol error) — do not retry; bounce.
    Failed {
        /// Why the attempt permanently failed.
        reason: String,
    },
}

/// The TLS posture for a single relay attempt to one mail exchange.
///
/// This is the per-exchange decision the relay makes after consulting any
/// MTA-STS policy (RFC 8461): an `enforce` policy yields [`TlsPolicy::Strict`]
/// for a policy-matched MX, everything else yields [`TlsPolicy::Opportunistic`]
/// (or [`TlsPolicy::None`] when no client config is available).
#[derive(Clone)]
pub enum TlsPolicy {
    /// No outbound TLS: deliver in plaintext (no client config was built).
    None,
    /// Encrypt if the exchange advertises `STARTTLS`, accepting any certificate;
    /// otherwise deliver in cleartext (RFC 3207). Standard MTA-to-MTA behaviour.
    Opportunistic(Arc<ClientConfig>),
    /// MTA-STS `enforce` (RFC 8461 §4.1): `STARTTLS` is mandatory and the
    /// certificate MUST validate against PKIX for the MX hostname. There is **no**
    /// cleartext fallback — a missing `STARTTLS` or a failed/invalid handshake
    /// defers the message rather than downgrading.
    Strict(Arc<ClientConfig>),
}

impl TlsPolicy {
    /// The client config to use for a STARTTLS upgrade, if any.
    fn config(&self) -> Option<&Arc<ClientConfig>> {
        match self {
            TlsPolicy::None => None,
            TlsPolicy::Opportunistic(c) | TlsPolicy::Strict(c) => Some(c),
        }
    }

    /// Whether TLS is mandatory (no cleartext fallback is permitted).
    fn is_mandatory(&self) -> bool {
        matches!(self, TlsPolicy::Strict(_))
    }
}

/// Read one SMTP reply, which may span several lines.
///
/// Per RFC 5321 a continuation line has `-` at index 3 (`250-...`) and the final
/// line has a space (`250 ...`). Returns the final 3-digit code and the text of
/// each line (the part after the code+separator).
///
/// # Errors
/// [`std::io::Error`] on socket failure, EOF mid-reply, or a malformed code.
pub async fn read_reply<R: AsyncBufRead + Unpin>(
    reader: &mut R,
) -> std::io::Result<(u16, Vec<String>)> {
    let mut texts = Vec::new();
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line).await? == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "connection closed mid-reply",
            ));
        }
        let trimmed = line.trim_end_matches(['\r', '\n']);
        let code: u16 = trimmed
            .get(..3)
            .and_then(|c| c.parse().ok())
            .ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("malformed SMTP reply line: {trimmed:?}"),
                )
            })?;
        let more = trimmed.as_bytes().get(3) == Some(&b'-');
        texts.push(trimmed.get(4..).unwrap_or("").to_string());
        if !more {
            return Ok((code, texts));
        }
    }
}

/// Classify a non-positive final code into a [`RelayReport`]: 4xx (and the
/// synthetic `0`) are transient → `Deferred`; everything else (5xx, odd codes) is
/// permanent → `Failed`.
fn classify(code: u16, context: &str) -> RelayReport {
    if code == 0 || (400..500).contains(&code) {
        RelayReport::Deferred {
            code,
            text: context.to_string(),
        }
    } else {
        RelayReport::Failed {
            reason: format!("{code} {context}"),
        }
    }
}

/// A relay client socket that may be upgraded from plaintext to TLS mid-session
/// by `STARTTLS`. Both variants are `Unpin`, so the delegating poll impls need no
/// `pin-project`. This is the outbound counterpart of the inbound `MaybeTlsStream`.
enum RelayStream {
    /// Plaintext TCP (before STARTTLS).
    Plain(TcpStream),
    /// TLS, after a successful STARTTLS upgrade.
    Tls(Box<ClientTlsStream<TcpStream>>),
}

impl AsyncRead for RelayStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            RelayStream::Plain(s) => Pin::new(s).poll_read(cx, buf),
            RelayStream::Tls(s) => Pin::new(&mut **s).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for RelayStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        match self.get_mut() {
            RelayStream::Plain(s) => Pin::new(s).poll_write(cx, buf),
            RelayStream::Tls(s) => Pin::new(&mut **s).poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            RelayStream::Plain(s) => Pin::new(s).poll_flush(cx),
            RelayStream::Tls(s) => Pin::new(&mut **s).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            RelayStream::Plain(s) => Pin::new(s).poll_shutdown(cx),
            RelayStream::Tls(s) => Pin::new(&mut **s).poll_shutdown(cx),
        }
    }
}

/// Whether an EHLO reply advertises the `STARTTLS` extension. Per RFC 5321 the
/// keyword is the first whitespace-delimited token of a capability line and is
/// matched case-insensitively (so a line like `XSTARTTLS` never false-matches).
fn advertises_starttls(capabilities: &[String]) -> bool {
    capabilities.iter().any(|line| {
        line.split_whitespace()
            .next()
            .is_some_and(|token| token.eq_ignore_ascii_case("STARTTLS"))
    })
}

/// Write one CRLF-terminated command, flush it, and read the (possibly multiline)
/// reply. Flushing matters once the stream is TLS: tokio-rustls buffers plaintext
/// into records, so an unflushed command would never reach the peer we then block
/// on reading from.
async fn command<S>(conn: &mut BufReader<S>, line: &str) -> std::io::Result<(u16, Vec<String>)>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    conn.write_all(line.as_bytes()).await?;
    conn.write_all(b"\r\n").await?;
    conn.flush().await?;
    read_reply(conn).await
}

/// Relay `message` to a single server at `addr` (`host:port`), announcing
/// ourselves as `helo`, under the given TLS `policy`.
///
/// - [`TlsPolicy::Opportunistic`]: if the server advertises `STARTTLS`, upgrade
///   to TLS (using `server_name` for the handshake) before the mail transaction;
///   otherwise the transaction runs in plaintext, as it must against a server
///   that offers no encryption.
/// - [`TlsPolicy::Strict`] (MTA-STS `enforce`): `STARTTLS` is mandatory and the
///   certificate is PKIX-validated against `server_name`; a server that does not
///   offer `STARTTLS`, or whose handshake fails, is **deferred** with no cleartext
///   fallback.
/// - [`TlsPolicy::None`]: always plaintext.
///
/// Connection failures become [`RelayReport::Deferred`] so the caller can retry;
/// genuine socket errors after connect propagate.
///
/// # Errors
/// [`std::io::Error`] on a read/write failure once connected.
pub async fn relay_to(
    addr: &str,
    server_name: &str,
    helo: &str,
    message: &Message,
    policy: &TlsPolicy,
) -> std::io::Result<RelayReport> {
    let script = relay_script(helo, message);
    let ehlo = &script.commands[0];

    let tcp = match TcpStream::connect(addr).await {
        Ok(tcp) => tcp,
        Err(error) => {
            return Ok(RelayReport::Deferred {
                code: 0,
                text: format!("connect {addr}: {error}"),
            });
        }
    };
    let mut conn = BufReader::new(RelayStream::Plain(tcp));

    // Server greeting.
    let (code, text) = read_reply(&mut conn).await?;
    if !(200..400).contains(&code) {
        return Ok(classify(code, &format!("greeting: {}", text.join(" "))));
    }

    // EHLO: announce ourselves and discover the server's capabilities.
    let (code, capabilities) = command(&mut conn, ehlo).await?;
    if !(200..300).contains(&code) {
        return Ok(classify(
            code,
            &format!("after `{ehlo}`: {}", capabilities.join(" ")),
        ));
    }

    // Under an MTA-STS enforce policy, STARTTLS is mandatory: an exchange that
    // does not advertise it cannot be delivered to in cleartext (RFC 8461 §4.1).
    // Defer so the worker retries (the policy host may be transiently misconfigured).
    if policy.is_mandatory() && !advertises_starttls(&capabilities) {
        return Ok(RelayReport::Deferred {
            code: 0,
            text: format!("MTA-STS enforce: {server_name} does not advertise STARTTLS"),
        });
    }

    // STARTTLS upgrade: if we have a client config and the server offered
    // STARTTLS, upgrade and re-issue EHLO over the encrypted channel (RFC 3207
    // §4.2). A failure to negotiate the TLS the server *advertised* is transient
    // (Deferred); we never silently continue in cleartext after offering to
    // encrypt, which would let an active attacker strip encryption (RFC 3207
    // §4.1). Under Strict the client config is PKIX-verifying, so an invalid or
    // mismatched certificate fails the handshake and likewise defers.
    if let Some(config) = policy.config()
        && advertises_starttls(&capabilities)
    {
        let (code, text) = command(&mut conn, "STARTTLS").await?;
        if !(200..300).contains(&code) {
            return Ok(RelayReport::Deferred {
                code,
                text: format!("STARTTLS refused: {}", text.join(" ")),
            });
        }
        if !conn.buffer().is_empty() {
            return Ok(RelayReport::Deferred {
                code: 0,
                text: "server pipelined data after STARTTLS".to_string(),
            });
        }
        let RelayStream::Plain(tcp) = conn.into_inner() else {
            unreachable!("connection is plaintext before STARTTLS")
        };
        let upgraded = match network::tls::connect(Arc::clone(config), server_name, tcp).await {
            Ok(stream) => stream,
            Err(error) => {
                return Ok(RelayReport::Deferred {
                    code: 0,
                    text: format!("STARTTLS handshake with {server_name}: {error}"),
                });
            }
        };
        conn = BufReader::new(RelayStream::Tls(Box::new(upgraded)));

        // The server discards all prior state at STARTTLS, so re-EHLO over TLS.
        let (code, text) = command(&mut conn, ehlo).await?;
        if !(200..300).contains(&code) {
            return Ok(classify(
                code,
                &format!("after TLS `{ehlo}`: {}", text.join(" ")),
            ));
        }
    }

    // Envelope + DATA handshake (MAIL FROM, RCPT TO.., DATA), over whichever
    // stream we now have.
    for cmd in &script.commands[1..] {
        let (code, text) = command(&mut conn, cmd).await?;
        let ok = if cmd == "DATA" {
            code == 354
        } else {
            (200..300).contains(&code)
        };
        if !ok {
            return Ok(classify(
                code,
                &format!("after `{cmd}`: {}", text.join(" ")),
            ));
        }
    }

    // Transmit the dot-stuffed, terminated DATA payload and read the verdict.
    conn.write_all(&script.data).await?;
    conn.flush().await?;
    let (code, text) = read_reply(&mut conn).await?;
    let _ = conn.write_all(b"QUIT\r\n").await; // best-effort
    let _ = conn.flush().await;

    if (200..300).contains(&code) {
        Ok(RelayReport::Delivered)
    } else {
        Ok(classify(code, &text.join(" ")))
    }
}

/// Relay `message` to its recipients' domain by resolving MX records via
/// `resolver` and trying each exchange (lowest preference first) at `port`
/// (`25` in production). The message is expected to be single-domain — the
/// spool enqueues one entry per recipient domain — so the first recipient's
/// domain drives the lookup.
///
/// A domain with no MX falls back to its A/AAAA record as an implicit MX
/// (RFC 5321 §5.1). Each exchange is then resolved to its IP address(es) through
/// the same `resolver` (so the final hop no longer relies on the OS resolver at
/// connect time). The first exchange to deliver wins; a permanent (`5xx`)
/// rejection stops immediately; otherwise the last transient outcome is
/// returned so the caller can retry.
///
/// `tls`, when set, enables opportunistic STARTTLS per exchange (the exchange
/// hostname is used as the TLS server name); see [`relay_to`].
///
/// `mta_sts`, when set, enables RFC 8461 MTA-STS: the recipient domain's policy
/// is resolved and, in `enforce` mode, only policy-matched exchanges are tried
/// and each is delivered to under [`TlsPolicy::Strict`] (PKIX-validated TLS, no
/// cleartext fallback). With no policy (or `none`/`testing` mode) the relay falls
/// back to the opportunistic `tls` behaviour.
pub async fn relay(
    resolver: &dyn DnsResolver,
    helo: &str,
    port: u16,
    message: &Message,
    tls: Option<&Arc<ClientConfig>>,
    mta_sts: Option<&MtaStsResolver>,
) -> RelayReport {
    let Some(domain) = message
        .envelope
        .recipients
        .first()
        .map(|m| m.domain.clone())
    else {
        return RelayReport::Failed {
            reason: "message has no recipients".to_string(),
        };
    };

    let exchanges = match resolver.lookup_mx(&domain).await {
        Ok(mut mxs) if !mxs.is_empty() => {
            mxs.sort_by_key(|mx| mx.preference);
            mxs
        }
        // No MX record: the domain's own A/AAAA is the implicit mail exchange.
        Ok(_) => vec![MxRecord {
            preference: 0,
            exchange: domain.clone(),
        }],
        Err(error) => {
            return RelayReport::Deferred {
                code: 0,
                text: format!("MX lookup for {domain}: {error}"),
            };
        }
    };

    // RFC 7505 null MX: a `0 .` record means the domain explicitly accepts no
    // mail. That is a permanent condition — bounce immediately rather than
    // connecting to an empty exchange (`:25`) and retrying until the queue gives
    // up. (A null MX must be the sole record, so "all null" captures it.)
    if exchanges.iter().all(MxRecord::is_null) {
        return RelayReport::Failed {
            reason: format!("{domain} does not accept mail (null MX, RFC 7505)"),
        };
    }

    // Resolve any MTA-STS policy for the recipient domain. In `enforce` mode it
    // both constrains which exchanges are usable and mandates PKIX TLS to them.
    let sts_policy = match mta_sts {
        Some(sts) => sts.policy_for(&domain).await,
        None => None,
    };
    let enforce = sts_policy
        .as_ref()
        .is_some_and(|p| p.mode == MtaStsMode::Enforce);
    let pkix = mta_sts.map(MtaStsResolver::pkix_config);

    let mut last = RelayReport::Deferred {
        code: 0,
        text: format!("no usable MX for {domain}"),
    };
    let mut attempted = false;
    for mx in &exchanges {
        // Defensive: never connect to an empty exchange (`:25`). A lone null MX
        // was already handled above; this skips a null mixed in with real records
        // (a misconfiguration) so we still try the deliverable hosts.
        if mx.is_null() {
            continue;
        }
        // Per-exchange TLS posture. Under MTA-STS enforce an unauthorized MX is
        // skipped entirely (RFC 8461 §4.1); an authorized one is delivered to
        // under Strict (PKIX, mandatory); otherwise opportunistic (or none).
        let Some(tls_policy) = exchange_tls_policy(sts_policy.as_ref(), pkix, &mx.exchange, tls)
        else {
            continue;
        };
        attempted = true;
        // Resolve the exchange to address(es) through the same (hickory) resolver
        // rather than letting the OS resolver do the final hop at connect time.
        // An address-literal exchange is used directly; the hostname is still used
        // as the TLS server name when STARTTLS upgrades.
        let addresses = match resolve_exchange(resolver, &mx.exchange).await {
            Ok(addrs) => addrs,
            Err(text) => {
                last = RelayReport::Deferred { code: 0, text };
                continue;
            }
        };
        for ip in addresses {
            let addr = SocketAddr::new(ip, port).to_string();
            match relay_to(&addr, &mx.exchange, helo, message, &tls_policy).await {
                Ok(RelayReport::Delivered) => return RelayReport::Delivered,
                Ok(failed @ RelayReport::Failed { .. }) => return failed, // permanent; stop
                Ok(deferred) => last = deferred, // try the next address / MX
                Err(error) => {
                    last = RelayReport::Deferred {
                        code: 0,
                        text: format!("{addr}: {error}"),
                    };
                }
            }
        }
    }

    // Under enforce, if no MX was authorized by the policy, the domain's
    // published MX disagree with its own policy — a transient misconfiguration,
    // so defer (RFC 8461 §5) rather than bounce.
    if enforce && !attempted {
        return RelayReport::Deferred {
            code: 0,
            text: format!("no MX for {domain} matches its MTA-STS policy"),
        };
    }
    last
}

/// Decide the per-exchange [`TlsPolicy`] under an optional MTA-STS policy.
///
/// Returns `None` to signal the exchange must be **skipped** — only under an
/// `enforce` policy whose `mx` patterns do not authorize `mx_host`, or when an
/// `enforce` policy is in force but no PKIX config is available to satisfy it
/// (skip rather than downgrade to cleartext). Otherwise:
/// - `enforce` + authorized MX → [`TlsPolicy::Strict`] (mandatory, PKIX TLS);
/// - any other case (`testing` / `none` / no policy) → the opportunistic config
///   when one is available, else [`TlsPolicy::None`].
fn exchange_tls_policy(
    sts: Option<&MtaStsPolicy>,
    pkix: Option<&Arc<ClientConfig>>,
    mx_host: &str,
    opportunistic: Option<&Arc<ClientConfig>>,
) -> Option<TlsPolicy> {
    if let Some(policy) = sts
        && policy.mode == MtaStsMode::Enforce
    {
        if !policy.allows_mx(mx_host) {
            return None;
        }
        return pkix.map(|c| TlsPolicy::Strict(Arc::clone(c)));
    }
    Some(opportunistic.map_or(TlsPolicy::None, |c| TlsPolicy::Opportunistic(Arc::clone(c))))
}

/// Resolve an MX exchange to its IP address(es) via `resolver`. An address-literal
/// exchange is returned verbatim (no lookup); a hostname is resolved through
/// hickory's A/AAAA lookup. An empty/failed lookup is a transient condition.
async fn resolve_exchange(
    resolver: &dyn DnsResolver,
    exchange: &str,
) -> std::result::Result<Vec<IpAddr>, String> {
    if let Ok(ip) = exchange.parse::<IpAddr>() {
        return Ok(vec![ip]);
    }
    match resolver.lookup_ip(exchange).await {
        Ok(records) if !records.is_empty() => Ok(records.iter().map(|r| r.0).collect()),
        Ok(_) => Err(format!("no A/AAAA address for MX {exchange}")),
        Err(error) => Err(format!("address lookup for MX {exchange}: {error}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mail::{Envelope, Mailbox};
    use tokio::net::TcpListener;

    fn message() -> Message {
        Message::parse(
            Envelope::new(
                Some(Mailbox::parse("alice@example.com").unwrap()),
                vec![Mailbox::parse("bob@remote.test").unwrap()],
            ),
            b"Subject: hi\r\n\r\nhello world",
        )
        .unwrap()
    }

    #[tokio::test]
    async fn read_reply_single_line() {
        let mut r = BufReader::new(&b"250 OK\r\n"[..]);
        let (code, texts) = read_reply(&mut r).await.unwrap();
        assert_eq!(code, 250);
        assert_eq!(texts, vec!["OK".to_string()]);
    }

    #[tokio::test]
    async fn read_reply_multiline_ehlo() {
        let mut r = BufReader::new(&b"250-mx.test Hello\r\n250-PIPELINING\r\n250 STARTTLS\r\n"[..]);
        let (code, texts) = read_reply(&mut r).await.unwrap();
        assert_eq!(code, 250);
        assert_eq!(texts, vec!["mx.test Hello", "PIPELINING", "STARTTLS"]);
    }

    #[tokio::test]
    async fn read_reply_errors_on_eof() {
        let mut r = BufReader::new(&b""[..]);
        assert!(read_reply(&mut r).await.is_err());
    }

    /// A minimal SMTP responder that accepts one message, echoing the canonical
    /// codes (with a multiline EHLO to exercise the client reader), and captures
    /// the bytes of the DATA body it received.
    async fn stub_receiver(listener: TcpListener) -> String {
        let (stream, _) = listener.accept().await.unwrap();
        let (read, mut write) = stream.into_split();
        let mut reader = BufReader::new(read);
        write.write_all(b"220 stub ESMTP\r\n").await.unwrap();
        let mut body = String::new();
        let mut in_data = false;
        loop {
            let mut line = String::new();
            if reader.read_line(&mut line).await.unwrap() == 0 {
                break;
            }
            if in_data {
                if line.trim_end_matches(['\r', '\n']) == "." {
                    in_data = false;
                    write.write_all(b"250 accepted\r\n").await.unwrap();
                } else {
                    body.push_str(&line);
                }
                continue;
            }
            let verb = line.split_whitespace().next().unwrap_or("").to_uppercase();
            match verb.as_str() {
                "EHLO" | "HELO" => write
                    .write_all(b"250-stub Hello\r\n250 STARTTLS\r\n")
                    .await
                    .unwrap(),
                "MAIL" | "RCPT" => write.write_all(b"250 OK\r\n").await.unwrap(),
                "DATA" => {
                    write.write_all(b"354 go ahead\r\n").await.unwrap();
                    in_data = true;
                }
                "QUIT" => {
                    write.write_all(b"221 bye\r\n").await.unwrap();
                    break;
                }
                _ => write.write_all(b"500 unknown\r\n").await.unwrap(),
            }
        }
        body
    }

    #[tokio::test]
    async fn relay_to_delivers_and_transmits_body() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        let server = tokio::spawn(stub_receiver(listener));

        // No client TLS config: even though the stub advertises STARTTLS, the
        // relay stays in plaintext (this exercises the non-TLS path).
        let report = relay_to(
            &addr,
            "stub.test",
            "relay.example.com",
            &message(),
            &TlsPolicy::None,
        )
        .await
        .unwrap();
        assert_eq!(report, RelayReport::Delivered);

        let body = server.await.unwrap();
        assert!(body.contains("Subject: hi"));
        assert!(body.contains("hello world"));
    }

    #[tokio::test]
    async fn relay_to_defers_when_connection_refused() {
        // Bind then drop the listener to get a port nobody is listening on.
        let addr = {
            let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
            l.local_addr().unwrap().to_string()
        };
        let report = relay_to(&addr, "h", "h", &message(), &TlsPolicy::None)
            .await
            .unwrap();
        assert!(matches!(report, RelayReport::Deferred { code: 0, .. }));
    }

    /// A self-signed cert + key (PEM) for `localhost`.
    fn self_signed() -> (String, String) {
        let ck = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
        (ck.cert.pem(), ck.key_pair.serialize_pem())
    }

    /// A TLS-capable SMTP responder: greets, advertises STARTTLS, performs the
    /// rustls server handshake on `STARTTLS`, then runs the whole mail
    /// transaction over the *encrypted* channel. Returns the DATA body it
    /// received — which it only ever reads after the handshake, so a non-empty
    /// body proves the message crossed the wire under TLS, not in cleartext.
    async fn starttls_receiver(listener: TcpListener, config: Arc<rustls::ServerConfig>) -> String {
        let (stream, _) = listener.accept().await.unwrap();
        let mut plain = BufReader::new(stream);
        plain.write_all(b"220 stub ESMTP\r\n").await.unwrap();
        plain.flush().await.unwrap();

        // Plaintext phase: EHLO (advertise STARTTLS) then the STARTTLS command.
        let mut line = String::new();
        plain.read_line(&mut line).await.unwrap();
        assert!(line.to_uppercase().starts_with("EHLO"), "got {line:?}");
        plain
            .write_all(b"250-stub Hello\r\n250 STARTTLS\r\n")
            .await
            .unwrap();
        plain.flush().await.unwrap();
        line.clear();
        plain.read_line(&mut line).await.unwrap();
        assert!(
            line.trim_end().eq_ignore_ascii_case("STARTTLS"),
            "expected STARTTLS, got {line:?}"
        );
        plain.write_all(b"220 go ahead\r\n").await.unwrap();
        plain.flush().await.unwrap();
        assert!(
            plain.buffer().is_empty(),
            "client must not pipeline before TLS"
        );

        // Upgrade the receiver side and run the rest over TLS.
        let tcp = plain.into_inner();
        let tls = network::tls::accept(config, tcp).await.unwrap();
        let mut conn = BufReader::new(tls);
        let mut body = String::new();
        let mut in_data = false;
        loop {
            let mut l = String::new();
            if conn.read_line(&mut l).await.unwrap() == 0 {
                break;
            }
            if in_data {
                if l.trim_end_matches(['\r', '\n']) == "." {
                    in_data = false;
                    conn.write_all(b"250 accepted\r\n").await.unwrap();
                    conn.flush().await.unwrap();
                } else {
                    body.push_str(&l);
                }
                continue;
            }
            match l
                .split_whitespace()
                .next()
                .unwrap_or("")
                .to_uppercase()
                .as_str()
            {
                "EHLO" | "HELO" => conn.write_all(b"250 stub\r\n").await.unwrap(),
                "MAIL" | "RCPT" => conn.write_all(b"250 OK\r\n").await.unwrap(),
                "DATA" => {
                    conn.write_all(b"354 go\r\n").await.unwrap();
                    in_data = true;
                }
                "QUIT" => {
                    conn.write_all(b"221 bye\r\n").await.unwrap();
                    conn.flush().await.unwrap();
                    break;
                }
                _ => conn.write_all(b"500 no\r\n").await.unwrap(),
            }
            conn.flush().await.unwrap();
        }
        body
    }

    /// A plaintext SMTP responder that does NOT advertise STARTTLS, so an
    /// opportunistic client must complete the transaction in cleartext.
    async fn plain_no_tls_receiver(listener: TcpListener) -> String {
        let (stream, _) = listener.accept().await.unwrap();
        let (read, mut write) = stream.into_split();
        let mut reader = BufReader::new(read);
        write.write_all(b"220 stub ESMTP\r\n").await.unwrap();
        let mut body = String::new();
        let mut in_data = false;
        loop {
            let mut line = String::new();
            if reader.read_line(&mut line).await.unwrap() == 0 {
                break;
            }
            if in_data {
                if line.trim_end_matches(['\r', '\n']) == "." {
                    in_data = false;
                    write.write_all(b"250 accepted\r\n").await.unwrap();
                } else {
                    body.push_str(&line);
                }
                continue;
            }
            match line
                .split_whitespace()
                .next()
                .unwrap_or("")
                .to_uppercase()
                .as_str()
            {
                // EHLO reply with no STARTTLS capability.
                "EHLO" | "HELO" => write.write_all(b"250 stub\r\n").await.unwrap(),
                "MAIL" | "RCPT" => write.write_all(b"250 OK\r\n").await.unwrap(),
                "DATA" => {
                    write.write_all(b"354 go\r\n").await.unwrap();
                    in_data = true;
                }
                "QUIT" => {
                    write.write_all(b"221 bye\r\n").await.unwrap();
                    break;
                }
                _ => write.write_all(b"500 no\r\n").await.unwrap(),
            }
        }
        body
    }

    /// A responder that advertises STARTTLS and accepts the command (`220`) but
    /// then closes the socket instead of performing a TLS handshake.
    async fn starttls_then_drop(listener: TcpListener) {
        let (stream, _) = listener.accept().await.unwrap();
        let (read, mut write) = stream.into_split();
        let mut reader = BufReader::new(read);
        write.write_all(b"220 stub ESMTP\r\n").await.unwrap();
        let mut line = String::new();
        reader.read_line(&mut line).await.unwrap(); // EHLO
        write
            .write_all(b"250-stub Hello\r\n250 STARTTLS\r\n")
            .await
            .unwrap();
        line.clear();
        reader.read_line(&mut line).await.unwrap(); // STARTTLS
        write.write_all(b"220 go ahead\r\n").await.unwrap();
        // Drop both halves: the client's TLS handshake reads EOF and fails.
    }

    #[tokio::test]
    async fn relay_to_upgrades_to_starttls_and_delivers_over_tls() {
        let (cert, key) = self_signed();
        let config = network::TlsConfig::server_from_pem(&cert, &key).unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        let server = tokio::spawn(starttls_receiver(listener, config));

        // Opportunistic client: STARTTLS is offered, so the relay must upgrade.
        let tls = network::TlsConfig::opportunistic_client().unwrap();
        let report = relay_to(
            &addr,
            "127.0.0.1",
            "relay.example.com",
            &message(),
            &TlsPolicy::Opportunistic(tls),
        )
        .await
        .unwrap();
        assert_eq!(report, RelayReport::Delivered);

        // The body was collected only after the handshake → it was encrypted.
        let body = server.await.unwrap();
        assert!(body.contains("Subject: hi"));
        assert!(body.contains("hello world"));
    }

    #[tokio::test]
    async fn relay_to_stays_cleartext_when_starttls_not_offered() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        let server = tokio::spawn(plain_no_tls_receiver(listener));

        // Even with a client TLS config available, a server that offers no
        // STARTTLS gets the message in cleartext — opportunistic, not mandatory.
        let tls = network::TlsConfig::opportunistic_client().unwrap();
        let report = relay_to(
            &addr,
            "127.0.0.1",
            "relay.example.com",
            &message(),
            &TlsPolicy::Opportunistic(tls),
        )
        .await
        .unwrap();
        assert_eq!(report, RelayReport::Delivered);

        let body = server.await.unwrap();
        assert!(body.contains("hello world"));
    }

    #[tokio::test]
    async fn relay_to_defers_when_starttls_handshake_fails() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        tokio::spawn(starttls_then_drop(listener));

        // The server advertised STARTTLS but the handshake cannot complete. We
        // must defer (retry later), never downgrade to cleartext in-session.
        let tls = network::TlsConfig::opportunistic_client().unwrap();
        let report = relay_to(
            &addr,
            "mx.invalid",
            "relay.example.com",
            &message(),
            &TlsPolicy::Opportunistic(tls),
        )
        .await
        .unwrap();
        assert!(
            matches!(report, RelayReport::Deferred { .. }),
            "a failed STARTTLS handshake must defer, got {report:?}"
        );
    }

    /// A resolver that publishes only an RFC 7505 null MX (`0 .`, which the
    /// network layer maps to an empty exchange).
    struct NullMxResolver;

    #[async_trait::async_trait]
    impl network::DnsResolver for NullMxResolver {
        async fn lookup_mx(&self, _domain: &str) -> network::Result<Vec<MxRecord>> {
            Ok(vec![MxRecord {
                preference: 0,
                exchange: String::new(),
            }])
        }
        async fn lookup_ip(&self, _host: &str) -> network::Result<Vec<network::AddressRecord>> {
            Ok(Vec::new())
        }
        async fn lookup_txt(&self, _name: &str) -> network::Result<Vec<network::TxtRecord>> {
            Ok(Vec::new())
        }
        async fn reverse_lookup(
            &self,
            _ip: std::net::IpAddr,
        ) -> network::Result<Vec<network::PtrRecord>> {
            Ok(Vec::new())
        }
    }

    #[tokio::test]
    async fn relay_bounces_permanently_on_null_mx() {
        // A null MX means the domain accepts no mail — a permanent failure, so the
        // worker bounces immediately instead of connecting to ":25" and retrying.
        let report = relay(
            &NullMxResolver,
            "relay.example.com",
            25,
            &message(),
            None,
            None,
        )
        .await;
        assert!(
            matches!(report, RelayReport::Failed { .. }),
            "a null MX must be a permanent failure, got {report:?}"
        );
    }

    /// A resolver whose MX is a *hostname* (`mx.test`) that A-resolves to loopback,
    /// exercising the hickory MX→IP final hop (the OS resolver could not resolve
    /// `mx.test`, so delivery proves the address came from this resolver).
    struct HostnameMxResolver;

    #[async_trait::async_trait]
    impl network::DnsResolver for HostnameMxResolver {
        async fn lookup_mx(&self, _domain: &str) -> network::Result<Vec<MxRecord>> {
            Ok(vec![MxRecord {
                preference: 10,
                exchange: "mx.test".to_string(),
            }])
        }
        async fn lookup_ip(&self, host: &str) -> network::Result<Vec<network::AddressRecord>> {
            if host == "mx.test" {
                Ok(vec![network::AddressRecord("127.0.0.1".parse().unwrap())])
            } else {
                Ok(Vec::new())
            }
        }
        async fn lookup_txt(&self, _name: &str) -> network::Result<Vec<network::TxtRecord>> {
            Ok(Vec::new())
        }
        async fn reverse_lookup(
            &self,
            _ip: std::net::IpAddr,
        ) -> network::Result<Vec<network::PtrRecord>> {
            Ok(Vec::new())
        }
    }

    #[tokio::test]
    async fn relay_resolves_hostname_mx_via_resolver_and_delivers() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = tokio::spawn(stub_receiver(listener));

        // The MX `mx.test` is resolved to loopback through the resolver (not the OS
        // resolver), then connected to at the relay port.
        let report = relay(
            &HostnameMxResolver,
            "relay.example.com",
            port,
            &message(),
            None,
            None,
        )
        .await;
        assert_eq!(report, RelayReport::Delivered);

        let body = server.await.unwrap();
        assert!(body.contains("hello world"));
    }

    #[tokio::test]
    async fn relay_defers_when_mx_host_has_no_address() {
        // An MX hostname that resolves to no address is a transient condition.
        struct NoAddr;
        #[async_trait::async_trait]
        impl network::DnsResolver for NoAddr {
            async fn lookup_mx(&self, _d: &str) -> network::Result<Vec<MxRecord>> {
                Ok(vec![MxRecord {
                    preference: 10,
                    exchange: "mx.test".to_string(),
                }])
            }
            async fn lookup_ip(&self, _h: &str) -> network::Result<Vec<network::AddressRecord>> {
                Ok(Vec::new())
            }
            async fn lookup_txt(&self, _n: &str) -> network::Result<Vec<network::TxtRecord>> {
                Ok(Vec::new())
            }
            async fn reverse_lookup(
                &self,
                _ip: std::net::IpAddr,
            ) -> network::Result<Vec<network::PtrRecord>> {
                Ok(Vec::new())
            }
        }
        let report = relay(&NoAddr, "relay.example.com", 25, &message(), None, None).await;
        assert!(
            matches!(report, RelayReport::Deferred { .. }),
            "an MX with no address is transient, got {report:?}"
        );
    }

    #[tokio::test]
    #[ignore = "hits live DNS + the network; run with --ignored"]
    async fn relay_live_mx_path() {
        // `example.com` is reserved and accepts no mail, so this exercises the
        // live resolver (MX lookup → A fallback) and connect handling without
        // ever delivering a message.
        let resolver = network::HickoryResolver::from_system().unwrap();
        let probe = Message::parse(
            Envelope::new(
                Some(Mailbox::parse("postmaster@snail.invalid").unwrap()),
                vec![Mailbox::parse("nobody@example.com").unwrap()],
            ),
            b"Subject: probe\r\n\r\nignored",
        )
        .unwrap();
        let report = relay(&resolver, "snail.invalid", 25, &probe, None, None).await;
        assert!(
            !matches!(report, RelayReport::Delivered),
            "example.com must not accept mail, got {report:?}"
        );
    }

    #[tokio::test]
    async fn strict_policy_defers_when_starttls_not_offered() {
        // The security property of MTA-STS `enforce`: a server that does NOT
        // advertise STARTTLS must be DEFERRED, never delivered to in cleartext.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        // Spawn (and abandon) the plaintext receiver: the relay never reaches DATA.
        tokio::spawn(plain_no_tls_receiver(listener));

        let pkix = network::TlsConfig::pkix_client().unwrap();
        let report = relay_to(
            &addr,
            "mx.example.com",
            "relay.example.com",
            &message(),
            &TlsPolicy::Strict(pkix),
        )
        .await
        .unwrap();
        assert!(
            matches!(report, RelayReport::Deferred { .. }),
            "MTA-STS enforce must defer when STARTTLS is absent, got {report:?}"
        );
    }

    #[tokio::test]
    async fn strict_policy_defers_when_certificate_is_untrusted() {
        // Under enforce, STARTTLS is offered but the cert is self-signed (does not
        // chain to the PKIX roots), so the handshake fails and we defer — never
        // downgrading to cleartext after offering to encrypt.
        let (cert, key) = self_signed();
        let config = network::TlsConfig::server_from_pem(&cert, &key).unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        tokio::spawn(starttls_receiver(listener, config));

        let pkix = network::TlsConfig::pkix_client().unwrap();
        let report = relay_to(
            &addr,
            "mx.example.com",
            "relay.example.com",
            &message(),
            &TlsPolicy::Strict(pkix),
        )
        .await
        .unwrap();
        assert!(
            matches!(report, RelayReport::Deferred { .. }),
            "a PKIX-invalid cert under enforce must defer, got {report:?}"
        );
    }

    #[test]
    fn exchange_tls_policy_selects_per_mode() {
        let opportunistic = network::TlsConfig::opportunistic_client().unwrap();
        let pkix = network::TlsConfig::pkix_client().unwrap();

        // No policy → opportunistic when a config exists, else None.
        assert!(matches!(
            exchange_tls_policy(None, Some(&pkix), "mx.example.com", Some(&opportunistic)),
            Some(TlsPolicy::Opportunistic(_))
        ));
        assert!(matches!(
            exchange_tls_policy(None, None, "mx.example.com", None),
            Some(TlsPolicy::None)
        ));

        // `none`/`testing` modes are advisory → opportunistic, never skipped.
        let testing = MtaStsPolicy {
            mode: MtaStsMode::Testing,
            mx: vec!["other.example.com".into()],
            max_age: 100,
        };
        assert!(matches!(
            exchange_tls_policy(
                Some(&testing),
                Some(&pkix),
                "mx.example.com",
                Some(&opportunistic)
            ),
            Some(TlsPolicy::Opportunistic(_))
        ));

        // `enforce`: an authorized MX → Strict; an unauthorized MX → skip (None).
        let enforce = MtaStsPolicy {
            mode: MtaStsMode::Enforce,
            mx: vec!["mx.example.com".into()],
            max_age: 100,
        };
        assert!(matches!(
            exchange_tls_policy(
                Some(&enforce),
                Some(&pkix),
                "mx.example.com",
                Some(&opportunistic)
            ),
            Some(TlsPolicy::Strict(_))
        ));
        assert!(
            exchange_tls_policy(
                Some(&enforce),
                Some(&pkix),
                "evil.example.net",
                Some(&opportunistic)
            )
            .is_none(),
            "an MX outside the policy must be skipped under enforce"
        );
    }
}
