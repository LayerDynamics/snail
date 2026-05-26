//! Outbound relay: the SMTP *client* socket dialog. Drives the protocol script
//! built by [`mail::transport::relay_script`] over a TCP connection to a
//! downstream server, reading the (possibly multiline) replies and classifying
//! the result for the retry spool. MX resolution lives in [`crate::relay`]; this
//! is the single-target transmit.

use mail::Message;
use mail::transport::relay_script;
use network::{DnsResolver, MxRecord};
use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;

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

/// Relay `message` to a single server at `addr` (`host:port`), announcing
/// ourselves as `helo`. Connection failures become [`RelayReport::Deferred`] so
/// the caller can retry; genuine socket errors after connect propagate.
///
/// # Errors
/// [`std::io::Error`] on a read/write failure once connected.
pub async fn relay_to(addr: &str, helo: &str, message: &Message) -> std::io::Result<RelayReport> {
    let script = relay_script(helo, message);
    let stream = match TcpStream::connect(addr).await {
        Ok(stream) => stream,
        Err(error) => {
            return Ok(RelayReport::Deferred {
                code: 0,
                text: format!("connect {addr}: {error}"),
            });
        }
    };
    let (read, mut write) = stream.into_split();
    let mut reader = BufReader::new(read);

    // Server greeting.
    let (code, text) = read_reply(&mut reader).await?;
    if !(200..400).contains(&code) {
        return Ok(classify(code, &format!("greeting: {}", text.join(" "))));
    }

    // Issue each scripted command, awaiting the expected reply.
    for command in &script.commands {
        write.write_all(command.as_bytes()).await?;
        write.write_all(b"\r\n").await?;
        let (code, text) = read_reply(&mut reader).await?;
        let ok = if command == "DATA" {
            code == 354
        } else {
            (200..300).contains(&code)
        };
        if !ok {
            return Ok(classify(
                code,
                &format!("after `{command}`: {}", text.join(" ")),
            ));
        }
    }

    // Transmit the dot-stuffed, terminated DATA payload and read the verdict.
    write.write_all(&script.data).await?;
    let (code, text) = read_reply(&mut reader).await?;
    let _ = write.write_all(b"QUIT\r\n").await; // best-effort

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
/// (RFC 5321 §5.1). The first exchange to deliver wins; a permanent (`5xx`)
/// rejection stops immediately; otherwise the last transient outcome is
/// returned so the caller can retry.
pub async fn relay(
    resolver: &dyn DnsResolver,
    helo: &str,
    port: u16,
    message: &Message,
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

    let mut last = RelayReport::Deferred {
        code: 0,
        text: format!("no usable MX for {domain}"),
    };
    for mx in &exchanges {
        let addr = format!("{}:{}", mx.exchange, port);
        match relay_to(&addr, helo, message).await {
            Ok(RelayReport::Delivered) => return RelayReport::Delivered,
            Ok(failed @ RelayReport::Failed { .. }) => return failed, // permanent; stop
            Ok(deferred) => last = deferred,                          // try the next MX
            Err(error) => {
                last = RelayReport::Deferred {
                    code: 0,
                    text: format!("{addr}: {error}"),
                };
            }
        }
    }
    last
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

        let report = relay_to(&addr, "relay.example.com", &message())
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
        let report = relay_to(&addr, "h", &message()).await.unwrap();
        assert!(matches!(report, RelayReport::Deferred { code: 0, .. }));
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
        let report = relay(&resolver, "snail.invalid", 25, &probe).await;
        assert!(
            !matches!(report, RelayReport::Delivered),
            "example.com must not accept mail, got {report:?}"
        );
    }
}
