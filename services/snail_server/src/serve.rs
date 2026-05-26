//! Async TCP servers that drive the (synchronous) protocol sessions over
//! sockets, plus the listener orchestration with graceful shutdown.
//!
//! Framing is UTF-8 line based; binary message bodies are a future enhancement.

use std::sync::Arc;

use access::{
    ImapCommand, ImapSession, MsaSession, Pop3Session, PopCommand, PopReply, TaggedCommand,
};
use mail::{InboundCollector, SmtpCommand};
use tokio::io::{AsyncBufReadExt, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};

use crate::server::Server;

/// Bind addresses for the protocol listeners.
#[derive(Debug, Clone)]
pub struct Listeners {
    /// Authenticated submission (SMTP+AUTH), e.g. `127.0.0.1:587`.
    pub submission: String,
    /// POP3, e.g. `127.0.0.1:110`.
    pub pop3: String,
    /// IMAP, e.g. `127.0.0.1:143`.
    pub imap: String,
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
    tracing::info!(
        submission = %listeners.submission,
        pop3 = %listeners.pop3,
        imap = %listeners.imap,
        "snail-server listening"
    );

    loop {
        tokio::select! {
            Ok((stream, _)) = submission.accept() => spawn(serve_submission(stream, Arc::clone(&server))),
            Ok((stream, _)) = pop3.accept() => spawn(serve_pop(stream, Arc::clone(&server))),
            Ok((stream, _)) = imap.accept() => spawn(serve_imap(stream, Arc::clone(&server))),
            _ = tokio::signal::ctrl_c() => {
                tracing::info!("shutdown signal received");
                break;
            }
        }
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

/// Serve one authenticated-submission (SMTP) connection.
///
/// # Errors
/// [`std::io::Error`] on socket failure.
pub async fn serve_submission(stream: TcpStream, server: Arc<Server>) -> std::io::Result<()> {
    let (read, mut write) = stream.into_split();
    let mut lines = BufReader::new(read).lines();
    let mut msa = MsaSession::new(server.authenticator());
    let mut collecting: Option<InboundCollector> = None;

    write.write_all(b"220 Snail ESMTP ready\r\n").await?;
    while let Some(line) = lines.next_line().await? {
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
                write.write_all(reply.as_bytes()).await?;
            }
            continue;
        }

        let trimmed = line.trim_end();
        // SASL PLAIN, initial-response form: `AUTH PLAIN <base64>`.
        if let Some(rest) = strip_prefix_ci(trimmed, "AUTH PLAIN") {
            let reply = match rest.trim() {
                "" => SmtpReplyText::new(501, "AUTH PLAIN requires an initial response"),
                b64 => {
                    let r = msa.authenticate_plain(b64);
                    SmtpReplyText::new(r.code, &r.text)
                }
            };
            write.write_all(reply.to_wire().as_bytes()).await?;
            continue;
        }

        match SmtpCommand::parse(&line) {
            Ok(command) => {
                let is_quit = matches!(command, SmtpCommand::Quit);
                let reply = msa.handle(command);
                write
                    .write_all(format!("{} {}\r\n", reply.code, reply.text).as_bytes())
                    .await?;
                if reply.code == 354 {
                    collecting = Some(InboundCollector::new());
                }
                if is_quit {
                    break;
                }
            }
            Err(error) => {
                write
                    .write_all(format!("500 {error}\r\n").as_bytes())
                    .await?;
            }
        }
    }
    Ok(())
}

/// Serve one POP3 connection.
///
/// # Errors
/// [`std::io::Error`] on socket failure.
pub async fn serve_pop(stream: TcpStream, server: Arc<Server>) -> std::io::Result<()> {
    let (read, mut write) = stream.into_split();
    let mut lines = BufReader::new(read).lines();
    let mut session = Pop3Session::new(server.authenticator(), server.store());

    write.write_all(b"+OK Snail POP3 ready\r\n").await?;
    while let Some(line) = lines.next_line().await? {
        let is_quit = line.trim_end().eq_ignore_ascii_case("QUIT");
        match PopCommand::parse(&line) {
            Ok(command) => {
                let reply = session.handle(command);
                write_pop_reply(&mut write, &reply).await?;
            }
            Err(error) => {
                write
                    .write_all(format!("-ERR {error}\r\n").as_bytes())
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
    let (read, mut write) = stream.into_split();
    let mut lines = BufReader::new(read).lines();
    let mut session = ImapSession::new(server.authenticator(), server.store());

    write.write_all(b"* OK Snail IMAP4rev1 ready\r\n").await?;
    while let Some(line) = lines.next_line().await? {
        match TaggedCommand::parse(&line) {
            Ok(tagged) => {
                let is_logout = matches!(tagged.command, ImapCommand::Logout);
                let response = session.handle(tagged);
                for untagged in &response.untagged {
                    write
                        .write_all(format!("* {untagged}\r\n").as_bytes())
                        .await?;
                }
                write
                    .write_all(format!("{}\r\n", response.status).as_bytes())
                    .await?;
                if is_logout {
                    break;
                }
            }
            Err(error) => {
                write
                    .write_all(format!("* BAD {error}\r\n").as_bytes())
                    .await?;
            }
        }
    }
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
}
