//! The background relay worker: drains due entries from the outbound spool,
//! attempts delivery to their remote MX, and reschedules (with exponential
//! backoff) or bounces them per the result. Runs until a shutdown notification.

use std::sync::Arc;
use std::time::{Duration, SystemTime};

use tokio::sync::Notify;
use tokio::task::JoinHandle;

use crate::outbound::{RelayReport, relay};
use crate::server::Server;
use crate::spool::backoff;

/// Bounce an entry once it has failed this many delivery attempts.
pub const MAX_ATTEMPTS: u32 = 5;

/// Process every entry currently due in the spool, once. Delivered entries are
/// removed; transient failures are deferred with [`backoff`] (and bounced once
/// [`MAX_ATTEMPTS`] is reached); permanent failures are bounced immediately. A
/// no-op when outbound relay is disabled.
pub async fn relay_due(server: &Server) {
    let Some(ctx) = server.relay_context() else {
        return;
    };
    let due = match ctx.spool.due_now(SystemTime::now()) {
        Ok(due) => due,
        Err(error) => {
            tracing::warn!(%error, "outbound spool scan failed");
            return;
        }
    };
    for entry in due {
        let message = match ctx.spool.load_message(&entry.id) {
            Ok(message) => message,
            Err(error) => {
                tracing::warn!(id = %entry.id, %error, "unreadable spool entry; bouncing");
                let _ = ctx.spool.bounce(&entry.id);
                continue;
            }
        };
        match relay(ctx.resolver.as_ref(), &ctx.helo, ctx.port, &message).await {
            RelayReport::Delivered => {
                tracing::info!(id = %entry.id, "relayed to remote MX");
                let _ = ctx.spool.remove(&entry.id);
            }
            RelayReport::Deferred { code, text } => {
                let attempts = entry.attempts + 1;
                if attempts >= MAX_ATTEMPTS {
                    tracing::warn!(id = %entry.id, attempts, code, %text, "relay attempts exhausted; bouncing");
                    let _ = ctx.spool.bounce(&entry.id);
                } else {
                    let next = SystemTime::now() + backoff(attempts);
                    tracing::info!(id = %entry.id, attempts, code, %text, "relay deferred");
                    let _ = ctx.spool.defer(&entry.id, attempts, next);
                }
            }
            RelayReport::Failed { reason } => {
                tracing::warn!(id = %entry.id, %reason, "relay permanently failed; bouncing");
                let _ = ctx.spool.bounce(&entry.id);
            }
        }
    }
}

/// Spawn the relay worker: run [`relay_due`] every `tick` until `shutdown` is
/// notified, then stop. Returns the join handle for a clean await on shutdown.
pub fn spawn_relay_worker(
    server: Arc<Server>,
    shutdown: Arc<Notify>,
    tick: Duration,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            tokio::select! {
                () = shutdown.notified() => break,
                () = tokio::time::sleep(tick) => relay_due(&server).await,
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ServerConfig;
    use crate::spool::OutboundSpool;
    use mail::{Envelope, Mailbox, Message};
    use std::net::IpAddr;
    use std::path::PathBuf;
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    use tokio::net::TcpListener;

    /// A resolver that points every domain at the loopback interface, so relay
    /// connects to a local stub receiver instead of the real internet.
    struct LoopbackResolver;

    #[async_trait::async_trait]
    impl network::DnsResolver for LoopbackResolver {
        async fn lookup_mx(&self, _domain: &str) -> network::Result<Vec<network::MxRecord>> {
            Ok(vec![network::MxRecord {
                preference: 10,
                exchange: "127.0.0.1".to_string(),
            }])
        }
        async fn lookup_ip(&self, _host: &str) -> network::Result<Vec<network::AddressRecord>> {
            Ok(vec![])
        }
        async fn lookup_txt(&self, _name: &str) -> network::Result<Vec<network::TxtRecord>> {
            Ok(vec![])
        }
        async fn reverse_lookup(&self, _ip: IpAddr) -> network::Result<Vec<network::PtrRecord>> {
            Ok(vec![])
        }
    }

    fn temp_spool_dir() -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!(
            "snail-worker-test-{nanos}-{:?}",
            std::thread::current().id()
        ))
    }

    fn remote_message() -> Message {
        Message::parse(
            Envelope::new(
                Some(Mailbox::parse("alice@example.com").unwrap()),
                vec![Mailbox::parse("bob@remote.test").unwrap()],
            ),
            b"Subject: relayed\r\n\r\nhi over relay",
        )
        .unwrap()
    }

    /// Accept-everything SMTP stub; returns the DATA body it received.
    async fn accept_stub(listener: TcpListener) -> String {
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

    /// A stub that greets and answers EHLO, then transiently refuses MAIL (421).
    async fn refuse_stub(listener: TcpListener) {
        let (stream, _) = listener.accept().await.unwrap();
        let (read, mut write) = stream.into_split();
        let mut reader = BufReader::new(read);
        write.write_all(b"220 stub ESMTP\r\n").await.unwrap();
        loop {
            let mut line = String::new();
            if reader.read_line(&mut line).await.unwrap() == 0 {
                break;
            }
            match line
                .split_whitespace()
                .next()
                .unwrap_or("")
                .to_uppercase()
                .as_str()
            {
                "EHLO" | "HELO" => write.write_all(b"250 stub\r\n").await.unwrap(),
                "MAIL" => {
                    write.write_all(b"421 try later\r\n").await.unwrap();
                    break;
                }
                _ => write.write_all(b"250 OK\r\n").await.unwrap(),
            }
        }
    }

    #[tokio::test]
    async fn worker_delivers_due_entry_and_clears_spool() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let recv = tokio::spawn(accept_stub(listener));

        let dir = temp_spool_dir();
        let spool = Arc::new(OutboundSpool::open(&dir).unwrap());
        spool.enqueue(&remote_message()).unwrap();

        let server = Server::new(&ServerConfig::new(["example.com".to_string()]))
            .with_relay(Arc::new(LoopbackResolver), Arc::clone(&spool))
            .with_relay_port(port);

        relay_due(&server).await;

        assert!(
            spool
                .due_now(SystemTime::now() + Duration::from_secs(1))
                .unwrap()
                .is_empty(),
            "a delivered entry must be removed from the spool"
        );
        let body = recv.await.unwrap();
        assert!(body.contains("Subject: relayed"));
        assert!(body.contains("hi over relay"));
        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn worker_defers_on_transient_failure() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(refuse_stub(listener));

        let dir = temp_spool_dir();
        let spool = Arc::new(OutboundSpool::open(&dir).unwrap());
        spool.enqueue(&remote_message()).unwrap();

        let server = Server::new(&ServerConfig::new(["example.com".to_string()]))
            .with_relay(Arc::new(LoopbackResolver), Arc::clone(&spool))
            .with_relay_port(port);

        relay_due(&server).await;

        // Still queued with an incremented attempt count, but no longer due now
        // (the backoff pushed next-attempt into the future).
        let all = spool
            .due_now(SystemTime::now() + Duration::from_secs(100_000))
            .unwrap();
        assert_eq!(all.len(), 1);
        assert_eq!(all[0].attempts, 1);
        assert!(
            spool.due_now(SystemTime::now()).unwrap().is_empty(),
            "deferred entry should not be immediately due"
        );
        let _ = std::fs::remove_dir_all(dir);
    }
}
