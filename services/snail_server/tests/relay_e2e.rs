//! End-to-end internet-MTA test: a message submitted (authenticated) to one
//! Snail server, addressed to a domain hosted by a *second* Snail server, is
//! spooled, relayed over real TCP by the relay worker, received by the second
//! server's inbound MX listener, and delivered to its mailbox store.
//!
//! A mock resolver points MX at the loopback interface and the sender's relay
//! port is the receiver's ephemeral port, so the whole path runs without DNS or
//! the privileged port 25.

use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use mail::MailStore;
use snail_server::{
    OutboundSpool, Server, ServerConfig, relay_due, serve_inbound, serve_submission,
};
use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};

/// Resolver that points every domain at the loopback interface.
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

async fn read_line<R: AsyncBufRead + Unpin>(r: &mut R) -> String {
    let mut buf = String::new();
    r.read_line(&mut buf).await.unwrap();
    buf.trim_end().to_string()
}

#[tokio::test]
async fn submission_relays_across_servers_to_inbound_receiver() {
    // ---- Receiver: hosts remote.test, accepts inbound mail on an ephemeral port.
    let receiver = Arc::new(Server::new(&ServerConfig::new(["remote.test".to_string()])));
    let recv_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let recv_port = recv_listener.local_addr().unwrap().port();
    {
        let r = Arc::clone(&receiver);
        tokio::spawn(async move {
            let (s, _) = recv_listener.accept().await.unwrap();
            serve_inbound(s, r).await.unwrap();
        });
    }

    // ---- Sender: hosts example.com, relays remote mail to the receiver's port.
    let spool_dir = std::env::temp_dir().join(format!(
        "snail-relay-e2e-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let spool = Arc::new(OutboundSpool::open(&spool_dir).unwrap());
    let mut sender = Server::new(&ServerConfig::new(["example.com".to_string()]))
        .with_relay(Arc::new(LoopbackResolver), Arc::clone(&spool))
        .with_relay_port(recv_port);
    sender.register_user("alice@example.com", "pw").unwrap();
    let sender = Arc::new(sender);

    let sub_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let sub_addr = sub_listener.local_addr().unwrap();
    {
        let s = Arc::clone(&sender);
        tokio::spawn(async move {
            let (c, peer) = sub_listener.accept().await.unwrap();
            serve_submission(c, peer, s).await.unwrap();
        });
    }

    // ---- Submit (authenticated) a message addressed to bob@remote.test.
    let client = TcpStream::connect(sub_addr).await.unwrap();
    let (cr, mut cw) = client.into_split();
    let mut cr = BufReader::new(cr);
    assert!(read_line(&mut cr).await.starts_with("220"));
    let auth = BASE64.encode("\0alice@example.com\0pw");
    for (cmd, expect) in [
        ("EHLO client".to_string(), "250"),
        (format!("AUTH PLAIN {auth}"), "235"),
        ("MAIL FROM:<alice@example.com>".to_string(), "250"),
        ("RCPT TO:<bob@remote.test>".to_string(), "250"),
        ("DATA".to_string(), "354"),
    ] {
        cw.write_all(format!("{cmd}\r\n").as_bytes()).await.unwrap();
        assert!(read_line(&mut cr).await.starts_with(expect), "cmd {cmd}");
    }
    cw.write_all(b"Subject: cross-server\r\n\r\nrelayed hello\r\n.\r\n")
        .await
        .unwrap();
    assert!(read_line(&mut cr).await.starts_with("250")); // accepted (spooled for relay)
    cw.write_all(b"QUIT\r\n").await.unwrap();

    // The remote recipient is now spooled; drive the relay worker once.
    relay_due(&sender).await;

    // The receiver delivers in its connection task; poll its store briefly.
    let mut delivered = false;
    for _ in 0..100 {
        if receiver.store().count("bob@remote.test") == 1 {
            delivered = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(
        delivered,
        "the relayed message should be delivered to the receiving server's store"
    );

    // The spool drained (delivered → removed); nothing left to retry.
    assert!(
        spool
            .due_now(std::time::SystemTime::now() + Duration::from_secs(1))
            .unwrap()
            .is_empty()
    );

    let _ = std::fs::remove_dir_all(spool_dir);
}

/// The same submission→relay→inbound path, but the receiving server advertises
/// STARTTLS. The sender's relay worker must opportunistically upgrade to TLS
/// (STARTTLS → handshake → re-EHLO) and deliver the message over the encrypted
/// channel — proving the cleartext-relay gap is closed end to end.
#[tokio::test]
async fn submission_relays_over_starttls_across_servers() {
    // ---- Receiver: hosts remote.test AND offers STARTTLS (self-signed cert).
    let ck = rcgen::generate_simple_self_signed(vec!["remote.test".to_string()]).unwrap();
    let certs = mail::MailCerts::new(ck.cert.pem(), ck.key_pair.serialize_pem()).unwrap();
    let receiver = Arc::new(
        Server::new(&ServerConfig::new(["remote.test".to_string()]))
            .with_tls(&certs)
            .unwrap(),
    );
    let recv_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let recv_port = recv_listener.local_addr().unwrap().port();
    {
        let r = Arc::clone(&receiver);
        tokio::spawn(async move {
            let (s, _) = recv_listener.accept().await.unwrap();
            serve_inbound(s, r).await.unwrap();
        });
    }

    // ---- Sender: relay enabled. `with_relay` builds the opportunistic-STARTTLS
    // client config, so the worker will upgrade to TLS when the receiver offers it.
    let spool_dir = std::env::temp_dir().join(format!(
        "snail-relay-tls-e2e-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let spool = Arc::new(OutboundSpool::open(&spool_dir).unwrap());
    let mut sender = Server::new(&ServerConfig::new(["example.com".to_string()]))
        .with_relay(Arc::new(LoopbackResolver), Arc::clone(&spool))
        .with_relay_port(recv_port);
    sender.register_user("alice@example.com", "pw").unwrap();
    let sender = Arc::new(sender);

    let sub_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let sub_addr = sub_listener.local_addr().unwrap();
    {
        let s = Arc::clone(&sender);
        tokio::spawn(async move {
            let (c, peer) = sub_listener.accept().await.unwrap();
            serve_submission(c, peer, s).await.unwrap();
        });
    }

    // ---- Submit (authenticated) a message addressed to bob@remote.test.
    let client = TcpStream::connect(sub_addr).await.unwrap();
    let (cr, mut cw) = client.into_split();
    let mut cr = BufReader::new(cr);
    assert!(read_line(&mut cr).await.starts_with("220"));
    let auth = BASE64.encode("\0alice@example.com\0pw");
    for (cmd, expect) in [
        ("EHLO client".to_string(), "250"),
        (format!("AUTH PLAIN {auth}"), "235"),
        ("MAIL FROM:<alice@example.com>".to_string(), "250"),
        ("RCPT TO:<bob@remote.test>".to_string(), "250"),
        ("DATA".to_string(), "354"),
    ] {
        cw.write_all(format!("{cmd}\r\n").as_bytes()).await.unwrap();
        assert!(read_line(&mut cr).await.starts_with(expect), "cmd {cmd}");
    }
    cw.write_all(b"Subject: secure-relay\r\n\r\nhello over tls\r\n.\r\n")
        .await
        .unwrap();
    assert!(read_line(&mut cr).await.starts_with("250")); // accepted (spooled)
    cw.write_all(b"QUIT\r\n").await.unwrap();

    // Drive the relay worker: it must STARTTLS-upgrade and deliver over TLS.
    relay_due(&sender).await;

    let mut delivered = false;
    for _ in 0..100 {
        if receiver.store().count("bob@remote.test") == 1 {
            delivered = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(
        delivered,
        "the relayed message should be delivered over STARTTLS to the receiver"
    );

    // Delivered → spool drained.
    assert!(
        spool
            .due_now(std::time::SystemTime::now() + Duration::from_secs(1))
            .unwrap()
            .is_empty()
    );

    let _ = std::fs::remove_dir_all(spool_dir);
}
