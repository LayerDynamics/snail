//! The composed Snail server: wires authentication (`identity` + `security`),
//! the shared mail store, the MTA + delivery agent with the spam `filter`, and
//! exposes the pieces the access servers (`access`) operate over.

use std::sync::Arc;

use filter::SpamFilter;
use identity::{Account, Authenticator};
use mail::{InboundResult, MailCerts, MailDeliveryAgent, Mailbox, MemoryMailStore, Message, Mta};
use network::DnsResolver;
use security::{Credential, CredentialStore, MemoryCredentialStore};

use crate::config::ServerConfig;
use crate::spool::OutboundSpool;

/// The default SMTP relay port (production MX delivery target).
pub const DEFAULT_RELAY_PORT: u16 = 25;

/// Everything the relay worker needs to drive outbound delivery: where to look
/// up MX (`resolver`), the durable queue (`spool`), the EHLO name to announce
/// (`helo`), and the port to connect to on each exchange (`port`).
pub struct RelayContext {
    /// DNS resolver for MX lookups.
    pub resolver: Arc<dyn DnsResolver>,
    /// Durable outbound queue.
    pub spool: Arc<OutboundSpool>,
    /// The domain announced in the client EHLO.
    pub helo: String,
    /// The port to connect to on each mail exchange (`25` in production).
    pub port: u16,
}

/// The concrete credential store the server authenticates against.
pub type ServerAuth = Authenticator<MemoryCredentialStore>;
/// The shared, cloneable mail store.
pub type SharedStore = Arc<MemoryMailStore>;
/// The concrete MTA: routes inbound mail, delivering local mail through the spam filter.
pub type ServerMta = Mta<SharedStore, SpamFilter>;

/// The composed server. Built once, then its [`authenticator`](Server::authenticator)
/// and [`store`](Server::store) are handed to the access protocol servers while
/// its [`mta`](Server::mta) accepts inbound mail.
pub struct Server {
    auth: ServerAuth,
    store: SharedStore,
    mta: ServerMta,
    tls: Option<Arc<rustls::ServerConfig>>,
    helo: String,
    relay: Option<RelayContext>,
}

impl Server {
    /// Compose a server from configuration: shared in-memory store, MTA with the
    /// spam filter wired into delivery, and an (empty) authenticator.
    #[must_use]
    pub fn new(config: &ServerConfig) -> Self {
        let store: SharedStore = Arc::new(MemoryMailStore::new());
        let mda = MailDeliveryAgent::new(Arc::clone(&store), SpamFilter::new());
        let mta = Mta::new(mda, config.local_domains.clone());
        let auth = Authenticator::new(MemoryCredentialStore::new());
        let helo = config
            .local_domains
            .first()
            .cloned()
            .unwrap_or_else(|| "localhost".to_string());
        Self {
            auth,
            store,
            mta,
            tls: None,
            helo,
            relay: None,
        }
    }

    /// Enable outbound relay: queue remote mail to `spool` and deliver it by
    /// resolving MX via `resolver`. Without this, the server delivers locally
    /// only. The relay port defaults to [`DEFAULT_RELAY_PORT`]; override it with
    /// [`Server::with_relay_port`] (tests point it at a loopback receiver).
    #[must_use]
    pub fn with_relay(mut self, resolver: Arc<dyn DnsResolver>, spool: Arc<OutboundSpool>) -> Self {
        self.relay = Some(RelayContext {
            resolver,
            spool,
            helo: self.helo.clone(),
            port: DEFAULT_RELAY_PORT,
        });
        self
    }

    /// Override the relay connection port (no-op if relay is not enabled).
    #[must_use]
    pub fn with_relay_port(mut self, port: u16) -> Self {
        if let Some(relay) = self.relay.as_mut() {
            relay.port = port;
        }
        self
    }

    /// The relay context, if outbound relay is enabled.
    #[must_use]
    pub fn relay_context(&self) -> Option<&RelayContext> {
        self.relay.as_ref()
    }

    /// Enable STARTTLS on the inbound receiver, building the rustls server config
    /// from the given PEM certificate material.
    ///
    /// # Errors
    /// Propagates a TLS-config build error (malformed PEM / missing key).
    pub fn with_tls(mut self, certs: &MailCerts) -> anyhow::Result<Self> {
        self.tls = Some(network::TlsConfig::server_from_pem(
            &certs.cert_pem,
            &certs.key_pem,
        )?);
        Ok(self)
    }

    /// The STARTTLS server config, if TLS is enabled.
    #[must_use]
    pub fn tls_config(&self) -> Option<Arc<rustls::ServerConfig>> {
        self.tls.clone()
    }

    /// Register a user: store their hashed password and create their account so
    /// they can authenticate (for IMAP/POP/submission) and receive mail.
    ///
    /// # Errors
    /// Propagates a hashing/storage error.
    pub fn register_user(&mut self, username: &str, password: &str) -> anyhow::Result<()> {
        let credential = Credential::new(username, password, self.auth.store().hasher())?;
        self.auth.store().put(credential)?;
        self.auth.add_account(Account::user(username));
        tracing::info!(user = username, "registered account");
        Ok(())
    }

    /// The authenticator (shared with the access protocol servers).
    #[must_use]
    pub fn authenticator(&self) -> &ServerAuth {
        &self.auth
    }

    /// The shared mail store (shared with the access protocol servers).
    #[must_use]
    pub fn store(&self) -> &SharedStore {
        &self.store
    }

    /// Accept an inbound message: deliver to local recipients (scanned by the
    /// spam filter), returning any recipients that must be relayed onward.
    pub fn accept_inbound(&self, message: Message) -> InboundResult {
        self.mta.accept_inbound(message)
    }

    /// Whether `mailbox` is hosted locally.
    #[must_use]
    pub fn is_local(&self, mailbox: &Mailbox) -> bool {
        matches!(self.mta.route(mailbox), mail::Route::Local)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use access::{Pop3Session, PopCommand, PopState};
    use mail::{DeliveryOutcome, Envelope};

    fn inbound(from: &str, to: &str, subject: &str, body: &str) -> Message {
        Message::parse(
            Envelope::new(
                Some(Mailbox::parse(from).unwrap()),
                vec![Mailbox::parse(to).unwrap()],
            ),
            format!("Subject: {subject}\r\n\r\n{body}").as_bytes(),
        )
        .unwrap()
    }

    #[test]
    fn end_to_end_submit_deliver_retrieve() {
        let mut server = Server::new(&ServerConfig::new(["example.com".to_string()]));
        server.register_user("bob@example.com", "s3cret").unwrap();

        // A remote sender delivers to local bob@example.com.
        let result = server.accept_inbound(inbound(
            "alice@remote.net",
            "bob@example.com",
            "Hi Bob",
            "hello from alice",
        ));
        assert!(matches!(
            result.local,
            Some(DeliveryOutcome::Delivered { recipients: 1, .. })
        ));
        assert!(result.relay.is_empty());

        // Bob retrieves it over POP3 against the same composed server.
        let mut pop = Pop3Session::new(server.authenticator(), server.store());
        pop.handle(PopCommand::User("bob@example.com".into()));
        assert!(pop.handle(PopCommand::Pass("s3cret".into())).ok);
        assert_eq!(pop.state(), PopState::Transaction);
        let retr = pop.handle(PopCommand::Retr(1));
        assert!(retr.ok);
        assert!(retr.lines.iter().any(|l| l.contains("Hi Bob")));
    }

    #[test]
    fn remote_recipient_is_routed_to_relay_not_stored() {
        let server = Server::new(&ServerConfig::new(["example.com".to_string()]));
        let result = server.accept_inbound(inbound(
            "alice@example.com",
            "carol@elsewhere.org",
            "hi",
            "x",
        ));
        assert!(result.local.is_none());
        assert_eq!(result.relay.len(), 1);
        assert_eq!(result.relay[0].to_string(), "carol@elsewhere.org");
    }

    #[test]
    fn wrong_password_cannot_retrieve() {
        let mut server = Server::new(&ServerConfig::new(["example.com".to_string()]));
        server.register_user("bob@example.com", "s3cret").unwrap();
        let mut pop = Pop3Session::new(server.authenticator(), server.store());
        pop.handle(PopCommand::User("bob@example.com".into()));
        assert!(!pop.handle(PopCommand::Pass("wrong".into())).ok);
    }
}
