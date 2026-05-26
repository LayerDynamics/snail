//! The composed Snail server: wires authentication (`identity` + `security`),
//! the shared mail store, the MTA + delivery agent with the spam `filter`, and
//! exposes the pieces the access servers (`access`) operate over.

use std::collections::BTreeMap;
use std::sync::Arc;

use filter::SpamFilter;
use identity::{Account, Authenticator};
use mail::{
    Envelope, Headers, InboundResult, MailCerts, MailDeliveryAgent, Mailbox, MemoryMailStore,
    Message, Mta,
};
use network::DnsResolver;
use security::{Credential, CredentialStore, Firewall, FirewallConfig, MemoryCredentialStore};

use crate::config::ServerConfig;
use crate::spool::OutboundSpool;

/// The default SMTP relay port (production MX delivery target).
pub const DEFAULT_RELAY_PORT: u16 = 25;

/// Everything the relay worker needs to drive outbound delivery: where to look
/// up MX (`resolver`), the durable queue (`spool`), the EHLO name to announce
/// (`helo`), the port to connect to on each exchange (`port`), and the client
/// TLS config used to opportunistically upgrade each delivery to STARTTLS
/// (`tls`).
pub struct RelayContext {
    /// DNS resolver for MX lookups.
    pub resolver: Arc<dyn DnsResolver>,
    /// Durable outbound queue.
    pub spool: Arc<OutboundSpool>,
    /// The domain announced in the client EHLO.
    pub helo: String,
    /// The port to connect to on each mail exchange (`25` in production).
    pub port: u16,
    /// Opportunistic-STARTTLS client config; `None` disables outbound TLS (the
    /// relay then only encrypts if this can be built — see [`Server::with_relay`]).
    pub tls: Option<Arc<rustls::ClientConfig>>,
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
    firewall: Arc<Firewall>,
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
            firewall: Arc::new(Firewall::new(&FirewallConfig::default())),
        }
    }

    /// Replace the connection firewall (the public inbound port is gated by it).
    /// Defaults to [`FirewallConfig::default`]; tests use a tight quota.
    #[must_use]
    pub fn with_firewall(mut self, config: &FirewallConfig) -> Self {
        self.firewall = Arc::new(Firewall::new(config));
        self
    }

    /// The connection firewall gating inbound (port 25) accepts.
    #[must_use]
    pub fn firewall(&self) -> &Firewall {
        &self.firewall
    }

    /// Enable outbound relay: queue remote mail to `spool` and deliver it by
    /// resolving MX via `resolver`. Without this, the server delivers locally
    /// only. The relay port defaults to [`DEFAULT_RELAY_PORT`]; override it with
    /// [`Server::with_relay_port`] (tests point it at a loopback receiver).
    ///
    /// Outbound deliveries opportunistically upgrade to STARTTLS using a client
    /// TLS config built here. If that config cannot be built (no usable crypto
    /// provider), relay still runs but in cleartext — the build never fails the
    /// server.
    #[must_use]
    pub fn with_relay(mut self, resolver: Arc<dyn DnsResolver>, spool: Arc<OutboundSpool>) -> Self {
        let tls = match network::TlsConfig::opportunistic_client() {
            Ok(config) => Some(config),
            Err(error) => {
                tracing::warn!(%error, "outbound STARTTLS disabled; relaying in cleartext");
                None
            }
        };
        self.relay = Some(RelayContext {
            resolver,
            spool,
            helo: self.helo.clone(),
            port: DEFAULT_RELAY_PORT,
            tls,
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
    /// spam filter) and, when outbound relay is enabled, queue any remote
    /// recipients onto the durable spool (grouped per domain, one entry each)
    /// for the relay worker. Returns the [`InboundResult`] from the MTA.
    pub fn accept_inbound(&self, message: Message) -> InboundResult {
        // Only the relay-enabled path needs the message parts cloned for the
        // spool; a local-only server avoids the copy entirely.
        let Some(relay) = self.relay.as_ref() else {
            return self.mta.accept_inbound(message);
        };
        let sender = message.envelope.sender.clone();
        let headers = message.headers.clone();
        let body = message.body.clone();
        let result = self.mta.accept_inbound(message);
        if !result.relay.is_empty() {
            enqueue_relay(relay, &sender, &headers, &body, &result.relay);
        }
        result
    }

    /// Whether `mailbox` is hosted locally.
    #[must_use]
    pub fn is_local(&self, mailbox: &Mailbox) -> bool {
        matches!(self.mta.route(mailbox), mail::Route::Local)
    }
}

/// Group `recipients` by domain and enqueue one spool entry per domain (each a
/// copy of the message restricted to that domain's recipients) for the relay
/// worker. One entry per domain keeps each queued message single-MX, so retries
/// never re-deliver to an already-accepted domain.
fn enqueue_relay(
    relay: &RelayContext,
    sender: &Option<Mailbox>,
    headers: &Headers,
    body: &[u8],
    recipients: &[Mailbox],
) {
    let mut by_domain: BTreeMap<String, Vec<Mailbox>> = BTreeMap::new();
    for rcpt in recipients {
        by_domain
            .entry(rcpt.domain.to_ascii_lowercase())
            .or_default()
            .push(rcpt.clone());
    }
    for (domain, rcpts) in by_domain {
        let message = Message {
            envelope: Envelope::new(sender.clone(), rcpts),
            headers: headers.clone(),
            body: body.to_vec(),
        };
        match relay.spool.enqueue(&message) {
            Ok(id) => tracing::info!(id = %id, domain = %domain, "queued message for relay"),
            Err(error) => tracing::error!(domain = %domain, %error, "failed to enqueue relay"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use access::{Pop3Session, PopCommand, PopState};
    use mail::DeliveryOutcome;

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
