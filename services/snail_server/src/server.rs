//! The composed Snail server: wires authentication (`identity` + `security`),
//! the shared mail store, the MTA + delivery agent with the spam `filter`, and
//! exposes the pieces the access servers (`access`) operate over.

use std::collections::BTreeMap;
use std::sync::Arc;

use filter::SpamFilter;
use identity::{Account, Authenticator};
use mail::{
    DEFAULT_MAX_MESSAGE_SIZE, Envelope, InboundResult, MailCerts, MailDeliveryAgent, Mailbox,
    MemoryMailStore, Message, Mta,
};
use network::DnsResolver;
use security::{
    AuthThrottle, Credential, CredentialStore, Firewall, FirewallConfig, MemoryCredentialStore,
    ThrottleConfig,
};

use crate::config::ServerConfig;
use crate::spool::OutboundSpool;

/// The default SMTP relay port (production MX delivery target).
pub const DEFAULT_RELAY_PORT: u16 = 25;

/// Whether a connection is authorized to relay mail to non-local recipients.
///
/// This is the enqueue-path half of the open-relay defense (the other half is the
/// RCPT-time `is_local` check on the inbound listener). Passed explicitly to
/// [`Server::accept_inbound`] so the relay decision is never implicit: only the
/// authenticated submission path is [`Permitted`](RelayAuthorization::Permitted);
/// the no-auth inbound (port 25) path is [`Forbidden`](RelayAuthorization::Forbidden).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelayAuthorization {
    /// Authenticated submission — remote recipients may be spooled for relay.
    Permitted,
    /// Unauthenticated inbound — local delivery only, never relay.
    Forbidden,
}

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
    auth_throttle: Arc<AuthThrottle>,
    collector_max_size: usize,
    /// Resolver for inbound message authentication (SPF). Independent of outbound
    /// relay, so inbound SPF works even when relay is disabled; populated by
    /// [`Server::with_relay`] or [`Server::with_resolver`].
    resolver: Option<Arc<dyn DnsResolver>>,
    /// When `true`, an SPF `Fail` rejects the message (`550`); otherwise the result
    /// is only stamped in a `Received-SPF` header for DMARC to weigh (the default).
    spf_enforce: bool,
    /// When `true`, a failing DMARC evaluation whose disposition is `reject` is
    /// refused (`550`); otherwise the result is only stamped in
    /// `Authentication-Results` (the default).
    dmarc_enforce: bool,
    /// Accumulates DMARC results for periodic aggregate (`rua`) reporting.
    dmarc_aggregator: Arc<crate::dmarc_report::DmarcAggregator>,
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
            auth_throttle: Arc::new(AuthThrottle::new(ThrottleConfig::default())),
            collector_max_size: DEFAULT_MAX_MESSAGE_SIZE,
            resolver: None,
            spf_enforce: false,
            dmarc_enforce: false,
            dmarc_aggregator: Arc::new(crate::dmarc_report::DmarcAggregator::new()),
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

    /// Replace the per-IP brute-force authentication throttle (consulted by the
    /// IMAP/POP3/submission loops on each credential check). Defaults to
    /// [`ThrottleConfig::default`]; tests use a tight policy.
    #[must_use]
    pub fn with_auth_throttle(mut self, config: ThrottleConfig) -> Self {
        self.auth_throttle = Arc::new(AuthThrottle::new(config));
        self
    }

    /// The brute-force authentication throttle shared across client connections.
    #[must_use]
    pub fn auth_throttle(&self) -> &AuthThrottle {
        &self.auth_throttle
    }

    /// Set the maximum accepted message (`DATA` body) size. Defaults to
    /// [`mail::DEFAULT_MAX_MESSAGE_SIZE`]; a larger body is refused with `552` and
    /// the connection closed, so an unauthenticated peer cannot OOM the process.
    #[must_use]
    pub fn with_max_message_size(mut self, max_size: usize) -> Self {
        self.collector_max_size = max_size;
        self
    }

    /// The maximum accepted message (`DATA` body) size.
    #[must_use]
    pub fn max_message_size(&self) -> usize {
        self.collector_max_size
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
        // The same resolver also backs inbound SPF.
        self.resolver = Some(Arc::clone(&resolver));
        self.relay = Some(RelayContext {
            resolver,
            spool,
            helo: self.helo.clone(),
            port: DEFAULT_RELAY_PORT,
            tls,
        });
        self
    }

    /// Provide a DNS resolver for inbound message authentication (SPF) without
    /// enabling outbound relay. [`Server::with_relay`] already sets one; this is
    /// for SPF-only deployments and tests.
    #[must_use]
    pub fn with_resolver(mut self, resolver: Arc<dyn DnsResolver>) -> Self {
        self.resolver = Some(resolver);
        self
    }

    /// The resolver used for inbound authentication (SPF), if configured.
    #[must_use]
    pub fn resolver(&self) -> Option<Arc<dyn DnsResolver>> {
        self.resolver.clone()
    }

    /// Enable hard SPF enforcement: a `Fail` result rejects the message. Default
    /// is stamp-only (`Received-SPF` header, no rejection).
    #[must_use]
    pub fn with_spf_enforcement(mut self, enforce: bool) -> Self {
        self.spf_enforce = enforce;
        self
    }

    /// Whether an SPF `Fail` should reject the message (vs. stamp-only).
    #[must_use]
    pub fn spf_enforce(&self) -> bool {
        self.spf_enforce
    }

    /// Enable DMARC enforcement: a failing evaluation whose disposition is
    /// `reject` is refused. Default is stamp-only (`Authentication-Results`).
    #[must_use]
    pub fn with_dmarc_enforcement(mut self, enforce: bool) -> Self {
        self.dmarc_enforce = enforce;
        self
    }

    /// Whether a DMARC `reject` disposition should refuse the message.
    #[must_use]
    pub fn dmarc_enforce(&self) -> bool {
        self.dmarc_enforce
    }

    /// The DMARC aggregate-report accumulator (fed per inbound message, drained
    /// by the periodic report worker).
    #[must_use]
    pub fn dmarc_aggregator(&self) -> &Arc<crate::dmarc_report::DmarcAggregator> {
        &self.dmarc_aggregator
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

    /// This server's own host name (the primary local domain), used for the `by`
    /// clause of the `Received:` trace header it stamps on inbound mail.
    #[must_use]
    pub fn host_name(&self) -> &str {
        &self.helo
    }

    /// Accept an inbound message: deliver to local recipients (scanned by the
    /// spam filter) and, when outbound relay is enabled **and** the connection is
    /// authorized to relay, queue any remote recipients onto the durable spool
    /// (grouped per domain, one entry each) for the relay worker. Returns the
    /// [`InboundResult`] from the MTA.
    ///
    /// `authorization` is the second, independent open-relay gate: only the
    /// authenticated submission path passes [`RelayAuthorization::Permitted`]. The
    /// no-auth inbound (port 25) listener passes [`RelayAuthorization::Forbidden`],
    /// so a non-local recipient is **never** spooled there — even if one were to
    /// slip past the RCPT-time `is_local` guard, Snail still cannot become an open
    /// relay. A forbidden remote recipient is dropped (not relayed) and logged.
    pub fn accept_inbound(
        &self,
        message: Message,
        authorization: RelayAuthorization,
    ) -> InboundResult {
        let permitted = authorization == RelayAuthorization::Permitted;
        // Relay only when outbound relay is configured AND this connection is
        // authorized to relay; otherwise deliver locally only.
        let Some(relay) = self.relay.as_ref().filter(|_| permitted) else {
            let result = self.mta.accept_inbound(message);
            if !permitted && !result.relay.is_empty() {
                // A non-local recipient reached the no-relay path. The RCPT-time
                // guard should have refused it; surface that it did not, and do
                // not relay it.
                tracing::warn!(
                    count = result.relay.len(),
                    "non-local recipient on a relay-forbidden connection was not relayed (open-relay guard)"
                );
            }
            return result;
        };
        // Only the relay-enabled path needs the message cloned (verbatim) for the
        // spool, before the MDA consumes it for local delivery.
        let source = message.clone();
        let result = self.mta.accept_inbound(message);
        if !result.relay.is_empty() {
            enqueue_relay(relay, &source, &result.relay);
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
///
/// # Invariant
/// Must only be called for [`RelayAuthorization::Permitted`] connections.
/// [`Server::accept_inbound`] is the sole caller and gates on that; do not call
/// this from any path that has not established relay authorization, or Snail
/// becomes an open relay.
fn enqueue_relay(relay: &RelayContext, source: &Message, recipients: &[Mailbox]) {
    let mut by_domain: BTreeMap<String, Vec<Mailbox>> = BTreeMap::new();
    for rcpt in recipients {
        by_domain
            .entry(rcpt.domain.to_ascii_lowercase())
            .or_default()
            .push(rcpt.clone());
    }
    for (domain, rcpts) in by_domain {
        // Clone the source message verbatim (preserving its exact wire bytes — so
        // DKIM survives relay) and narrow the envelope to this domain's recipients.
        let mut message = source.clone();
        message.envelope = Envelope::new(source.envelope.sender.clone(), rcpts);
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
        let result = server.accept_inbound(
            inbound(
                "alice@remote.net",
                "bob@example.com",
                "Hi Bob",
                "hello from alice",
            ),
            RelayAuthorization::Permitted,
        );
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
        let body = retr.body.expect("RETR returns the raw message bytes");
        assert!(String::from_utf8_lossy(&body).contains("Hi Bob"));
    }

    #[test]
    fn remote_recipient_is_routed_to_relay_not_stored() {
        let server = Server::new(&ServerConfig::new(["example.com".to_string()]));
        let result = server.accept_inbound(
            inbound("alice@example.com", "carol@elsewhere.org", "hi", "x"),
            RelayAuthorization::Permitted,
        );
        assert!(result.local.is_none());
        assert_eq!(result.relay.len(), 1);
        assert_eq!(result.relay[0].to_string(), "carol@elsewhere.org");
    }

    /// A resolver stub: relay enqueueing needs a relay context, but the enqueue
    /// path never calls the resolver (only the worker does).
    struct DummyResolver;

    #[async_trait::async_trait]
    impl network::DnsResolver for DummyResolver {
        async fn lookup_mx(&self, _domain: &str) -> network::Result<Vec<network::MxRecord>> {
            Ok(Vec::new())
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

    #[test]
    fn forbidden_never_spools_remote_recipient_even_when_relay_is_configured() {
        use crate::spool::OutboundSpool;
        use std::sync::Arc;
        use std::time::{Duration, SystemTime};

        let nanos = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("snail-relayauth-{nanos}"));
        let spool = Arc::new(OutboundSpool::open(&dir).unwrap());
        let server = Server::new(&ServerConfig::new(["example.com".to_string()]))
            .with_relay(Arc::new(DummyResolver), Arc::clone(&spool));
        let not_empty =
            |after: Duration| !spool.due_now(SystemTime::now() + after).unwrap().is_empty();

        // Forbidden (no-auth inbound): the MTA still classifies the recipient as
        // remote, but it MUST NOT be spooled — Snail is never an open relay.
        let result = server.accept_inbound(
            inbound("attacker@evil.test", "victim@elsewhere.org", "hi", "x"),
            RelayAuthorization::Forbidden,
        );
        assert_eq!(
            result.relay.len(),
            1,
            "recipient is routed remote by the MTA"
        );
        assert!(
            !not_empty(Duration::from_secs(1)),
            "a relay-forbidden connection must never spool a remote recipient"
        );

        // Permitted (authenticated submission): the same kind of recipient IS spooled.
        server.accept_inbound(
            inbound("alice@example.com", "carol@elsewhere.org", "hi", "x"),
            RelayAuthorization::Permitted,
        );
        assert!(
            not_empty(Duration::from_secs(1)),
            "an authorized submission must spool the remote recipient"
        );

        let _ = std::fs::remove_dir_all(dir);
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
