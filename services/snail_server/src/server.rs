//! The composed Snail server: wires authentication (`identity` + `security`),
//! the shared mail store, the MTA + delivery agent with the spam `filter`, and
//! exposes the pieces the access servers (`access`) operate over.

use std::sync::Arc;

use filter::SpamFilter;
use identity::{Account, Authenticator};
use mail::{InboundResult, MailDeliveryAgent, Mailbox, MemoryMailStore, Message, Mta};
use security::{Credential, CredentialStore, MemoryCredentialStore};

use crate::config::ServerConfig;

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
        Self { auth, store, mta }
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
