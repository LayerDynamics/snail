//! The Mail Transfer Agent: routes each recipient of an inbound message to
//! local delivery (via the MDA) or remote relay, by the set of hosted domains.

use std::collections::HashSet;

use crate::snailmail::{Envelope, Mailbox, Message, MessageFilter};
use crate::storage::{DeliveryOutcome, MailDeliveryAgent, MailStore};

/// How a single recipient is handled.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Route {
    /// The recipient's domain is hosted here — deliver locally.
    Local,
    /// The recipient is elsewhere — relay onward.
    Relay,
}

/// The result of accepting an inbound message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InboundResult {
    /// Local delivery outcome, if any recipients were local.
    pub local: Option<DeliveryOutcome>,
    /// Recipients that must be relayed to remote servers.
    pub relay: Vec<Mailbox>,
}

/// Routes inbound mail between local delivery and remote relay.
pub struct Mta<S: MailStore, F: MessageFilter> {
    local_domains: HashSet<String>,
    mda: MailDeliveryAgent<S, F>,
}

impl<S: MailStore, F: MessageFilter> Mta<S, F> {
    /// Build an MTA over an MDA and the set of locally-hosted domains.
    pub fn new(
        mda: MailDeliveryAgent<S, F>,
        local_domains: impl IntoIterator<Item = String>,
    ) -> Self {
        Self {
            local_domains: local_domains
                .into_iter()
                .map(|d| d.to_ascii_lowercase())
                .collect(),
            mda,
        }
    }

    /// Classify a recipient as local or relay.
    #[must_use]
    pub fn route(&self, mailbox: &Mailbox) -> Route {
        if self
            .local_domains
            .contains(&mailbox.domain.to_ascii_lowercase())
        {
            Route::Local
        } else {
            Route::Relay
        }
    }

    /// The underlying delivery agent (e.g. to read delivered mail).
    pub fn mda(&self) -> &MailDeliveryAgent<S, F> {
        &self.mda
    }

    /// Accept an inbound `message`: deliver to its local recipients via the MDA,
    /// and return the recipients that still need relaying.
    pub fn accept_inbound(&self, message: Message) -> InboundResult {
        let (local, relay): (Vec<Mailbox>, Vec<Mailbox>) = message
            .envelope
            .recipients
            .iter()
            .cloned()
            .partition(|r| self.route(r) == Route::Local);

        let local_outcome = if local.is_empty() {
            None
        } else {
            // Clone the message verbatim (preserving its exact wire bytes) and
            // narrow the envelope to just the local recipients.
            let mut local_message = message.clone();
            local_message.envelope = Envelope::new(message.envelope.sender.clone(), local);
            Some(self.mda.deliver(local_message))
        };

        InboundResult {
            local: local_outcome,
            relay,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::snailmail::NullFilter;
    use crate::storage::MemoryMailStore;

    fn mta() -> Mta<MemoryMailStore, NullFilter> {
        let mda = MailDeliveryAgent::new(MemoryMailStore::new(), NullFilter);
        Mta::new(mda, ["example.com".to_string()])
    }

    fn message(recipients: &[&str]) -> Message {
        let rcpts = recipients
            .iter()
            .map(|r| Mailbox::parse(r).unwrap())
            .collect();
        Message::parse(Envelope::new(None, rcpts), b"Subject: x\r\n\r\nbody").unwrap()
    }

    #[test]
    fn routes_by_local_domain() {
        let mta = mta();
        assert_eq!(
            mta.route(&Mailbox::parse("bob@EXAMPLE.com").unwrap()),
            Route::Local
        );
        assert_eq!(
            mta.route(&Mailbox::parse("eve@other.net").unwrap()),
            Route::Relay
        );
    }

    #[test]
    fn delivers_local_and_returns_remote_for_relay() {
        let mta = mta();
        let result = mta.accept_inbound(message(&["bob@example.com", "eve@other.net"]));
        assert_eq!(
            result.local,
            Some(DeliveryOutcome::Delivered {
                recipients: 1,
                flagged: false
            })
        );
        assert_eq!(result.relay.len(), 1);
        assert_eq!(result.relay[0].to_string(), "eve@other.net");
        // Only the local recipient was stored.
        assert_eq!(mta.mda().store().count("bob@example.com"), 1);
        assert_eq!(mta.mda().store().count("eve@other.net"), 0);
    }

    #[test]
    fn all_remote_does_no_local_delivery() {
        let mta = mta();
        let result = mta.accept_inbound(message(&["eve@other.net"]));
        assert_eq!(result.local, None);
        assert_eq!(result.relay.len(), 1);
    }
}
