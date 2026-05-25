//! Mail Delivery Agent: scans a message through the [`MessageFilter`], then
//! delivers it into the [`MailStore`] for each envelope recipient.

use crate::snailmail::{FilterVerdict, Message, MessageFilter};
use crate::storage::store::MailStore;

/// The result of attempting to deliver a message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeliveryOutcome {
    /// Delivered to `recipients` mailboxes; `flagged` if the filter flagged it.
    Delivered {
        /// Number of recipient mailboxes written to.
        recipients: usize,
        /// Whether the filter flagged the message as suspicious.
        flagged: bool,
    },
    /// The filter rejected the message; nothing was stored.
    Rejected,
}

/// Delivers messages into a [`MailStore`], filtering them first. Generic over the
/// concrete store and filter so the composition root injects real implementations.
pub struct MailDeliveryAgent<S: MailStore, F: MessageFilter> {
    store: S,
    filter: F,
}

impl<S: MailStore, F: MessageFilter> MailDeliveryAgent<S, F> {
    /// Build an MDA over a store and a filter.
    pub fn new(store: S, filter: F) -> Self {
        Self { store, filter }
    }

    /// The backing store (e.g. to read delivered mail).
    pub fn store(&self) -> &S {
        &self.store
    }

    /// Scan and deliver `message` to each envelope recipient's mailbox.
    pub fn deliver(&self, message: Message) -> DeliveryOutcome {
        let flagged = match self.filter.scan(&message) {
            FilterVerdict::Reject => return DeliveryOutcome::Rejected,
            FilterVerdict::Flag => true,
            FilterVerdict::Accept => false,
        };
        let recipients = message.envelope.recipients.clone();
        for rcpt in &recipients {
            self.store.deliver(&rcpt.to_string(), message.clone());
        }
        DeliveryOutcome::Delivered {
            recipients: recipients.len(),
            flagged,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::snailmail::{Envelope, Mailbox, NullFilter};
    use crate::storage::store::MemoryMailStore;

    fn message_to(recipients: &[&str]) -> Message {
        let rcpts = recipients
            .iter()
            .map(|r| Mailbox::parse(r).unwrap())
            .collect();
        Message::parse(Envelope::new(None, rcpts), b"Subject: hi\r\n\r\nbody").unwrap()
    }

    /// A filter with a fixed verdict, for testing the MDA's branching.
    struct FixedFilter(FilterVerdict);
    impl MessageFilter for FixedFilter {
        fn scan(&self, _m: &Message) -> FilterVerdict {
            self.0
        }
    }

    #[test]
    fn delivers_to_each_recipient() {
        let mda = MailDeliveryAgent::new(MemoryMailStore::new(), NullFilter);
        let outcome = mda.deliver(message_to(&["a@x.com", "b@y.com"]));
        assert_eq!(
            outcome,
            DeliveryOutcome::Delivered {
                recipients: 2,
                flagged: false
            }
        );
        assert_eq!(mda.store().count("a@x.com"), 1);
        assert_eq!(mda.store().count("b@y.com"), 1);
    }

    #[test]
    fn rejected_message_is_not_stored() {
        let mda =
            MailDeliveryAgent::new(MemoryMailStore::new(), FixedFilter(FilterVerdict::Reject));
        assert_eq!(
            mda.deliver(message_to(&["a@x.com"])),
            DeliveryOutcome::Rejected
        );
        assert_eq!(mda.store().count("a@x.com"), 0);
    }

    #[test]
    fn flagged_message_is_delivered_and_marked() {
        let mda = MailDeliveryAgent::new(MemoryMailStore::new(), FixedFilter(FilterVerdict::Flag));
        let outcome = mda.deliver(message_to(&["a@x.com"]));
        assert_eq!(
            outcome,
            DeliveryOutcome::Delivered {
                recipients: 1,
                flagged: true
            }
        );
        assert_eq!(mda.store().count("a@x.com"), 1);
    }
}
