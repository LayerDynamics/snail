//! Mailbox storage: the [`MailStore`] trait + an in-memory implementation.
//!
//! `MemoryMailStore` is real storage (just not durable); a persistent
//! Maildir/DB store can replace it behind the trait without touching callers.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, PoisonError};

use crate::snailmail::Message;

/// A delivered message with the id its mailbox assigned it.
#[derive(Debug, Clone)]
pub struct StoredMessage {
    /// Per-store unique id.
    pub id: u64,
    /// The stored message.
    pub message: Message,
}

/// Persistence for delivered mail, keyed by recipient mailbox address.
pub trait MailStore: Send + Sync {
    /// Append `message` to `mailbox`, returning its assigned id.
    fn deliver(&self, mailbox: &str, message: Message) -> u64;
    /// All messages currently in `mailbox`, oldest first.
    fn list(&self, mailbox: &str) -> Vec<StoredMessage>;
    /// Number of messages in `mailbox`.
    fn count(&self, mailbox: &str) -> usize;
    /// Remove the message with `id` from `mailbox`; returns whether it existed.
    fn remove(&self, mailbox: &str, id: u64) -> bool;
}

/// `Arc<Store>` is itself a [`MailStore`], so a single store can be shared
/// (by clone) between the delivery agent and the access servers.
impl<T: MailStore + ?Sized> MailStore for Arc<T> {
    fn deliver(&self, mailbox: &str, message: Message) -> u64 {
        (**self).deliver(mailbox, message)
    }
    fn list(&self, mailbox: &str) -> Vec<StoredMessage> {
        (**self).list(mailbox)
    }
    fn count(&self, mailbox: &str) -> usize {
        (**self).count(mailbox)
    }
    fn remove(&self, mailbox: &str, id: u64) -> bool {
        (**self).remove(mailbox, id)
    }
}

#[derive(Debug, Default)]
struct Inner {
    next_id: u64,
    mailboxes: HashMap<String, Vec<StoredMessage>>,
}

/// An in-memory [`MailStore`].
#[derive(Debug, Default)]
pub struct MemoryMailStore {
    inner: Mutex<Inner>,
}

impl MemoryMailStore {
    /// Create an empty store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

impl MailStore for MemoryMailStore {
    fn deliver(&self, mailbox: &str, message: Message) -> u64 {
        let mut inner = self.inner.lock().unwrap_or_else(PoisonError::into_inner);
        inner.next_id += 1;
        let id = inner.next_id;
        inner
            .mailboxes
            .entry(mailbox.to_string())
            .or_default()
            .push(StoredMessage { id, message });
        id
    }

    fn list(&self, mailbox: &str) -> Vec<StoredMessage> {
        self.inner
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .mailboxes
            .get(mailbox)
            .cloned()
            .unwrap_or_default()
    }

    fn count(&self, mailbox: &str) -> usize {
        self.inner
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .mailboxes
            .get(mailbox)
            .map_or(0, Vec::len)
    }

    fn remove(&self, mailbox: &str, id: u64) -> bool {
        let mut inner = self.inner.lock().unwrap_or_else(PoisonError::into_inner);
        let Some(messages) = inner.mailboxes.get_mut(mailbox) else {
            return false;
        };
        let before = messages.len();
        messages.retain(|m| m.id != id);
        messages.len() != before
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::snailmail::Envelope;

    fn message() -> Message {
        Message::parse(Envelope::new(None, vec![]), b"Subject: x\r\n\r\nbody").unwrap()
    }

    #[test]
    fn deliver_then_list_and_count() {
        let store = MemoryMailStore::new();
        let id = store.deliver("bob@example.org", message());
        assert_eq!(store.count("bob@example.org"), 1);
        let listed = store.list("bob@example.org");
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].id, id);
    }

    #[test]
    fn ids_are_unique_and_remove_works() {
        let store = MemoryMailStore::new();
        let a = store.deliver("bob@example.org", message());
        let b = store.deliver("bob@example.org", message());
        assert_ne!(a, b);
        assert!(store.remove("bob@example.org", a));
        assert!(!store.remove("bob@example.org", a)); // already gone
        assert_eq!(store.count("bob@example.org"), 1);
    }

    #[test]
    fn unknown_mailbox_is_empty() {
        let store = MemoryMailStore::new();
        assert_eq!(store.count("ghost@example.org"), 0);
        assert!(store.list("ghost@example.org").is_empty());
    }
}
