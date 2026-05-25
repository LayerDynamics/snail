//! Mailbox storage and local delivery.

pub mod mda;
pub mod store;

pub use mda::{DeliveryOutcome, MailDeliveryAgent};
pub use store::{MailStore, MemoryMailStore, StoredMessage};
