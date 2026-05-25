//! The Snail mail engine.
//!
//! Currently exposes the core message model ([`snailmail`]) and the
//! [`snailmail::MessageFilter`] contract. Transport (MTA/SMTP), storage
//! (MDA/store), message security, and observability are populated by the rest
//! of milestone m12.

pub mod error;
pub mod snailmail;
pub mod storage;
pub mod transport;

pub use error::{MailError, Result};
pub use snailmail::{
    Envelope, FilterVerdict, Headers, Mailbox, Message, MessageFilter, NullFilter,
};
pub use storage::{DeliveryOutcome, MailDeliveryAgent, MailStore, MemoryMailStore, StoredMessage};
pub use transport::{SmtpCommand, SmtpReply, SmtpSession};
