//! The Snail mail engine.
//!
//! Currently exposes the core message model ([`snailmail`]) and the
//! [`snailmail::MessageFilter`] contract. Transport (MTA/SMTP), storage
//! (MDA/store), message security, and observability are populated by the rest
//! of milestone m12.

pub mod error;
pub mod observability;
pub mod security;
pub mod snailmail;
pub mod storage;
pub mod transport;

pub use error::{MailError, Result};
pub use observability::{
    MailMetrics, MailObservabilityConfig, MetricsSnapshot, ObservabilityManager,
};
pub use security::{ContentScanner, MailCerts, TlsPolicy};
pub use snailmail::{
    Envelope, FilterVerdict, Headers, Mailbox, Message, MessageFilter, NullFilter,
};
pub use storage::{DeliveryOutcome, MailDeliveryAgent, MailStore, MemoryMailStore, StoredMessage};
pub use transport::{
    InboundCollector, InboundResult, Mta, RelayScript, Route, SmtpCommand, SmtpReply, SmtpSession,
};
