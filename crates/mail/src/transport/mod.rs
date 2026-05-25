//! Mail transport: the SMTP protocol, inbound reception, outbound relay, and the
//! MTA that routes between local delivery and remote relay.

pub mod inbound;
pub mod mta;
pub mod outbound;
pub mod smtp;

pub use inbound::InboundCollector;
pub use mta::{InboundResult, Mta, Route};
pub use outbound::{RelayScript, relay_script};
pub use smtp::{Phase, SmtpCommand, SmtpReply, SmtpSession};
