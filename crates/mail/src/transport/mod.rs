//! Mail transport: the SMTP protocol, inbound reception, outbound relay, and the
//! MTA that routes between local delivery and remote relay.

pub mod smtp;

pub use smtp::{Phase, SmtpCommand, SmtpReply, SmtpSession};
