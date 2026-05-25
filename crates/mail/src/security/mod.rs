//! Message security for the mail engine: a content-scanning filter, server TLS
//! certificate material, and the STARTTLS policy.

pub mod certs;
pub mod scanner;
pub mod tls;

pub use certs::MailCerts;
pub use scanner::ContentScanner;
pub use tls::TlsPolicy;
