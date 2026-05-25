//! Error type for the mail engine.

use thiserror::Error;

/// Errors produced by the mail engine.
#[derive(Debug, Error)]
pub enum MailError {
    /// An email address could not be parsed.
    #[error("invalid mailbox address: {0}")]
    InvalidAddress(String),
    /// A message could not be parsed into headers + body.
    #[error("malformed message: {0}")]
    Malformed(String),
}

/// Convenience alias for results that fail with [`MailError`].
pub type Result<T> = std::result::Result<T, MailError>;
