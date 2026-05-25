//! Error type for the access layer.

use thiserror::Error;

/// Errors produced by the client-facing access protocols.
#[derive(Debug, Error)]
pub enum AccessError {
    /// A protocol-level error (malformed command, bad sequence).
    #[error("protocol error: {0}")]
    Protocol(String),
    /// An operation was attempted before authenticating.
    #[error("not authenticated")]
    NotAuthenticated,
}

/// Convenience alias for results that fail with [`AccessError`].
pub type Result<T> = std::result::Result<T, AccessError>;
