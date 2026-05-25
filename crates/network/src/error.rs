//! Error type for the network layer.

use thiserror::Error;

/// Errors produced by DNS resolution and TLS setup.
#[derive(Debug, Error)]
pub enum NetworkError {
    /// A DNS lookup failed.
    #[error("dns lookup failed for `{name}`: {reason}")]
    Resolve {
        /// The queried name.
        name: String,
        /// Underlying cause.
        reason: String,
    },
    /// A DNS record could not be parsed into the expected shape.
    #[error("malformed {kind} record: {reason}")]
    Record {
        /// Record kind (e.g. `DKIM`, `DMARC`).
        kind: String,
        /// What was wrong.
        reason: String,
    },
    /// A TLS configuration error (cert/key load or builder).
    #[error("tls configuration error: {0}")]
    Tls(String),
    /// An I/O error (PEM file read, socket).
    #[error("i/o error: {0}")]
    Io(#[from] std::io::Error),
}

/// Convenience alias for results that fail with [`NetworkError`].
pub type Result<T> = std::result::Result<T, NetworkError>;
