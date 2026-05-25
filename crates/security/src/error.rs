//! Error type for the security layer.

use thiserror::Error;

/// Errors produced by cryptography and connection policy.
#[derive(Debug, Error)]
pub enum SecurityError {
    /// Password hashing or verification failed.
    #[error("password hashing error: {0}")]
    Hash(String),
    /// Secret encryption failed.
    #[error("encryption error: {0}")]
    Encrypt(String),
    /// Secret decryption or authentication failed.
    #[error("decryption error: {0}")]
    Decrypt(String),
    /// A credential-store operation failed.
    #[error("credential error: {0}")]
    Credential(String),
    /// A firewall / connection-policy operation failed.
    #[error("firewall error: {0}")]
    Firewall(String),
}

/// Convenience alias for results that fail with [`SecurityError`].
pub type Result<T> = std::result::Result<T, SecurityError>;
