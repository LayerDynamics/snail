//! Error type for the identity layer.

use thiserror::Error;

/// Errors produced by authentication and identity handling.
#[derive(Debug, Error)]
pub enum IdentityError {
    /// Authentication failed. Deliberately generic — never leaks whether the
    /// account exists, is disabled, or the password was wrong (anti-enumeration).
    #[error("authentication failed")]
    AuthFailed,
    /// An account exists but is disabled (internal; surfaced to clients as `AuthFailed`).
    #[error("account disabled: {0}")]
    AccountDisabled(String),
    /// A SASL exchange could not be decoded.
    #[error("malformed SASL exchange: {0}")]
    Sasl(String),
    /// An XOAUTH2 token could not be parsed.
    #[error("malformed XOAUTH2 token: {0}")]
    OAuth(String),
    /// The security backend (credential store) returned an error.
    #[error("security backend error: {0}")]
    Backend(String),
}

/// Convenience alias for results that fail with [`IdentityError`].
pub type Result<T> = std::result::Result<T, IdentityError>;
