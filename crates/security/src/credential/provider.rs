//! The `CredentialStore` contract and the `Credential` value type.

use crate::encryption::PasswordHasher;
use crate::error::Result;

/// A stored credential: a username, an Argon2 PHC password hash, and an optional
/// `SecretCipher`-encrypted secret blob (e.g. a relay password / OAuth token).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Credential {
    /// The account username (lookup key).
    pub username: String,
    /// Argon2id PHC string (salt + params embedded).
    pub password_phc: String,
    /// Optional encrypted secret (ciphertext from `SecretCipher`).
    pub secret: Option<Vec<u8>>,
}

impl Credential {
    /// Create a credential, hashing `password` with `hasher`.
    ///
    /// # Errors
    /// Propagates [`crate::error::SecurityError::Hash`] if hashing fails.
    pub fn new(
        username: impl Into<String>,
        password: &str,
        hasher: &PasswordHasher,
    ) -> Result<Self> {
        Ok(Self {
            username: username.into(),
            password_phc: hasher.hash(password)?,
            secret: None,
        })
    }

    /// Attach an encrypted secret blob.
    #[must_use]
    pub fn with_secret(mut self, sealed: Vec<u8>) -> Self {
        self.secret = Some(sealed);
        self
    }
}

/// Storage and verification of [`Credential`]s.
pub trait CredentialStore: Send + Sync {
    /// Insert or replace a credential (keyed by username).
    ///
    /// # Errors
    /// [`crate::error::SecurityError::Credential`] on a storage failure.
    fn put(&self, credential: Credential) -> Result<()>;

    /// Fetch a credential by username, if present.
    ///
    /// # Errors
    /// [`crate::error::SecurityError::Credential`] on a storage failure.
    fn get(&self, username: &str) -> Result<Option<Credential>>;

    /// Verify a plaintext `password` against the stored hash for `username`.
    /// Returns `Ok(false)` for an unknown user or a wrong password.
    ///
    /// Implementations **must not** leak account existence through timing: the
    /// unknown-user path must spend the same work as a real verify by hashing
    /// against a decoy (see [`crate::encryption::PasswordHasher::verify_dummy`]).
    /// Returning `Ok(false)` early without hashing reopens an account-enumeration
    /// oracle.
    ///
    /// # Errors
    /// [`crate::error::SecurityError::Hash`] if the stored PHC is malformed.
    fn verify_password(&self, username: &str, password: &str) -> Result<bool>;
}
