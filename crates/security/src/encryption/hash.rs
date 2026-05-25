//! Argon2id password hashing.

use argon2::password_hash::{PasswordHash, PasswordHasher as _, PasswordVerifier};

use crate::encryption::algos::PasswordAlgo;
use crate::encryption::salt;
use crate::error::{Result, SecurityError};

/// Hashes and verifies passwords with the configured algorithm (Argon2id).
pub struct PasswordHasher {
    algo: PasswordAlgo,
}

impl Default for PasswordHasher {
    fn default() -> Self {
        Self {
            algo: PasswordAlgo::Argon2id,
        }
    }
}

impl PasswordHasher {
    /// Hash `password`, returning a self-describing PHC string (salt + params embedded).
    ///
    /// # Errors
    /// [`SecurityError::Hash`] if hashing fails.
    pub fn hash(&self, password: &str) -> Result<String> {
        let salt = salt::generate();
        let hash = self
            .algo
            .hasher()
            .hash_password(password.as_bytes(), &salt)
            .map_err(|e| SecurityError::Hash(e.to_string()))?;
        Ok(hash.to_string())
    }

    /// Verify `password` against a PHC string. Returns `Ok(false)` on mismatch,
    /// `Err` only if the PHC string is malformed.
    ///
    /// # Errors
    /// [`SecurityError::Hash`] if `phc` cannot be parsed.
    pub fn verify(&self, password: &str, phc: &str) -> Result<bool> {
        let parsed = PasswordHash::new(phc).map_err(|e| SecurityError::Hash(e.to_string()))?;
        match self
            .algo
            .hasher()
            .verify_password(password.as_bytes(), &parsed)
        {
            Ok(()) => Ok(true),
            Err(argon2::password_hash::Error::Password) => Ok(false),
            Err(e) => Err(SecurityError::Hash(e.to_string())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_then_verify_roundtrips() {
        let h = PasswordHasher::default();
        let phc = h.hash("correct horse battery staple").unwrap();
        assert!(h.verify("correct horse battery staple", &phc).unwrap());
    }

    #[test]
    fn wrong_password_fails_verification() {
        let h = PasswordHasher::default();
        let phc = h.hash("correct horse battery staple").unwrap();
        assert!(!h.verify("Tr0ub4dor&3", &phc).unwrap());
    }

    #[test]
    fn same_password_hashes_differ_by_salt() {
        let h = PasswordHasher::default();
        assert_ne!(h.hash("pw").unwrap(), h.hash("pw").unwrap());
    }

    #[test]
    fn malformed_phc_errors() {
        let h = PasswordHasher::default();
        assert!(h.verify("pw", "not-a-phc-string").is_err());
    }
}
