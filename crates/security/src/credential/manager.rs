//! In-memory [`CredentialStore`] implementation.

use std::collections::HashMap;
use std::sync::RwLock;

use crate::credential::provider::{Credential, CredentialStore};
use crate::encryption::PasswordHasher;
use crate::error::{Result, SecurityError};

/// A thread-safe in-memory credential store. Owns the [`PasswordHasher`] used to
/// verify passwords; a persistent (DB) implementation can replace this behind the
/// same [`CredentialStore`] trait when storage lands (m12).
pub struct MemoryCredentialStore {
    hasher: PasswordHasher,
    creds: RwLock<HashMap<String, Credential>>,
}

impl Default for MemoryCredentialStore {
    fn default() -> Self {
        Self {
            hasher: PasswordHasher::default(),
            creds: RwLock::new(HashMap::new()),
        }
    }
}

impl MemoryCredentialStore {
    /// Create an empty store with the default password hasher.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// The hasher this store uses (e.g. to build [`Credential`]s consistently).
    #[must_use]
    pub fn hasher(&self) -> &PasswordHasher {
        &self.hasher
    }
}

impl CredentialStore for MemoryCredentialStore {
    fn put(&self, credential: Credential) -> Result<()> {
        let mut creds = self
            .creds
            .write()
            .map_err(|_| SecurityError::Credential("credential store lock poisoned".into()))?;
        creds.insert(credential.username.clone(), credential);
        Ok(())
    }

    fn get(&self, username: &str) -> Result<Option<Credential>> {
        let creds = self
            .creds
            .read()
            .map_err(|_| SecurityError::Credential("credential store lock poisoned".into()))?;
        Ok(creds.get(username).cloned())
    }

    fn verify_password(&self, username: &str, password: &str) -> Result<bool> {
        let phc = {
            let creds = self
                .creds
                .read()
                .map_err(|_| SecurityError::Credential("credential store lock poisoned".into()))?;
            match creds.get(username) {
                Some(c) => c.password_phc.clone(),
                None => return Ok(false),
            }
        };
        self.hasher.verify(password, &phc)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stored_credential_verifies_correct_password() {
        let store = MemoryCredentialStore::new();
        let cred = Credential::new("alice", "s3cret-pass", store.hasher()).unwrap();
        store.put(cred).unwrap();
        assert!(store.verify_password("alice", "s3cret-pass").unwrap());
    }

    #[test]
    fn wrong_password_and_unknown_user_return_false() {
        let store = MemoryCredentialStore::new();
        store
            .put(Credential::new("alice", "s3cret-pass", store.hasher()).unwrap())
            .unwrap();
        assert!(!store.verify_password("alice", "wrong").unwrap());
        assert!(!store.verify_password("nobody", "whatever").unwrap());
    }

    #[test]
    fn get_returns_stored_credential() {
        let store = MemoryCredentialStore::new();
        store
            .put(Credential::new("bob", "pw", store.hasher()).unwrap())
            .unwrap();
        assert_eq!(store.get("bob").unwrap().unwrap().username, "bob");
        assert!(store.get("ghost").unwrap().is_none());
    }
}
