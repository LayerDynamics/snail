//! `CredentialReceiver`: the intake seam that validates credentials a connecting
//! session *presents* against a [`CredentialStore`]. This is what the identity
//! layer (m11) calls when an SMTP/IMAP/POP client authenticates.

use crate::credential::provider::CredentialStore;
use crate::error::Result;

/// Outcome of authenticating presented credentials.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthOutcome {
    /// The username + password matched a stored credential.
    Authenticated,
    /// No match (unknown user or wrong password).
    Rejected,
}

/// Validates presented credentials against a backing [`CredentialStore`].
pub struct CredentialReceiver<S: CredentialStore> {
    store: S,
}

impl<S: CredentialStore> CredentialReceiver<S> {
    /// Wrap a credential store.
    pub fn new(store: S) -> Self {
        Self { store }
    }

    /// Authenticate a presented `username` + `password`.
    ///
    /// # Errors
    /// Propagates store/hash errors; a wrong password is `Ok(AuthOutcome::Rejected)`, not an error.
    pub fn authenticate(&self, username: &str, password: &str) -> Result<AuthOutcome> {
        if self.store.verify_password(username, password)? {
            Ok(AuthOutcome::Authenticated)
        } else {
            Ok(AuthOutcome::Rejected)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::credential::manager::MemoryCredentialStore;
    use crate::credential::provider::Credential;

    fn store_with(user: &str, pw: &str) -> MemoryCredentialStore {
        let store = MemoryCredentialStore::new();
        store
            .put(Credential::new(user, pw, store.hasher()).unwrap())
            .unwrap();
        store
    }

    #[test]
    fn accepts_valid_credentials() {
        let rx = CredentialReceiver::new(store_with("alice", "pw"));
        assert_eq!(
            rx.authenticate("alice", "pw").unwrap(),
            AuthOutcome::Authenticated
        );
    }

    #[test]
    fn rejects_wrong_password() {
        let rx = CredentialReceiver::new(store_with("alice", "pw"));
        assert_eq!(
            rx.authenticate("alice", "nope").unwrap(),
            AuthOutcome::Rejected
        );
    }
}
