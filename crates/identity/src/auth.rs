//! The password [`Authenticator`]: verifies credentials against a security
//! [`CredentialStore`] and an account directory, yielding an [`Identity`].

use std::collections::HashMap;

use security::CredentialStore;

use crate::check::check_account;
use crate::data::{Account, Identity};
use crate::error::{IdentityError, Result};

/// Authenticates username/password pairs. Composes m10's [`CredentialStore`]
/// (which holds the Argon2 password hashes) with an account directory that
/// carries roles and the enabled flag.
pub struct Authenticator<S: CredentialStore> {
    store: S,
    accounts: HashMap<String, Account>,
}

impl<S: CredentialStore> Authenticator<S> {
    /// Build an authenticator over a credential store, with no accounts yet.
    pub fn new(store: S) -> Self {
        Self {
            store,
            accounts: HashMap::new(),
        }
    }

    /// Register account metadata (roles, enabled). The password itself lives in
    /// the credential store.
    pub fn add_account(&mut self, account: Account) {
        self.accounts.insert(account.username.clone(), account);
    }

    /// The backing credential store (e.g. to register passwords).
    pub fn store(&self) -> &S {
        &self.store
    }

    /// Authenticate `username` + `password`, returning the resulting [`Identity`].
    ///
    /// All failure modes (unknown account, disabled account, wrong password)
    /// collapse to [`IdentityError::AuthFailed`] so callers cannot enumerate
    /// accounts.
    ///
    /// # Errors
    /// [`IdentityError::AuthFailed`] on any authentication failure;
    /// [`IdentityError::Backend`] if the credential store itself errors.
    pub fn authenticate(&self, username: &str, password: &str) -> Result<Identity> {
        let account = self
            .accounts
            .get(username)
            .ok_or(IdentityError::AuthFailed)?;
        check_account(account).map_err(|_| IdentityError::AuthFailed)?;
        let verified = self
            .store
            .verify_password(username, password)
            .map_err(|e| IdentityError::Backend(e.to_string()))?;
        if verified {
            Ok(account.to_identity())
        } else {
            Err(IdentityError::AuthFailed)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::data::Role;
    use security::{Credential, MemoryCredentialStore};

    fn authenticator_with(user: &str, pw: &str) -> Authenticator<MemoryCredentialStore> {
        let store = MemoryCredentialStore::new();
        store
            .put(Credential::new(user, pw, store.hasher()).unwrap())
            .unwrap();
        let mut auth = Authenticator::new(store);
        auth.add_account(Account::user(user));
        auth
    }

    #[test]
    fn correct_credentials_yield_identity() {
        let auth = authenticator_with("alice", "pw");
        let id = auth.authenticate("alice", "pw").unwrap();
        assert_eq!(id.username, "alice");
        assert!(id.roles.contains(&Role::User));
    }

    #[test]
    fn wrong_password_fails() {
        let auth = authenticator_with("alice", "pw");
        assert!(matches!(
            auth.authenticate("alice", "nope").unwrap_err(),
            IdentityError::AuthFailed
        ));
    }

    #[test]
    fn unknown_account_fails_generically() {
        let auth = authenticator_with("alice", "pw");
        assert!(matches!(
            auth.authenticate("mallory", "pw").unwrap_err(),
            IdentityError::AuthFailed
        ));
    }

    #[test]
    fn disabled_account_fails_even_with_correct_password() {
        let store = MemoryCredentialStore::new();
        store
            .put(Credential::new("bob", "pw", store.hasher()).unwrap())
            .unwrap();
        let mut auth = Authenticator::new(store);
        auth.add_account(Account::user("bob").disabled());
        assert!(matches!(
            auth.authenticate("bob", "pw").unwrap_err(),
            IdentityError::AuthFailed
        ));
    }
}
