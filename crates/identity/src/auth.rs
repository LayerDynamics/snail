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
    /// collapse to [`IdentityError::AuthFailed`], and they do so in **constant
    /// wall-clock time**: the password is verified first and unconditionally
    /// (the store performs an Argon2 verify against a decoy hash for unknown
    /// users), so a caller cannot enumerate accounts by either the returned value
    /// or response timing. A disabled account still pays the verify cost rather
    /// than returning early — do not "optimize" that away or the oracle reopens.
    ///
    /// # Errors
    /// [`IdentityError::AuthFailed`] on any authentication failure;
    /// [`IdentityError::Backend`] if the credential store itself errors.
    pub fn authenticate(&self, username: &str, password: &str) -> Result<Identity> {
        // Verify first, on every path. The expensive, constant-cost Argon2 work
        // happens here regardless of whether the account exists or is enabled.
        let verified = self
            .store
            .verify_password(username, password)
            .map_err(|e| IdentityError::Backend(e.to_string()))?;

        // Account existence and the enabled flag are cheap map lookups, evaluated
        // only after the verify so they contribute no observable timing signal.
        let enabled = self
            .accounts
            .get(username)
            .is_some_and(|account| check_account(account).is_ok());

        match self.accounts.get(username).filter(|_| verified && enabled) {
            Some(account) => Ok(account.to_identity()),
            None => Err(IdentityError::AuthFailed),
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

    #[test]
    fn miss_paths_hash_like_a_real_verify_no_timing_oracle() {
        use std::time::{Duration, Instant};

        // alice: known + enabled; bob: known + disabled.
        let store = MemoryCredentialStore::new();
        store
            .put(Credential::new("alice", "pw", store.hasher()).unwrap())
            .unwrap();
        store
            .put(Credential::new("bob", "pw", store.hasher()).unwrap())
            .unwrap();
        let mut auth = Authenticator::new(store);
        auth.add_account(Account::user("alice"));
        auth.add_account(Account::user("bob").disabled());

        let avg = |f: &dyn Fn()| -> Duration {
            const ITERS: u32 = 3;
            let start = Instant::now();
            for _ in 0..ITERS {
                f();
            }
            start.elapsed() / ITERS
        };

        // Baseline: known + enabled account, wrong password — one real verify.
        let real = avg(&|| {
            assert!(auth.authenticate("alice", "wrong").is_err());
        });
        // Unknown account — must still hash (decoy verify in the store).
        let unknown = avg(&|| {
            assert!(auth.authenticate("mallory", "pw").is_err());
        });
        // Disabled account — must still hash rather than returning early.
        let disabled = avg(&|| {
            assert!(auth.authenticate("bob", "pw").is_err());
        });

        assert!(
            unknown >= real / 4,
            "unknown-account auth ({unknown:?}) skips the hash vs a real verify ({real:?})"
        );
        assert!(
            disabled >= real / 4,
            "disabled-account auth ({disabled:?}) skips the hash vs a real verify ({real:?})"
        );
    }
}
