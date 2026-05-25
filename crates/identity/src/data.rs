//! Identity and account model.
//!
//! Note: if a shared `crates/core` types crate is later extracted (m12's open
//! decision), `Identity`/`Account`/`Role` likely move there.

use std::collections::BTreeSet;

/// A coarse authorization role.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Role {
    /// A regular mailbox user.
    User,
    /// An administrator.
    Admin,
}

/// An authenticated principal — the result of a successful authentication.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Identity {
    /// The authenticated username.
    pub username: String,
    /// The roles granted to this identity.
    pub roles: BTreeSet<Role>,
}

/// An account record: who can log in, their roles, and whether login is allowed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Account {
    /// The account username.
    pub username: String,
    /// Roles granted on successful authentication.
    pub roles: BTreeSet<Role>,
    /// Whether the account may authenticate.
    pub enabled: bool,
}

impl Account {
    /// Create an enabled account with the [`Role::User`] role.
    #[must_use]
    pub fn user(username: impl Into<String>) -> Self {
        let mut roles = BTreeSet::new();
        roles.insert(Role::User);
        Self {
            username: username.into(),
            roles,
            enabled: true,
        }
    }

    /// Grant an additional role.
    #[must_use]
    pub fn with_role(mut self, role: Role) -> Self {
        self.roles.insert(role);
        self
    }

    /// Mark the account disabled.
    #[must_use]
    pub fn disabled(mut self) -> Self {
        self.enabled = false;
        self
    }

    /// The [`Identity`] this account becomes once authenticated.
    #[must_use]
    pub fn to_identity(&self) -> Identity {
        Identity {
            username: self.username.clone(),
            roles: self.roles.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn user_account_has_user_role_and_is_enabled() {
        let a = Account::user("alice");
        assert!(a.enabled);
        assert!(a.roles.contains(&Role::User));
    }

    #[test]
    fn with_role_and_disabled_compose() {
        let a = Account::user("root").with_role(Role::Admin).disabled();
        assert!(a.roles.contains(&Role::Admin));
        assert!(!a.enabled);
        assert_eq!(a.to_identity().username, "root");
    }
}
