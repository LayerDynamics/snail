//! Per-connection authentication state — what a single client session holds
//! while it authenticates (and after).

use crate::data::Identity;

/// The authentication state of one client connection.
#[derive(Debug, Clone, Default)]
pub enum ConnectionState {
    /// Not yet authenticated.
    #[default]
    Unauthenticated,
    /// Authenticated as the given identity.
    Authenticated(Identity),
}

/// Tracks a connection's authentication state and its failed-attempt count
/// (so a protocol server can drop a connection after too many failures).
#[derive(Debug, Default)]
pub struct ConnectionAuth {
    state: ConnectionState,
    failed_attempts: u32,
}

impl ConnectionAuth {
    /// A fresh, unauthenticated connection.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Whether the connection has authenticated.
    #[must_use]
    pub fn is_authenticated(&self) -> bool {
        matches!(self.state, ConnectionState::Authenticated(_))
    }

    /// The authenticated identity, if any.
    #[must_use]
    pub fn identity(&self) -> Option<&Identity> {
        match &self.state {
            ConnectionState::Authenticated(id) => Some(id),
            ConnectionState::Unauthenticated => None,
        }
    }

    /// Record a successful authentication, transitioning to authenticated.
    pub fn succeed(&mut self, identity: Identity) {
        self.state = ConnectionState::Authenticated(identity);
    }

    /// Record a failed attempt, returning the running failure count.
    pub fn fail(&mut self) -> u32 {
        self.failed_attempts += 1;
        self.failed_attempts
    }

    /// Number of failed attempts on this connection so far.
    #[must_use]
    pub fn failed_attempts(&self) -> u32 {
        self.failed_attempts
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::data::Account;

    #[test]
    fn starts_unauthenticated() {
        let c = ConnectionAuth::new();
        assert!(!c.is_authenticated());
        assert!(c.identity().is_none());
    }

    #[test]
    fn succeed_records_identity() {
        let mut c = ConnectionAuth::new();
        c.succeed(Account::user("alice").to_identity());
        assert!(c.is_authenticated());
        assert_eq!(c.identity().unwrap().username, "alice");
    }

    #[test]
    fn fail_counts_attempts() {
        let mut c = ConnectionAuth::new();
        assert_eq!(c.fail(), 1);
        assert_eq!(c.fail(), 2);
        assert_eq!(c.failed_attempts(), 2);
        assert!(!c.is_authenticated());
    }
}
