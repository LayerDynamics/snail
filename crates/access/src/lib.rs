//! Client-facing access protocols for the Snail mail server: IMAP, POP3, MSA
//! (authenticated submission), web access, and the manager that runs them. Each
//! authenticates via `identity` and reads/writes the `mail` store.

pub mod error;
pub mod pop;

pub use error::{AccessError, Result};
pub use pop::{Pop3Session, PopCommand, PopReply, PopState};

/// Authenticates a username + password for an access session.
///
/// Implemented for [`identity::Authenticator`] so the protocol servers stay
/// decoupled from the concrete credential backend (and testable with a stub).
pub trait SessionAuth {
    /// Whether the username + password authenticate successfully.
    fn check(&self, username: &str, password: &str) -> bool;
}

impl<S: security::CredentialStore> SessionAuth for identity::Authenticator<S> {
    fn check(&self, username: &str, password: &str) -> bool {
        self.authenticate(username, password).is_ok()
    }
}
