//! `AccessManager`: coordinates the access protocol servers, holding the shared
//! authenticator and mail store and which protocols are enabled, and handing out
//! per-connection protocol sessions.

use mail::MailStore;

use crate::SessionAuth;
use crate::imap::ImapSession;
use crate::msa::MsaSession;
use crate::pop::Pop3Session;
use crate::web::WebAccess;

/// Which access protocols are enabled.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AccessConfig {
    /// Serve IMAP.
    pub imap: bool,
    /// Serve POP3.
    pub pop3: bool,
    /// Serve authenticated submission (MSA).
    pub submission: bool,
    /// Serve web access.
    pub web: bool,
}

impl Default for AccessConfig {
    fn default() -> Self {
        Self {
            imap: true,
            pop3: true,
            submission: true,
            web: true,
        }
    }
}

/// Owns the shared authenticator + mail store and gates which protocol servers
/// run. Hands out a fresh session per accepted connection.
pub struct AccessManager<'a, A: SessionAuth, S: MailStore> {
    auth: &'a A,
    store: &'a S,
    config: AccessConfig,
}

impl<'a, A: SessionAuth, S: MailStore> AccessManager<'a, A, S> {
    /// Build a manager over a shared authenticator and store.
    pub fn new(auth: &'a A, store: &'a S, config: AccessConfig) -> Self {
        Self {
            auth,
            store,
            config,
        }
    }

    /// The enabled-protocol configuration.
    #[must_use]
    pub fn config(&self) -> AccessConfig {
        self.config
    }

    /// A new IMAP session, if IMAP is enabled.
    #[must_use]
    pub fn imap_session(&self) -> Option<ImapSession<'a, A, S>> {
        self.config
            .imap
            .then(|| ImapSession::new(self.auth, self.store))
    }

    /// A new POP3 session, if POP3 is enabled.
    #[must_use]
    pub fn pop3_session(&self) -> Option<Pop3Session<'a, A, S>> {
        self.config
            .pop3
            .then(|| Pop3Session::new(self.auth, self.store))
    }

    /// A new submission (MSA) session, if submission is enabled.
    #[must_use]
    pub fn submission_session(&self) -> Option<MsaSession<'a, A>> {
        self.config.submission.then(|| MsaSession::new(self.auth))
    }

    /// A web access handler, if web is enabled.
    #[must_use]
    pub fn web(&self) -> Option<WebAccess<'a, A, S>> {
        self.config
            .web
            .then(|| WebAccess::new(self.auth, self.store))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mail::MemoryMailStore;

    struct StubAuth;
    impl SessionAuth for StubAuth {
        fn check(&self, _u: &str, _p: &str) -> bool {
            false
        }
    }

    #[test]
    fn config_gates_session_creation() {
        let (auth, store) = (StubAuth, MemoryMailStore::new());
        let config = AccessConfig {
            imap: true,
            pop3: false,
            submission: true,
            web: false,
        };
        let mgr = AccessManager::new(&auth, &store, config);
        assert!(mgr.imap_session().is_some());
        assert!(mgr.pop3_session().is_none());
        assert!(mgr.submission_session().is_some());
        assert!(mgr.web().is_none());
    }

    #[test]
    fn default_enables_all() {
        let (auth, store) = (StubAuth, MemoryMailStore::new());
        let mgr = AccessManager::new(&auth, &store, AccessConfig::default());
        assert!(mgr.imap_session().is_some());
        assert!(mgr.pop3_session().is_some());
        assert!(mgr.submission_session().is_some());
        assert!(mgr.web().is_some());
    }
}
