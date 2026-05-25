//! `AuditManager`: owns the process audit log and hands out shared handles so
//! several subsystems (firewall, identity, …) can record to the same log.

use std::sync::Arc;

use crate::audit::audit_logger::AuditLog;
use crate::audit::config::AuditConfig;

/// Owns the audit log and provides shared [`Arc`] handles to it.
pub struct AuditManager {
    log: Arc<AuditLog>,
}

impl AuditManager {
    /// Build a manager (and its audit log) from `config`.
    #[must_use]
    pub fn new(config: &AuditConfig) -> Self {
        Self {
            log: Arc::new(AuditLog::new(config)),
        }
    }

    /// A shared handle to the audit log, cloneable across subsystems.
    #[must_use]
    pub fn handle(&self) -> Arc<AuditLog> {
        Arc::clone(&self.log)
    }

    /// Borrow the audit log directly.
    #[must_use]
    pub fn log(&self) -> &AuditLog {
        &self.log
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::audit_logger::AuditEvent;

    #[test]
    fn handle_shares_the_same_log() {
        let mgr = AuditManager::new(&AuditConfig::default());
        let handle = mgr.handle();
        handle.record(AuditEvent::AuthSuccess {
            user: "alice".into(),
        });
        // The event recorded via the shared handle is visible through the manager's log.
        assert_eq!(mgr.log().len(), 1);
    }
}
