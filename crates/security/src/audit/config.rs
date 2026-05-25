//! Audit-log configuration.

/// Configuration for an [`crate::audit::AuditLog`].
#[derive(Debug, Clone)]
pub struct AuditConfig {
    /// Maximum number of recent events retained in memory for inspection.
    pub capacity: usize,
}

impl Default for AuditConfig {
    fn default() -> Self {
        Self { capacity: 1024 }
    }
}
