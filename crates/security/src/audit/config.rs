//! Audit-log configuration.

use std::path::PathBuf;

/// Configuration for an [`crate::audit::AuditLog`].
#[derive(Debug, Clone)]
pub struct AuditConfig {
    /// Maximum number of recent events retained in memory for inspection.
    pub capacity: usize,
    /// Optional path to a durable, append-only, hash-chained audit file. When set,
    /// every recorded event is also persisted there (surviving restarts and
    /// resisting tampering); `None` keeps the log RAM-only as before.
    pub sink_path: Option<PathBuf>,
}

impl Default for AuditConfig {
    fn default() -> Self {
        Self {
            capacity: 1024,
            sink_path: None,
        }
    }
}
