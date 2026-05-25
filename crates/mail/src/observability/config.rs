//! Mail observability configuration.

/// Configuration for mail-flow metrics.
#[derive(Debug, Clone)]
pub struct MailObservabilityConfig {
    /// Service label attached to emitted metric events.
    pub service: String,
    /// Whether to emit a `tracing` record on each counter increment (the counters
    /// always update regardless).
    pub emit_events: bool,
}

impl Default for MailObservabilityConfig {
    fn default() -> Self {
        Self {
            service: "snail-mail".to_string(),
            emit_events: true,
        }
    }
}
