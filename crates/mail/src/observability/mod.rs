//! Mail-flow observability: counters emitted via `tracing`, behind a manager.

pub mod config;
pub mod manager;

pub use config::MailObservabilityConfig;
pub use manager::{MailMetrics, MetricsSnapshot, ObservabilityManager};
