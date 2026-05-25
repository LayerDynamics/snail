//! Mail-flow metrics and their manager.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use crate::observability::config::MailObservabilityConfig;

/// A point-in-time snapshot of the mail-flow counters.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct MetricsSnapshot {
    /// Messages received (inbound).
    pub received: u64,
    /// Messages delivered to a local mailbox.
    pub delivered: u64,
    /// Messages relayed to a remote server.
    pub relayed: u64,
    /// Messages rejected (by the filter or policy).
    pub rejected: u64,
}

/// Running counts of mail-flow events; emits a `tracing` record per increment
/// (so telemetry/m6 captures it) when `emit_events` is set.
#[derive(Debug)]
pub struct MailMetrics {
    config: MailObservabilityConfig,
    received: AtomicU64,
    delivered: AtomicU64,
    relayed: AtomicU64,
    rejected: AtomicU64,
}

impl MailMetrics {
    /// Create metrics with the given configuration.
    #[must_use]
    pub fn new(config: MailObservabilityConfig) -> Self {
        Self {
            config,
            received: AtomicU64::new(0),
            delivered: AtomicU64::new(0),
            relayed: AtomicU64::new(0),
            rejected: AtomicU64::new(0),
        }
    }

    fn bump(&self, counter: &AtomicU64, event: &'static str) -> u64 {
        let count = counter.fetch_add(1, Ordering::Relaxed) + 1;
        if self.config.emit_events {
            tracing::debug!(
                target: "snail::mail::metrics",
                service = self.config.service.as_str(),
                event,
                count
            );
        }
        count
    }

    /// Record an inbound message.
    pub fn record_received(&self) -> u64 {
        self.bump(&self.received, "received")
    }

    /// Record a local delivery.
    pub fn record_delivered(&self) -> u64 {
        self.bump(&self.delivered, "delivered")
    }

    /// Record a remote relay.
    pub fn record_relayed(&self) -> u64 {
        self.bump(&self.relayed, "relayed")
    }

    /// Record a rejection.
    pub fn record_rejected(&self) -> u64 {
        self.bump(&self.rejected, "rejected")
    }

    /// Snapshot the current counts.
    #[must_use]
    pub fn snapshot(&self) -> MetricsSnapshot {
        MetricsSnapshot {
            received: self.received.load(Ordering::Relaxed),
            delivered: self.delivered.load(Ordering::Relaxed),
            relayed: self.relayed.load(Ordering::Relaxed),
            rejected: self.rejected.load(Ordering::Relaxed),
        }
    }
}

/// Owns the mail metrics and hands out shared [`Arc`] handles so transport and
/// delivery can record to the same counters.
pub struct ObservabilityManager {
    metrics: Arc<MailMetrics>,
}

impl ObservabilityManager {
    /// Build a manager (and its metrics) from configuration.
    #[must_use]
    pub fn new(config: MailObservabilityConfig) -> Self {
        Self {
            metrics: Arc::new(MailMetrics::new(config)),
        }
    }

    /// A shared handle to the metrics.
    #[must_use]
    pub fn metrics(&self) -> Arc<MailMetrics> {
        Arc::clone(&self.metrics)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counters_increment_and_snapshot() {
        let m = MailMetrics::new(MailObservabilityConfig::default());
        m.record_received();
        m.record_received();
        m.record_delivered();
        m.record_rejected();
        let snap = m.snapshot();
        assert_eq!(snap.received, 2);
        assert_eq!(snap.delivered, 1);
        assert_eq!(snap.relayed, 0);
        assert_eq!(snap.rejected, 1);
    }

    #[test]
    fn handle_shares_the_same_metrics() {
        let mgr = ObservabilityManager::new(MailObservabilityConfig::default());
        let handle = mgr.metrics();
        handle.record_relayed();
        assert_eq!(mgr.metrics().snapshot().relayed, 1);
    }
}
