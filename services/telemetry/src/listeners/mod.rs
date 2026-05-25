//! In-process listeners that tap the live telemetry stream.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use tracing::{Event, Subscriber};
use tracing_subscriber::layer::{Context, Layer};

/// Counts every `tracing` event observed. Used by `telemetry selftest` to prove
/// the pipeline is live; available to a future collector for health metrics.
#[derive(Clone, Default)]
pub struct EventCounter {
    count: Arc<AtomicU64>,
}

impl EventCounter {
    /// Create a counter starting at zero.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Number of events observed so far.
    #[must_use]
    pub fn count(&self) -> u64 {
        self.count.load(Ordering::Relaxed)
    }
}

impl<S: Subscriber> Layer<S> for EventCounter {
    fn on_event(&self, _event: &Event<'_>, _ctx: Context<'_, S>) {
        self.count.fetch_add(1, Ordering::Relaxed);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tracing_subscriber::layer::SubscriberExt;

    #[test]
    fn event_counter_increments_per_event() {
        // `.with(counter.clone())` only compiles if `EventCounter: Layer<_>`,
        // so this test also proves the trait impl at compile time.
        let counter = EventCounter::new();
        let subscriber = tracing_subscriber::registry().with(counter.clone());
        tracing::subscriber::with_default(subscriber, || {
            tracing::info!("one");
            tracing::warn!("two");
        });
        assert_eq!(counter.count(), 2);
    }
}
