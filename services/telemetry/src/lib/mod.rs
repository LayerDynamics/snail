//! Core initialisation: wire `tracing` + OpenTelemetry into one subscriber.

use opentelemetry::trace::TracerProvider as _;
use opentelemetry_sdk::trace::TracerProvider;
use thiserror::Error;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{EnvFilter, fmt};

use crate::data::TelemetryConfig;
use crate::listeners::EventCounter;
use crate::otel;

/// Errors raised while configuring telemetry.
#[derive(Debug, Error)]
pub enum TelemetryError {
    /// The log-filter directive could not be parsed.
    #[error("invalid log filter `{0}`")]
    Filter(String),
    /// An exporter failed to build.
    #[error("exporter error: {0}")]
    Exporter(String),
    /// `init` was called more than once in this process.
    #[error("telemetry already initialised")]
    AlreadyInitialised,
}

/// Held for the lifetime of the process; flushes and shuts down the exporter on drop.
pub struct TelemetryGuard {
    provider: TracerProvider,
    /// Live event counter, useful for self-tests and health checks.
    pub events: EventCounter,
}

impl Drop for TelemetryGuard {
    fn drop(&mut self) {
        // Best-effort flush during teardown; ignore shutdown errors.
        let _ = self.provider.shutdown();
    }
}

/// Validate a config's log filter, returning a ready [`EnvFilter`].
///
/// # Errors
/// Returns [`TelemetryError::Filter`] if the directive is invalid.
pub(crate) fn build_filter(config: &TelemetryConfig) -> Result<EnvFilter, TelemetryError> {
    EnvFilter::try_new(&config.log_filter)
        .map_err(|_| TelemetryError::Filter(config.log_filter.clone()))
}

/// Initialise global telemetry from `config`. Call once at process start.
///
/// # Errors
/// Returns [`TelemetryError`] if the filter is invalid, an exporter fails, or
/// telemetry was already initialised in this process.
pub fn init(config: &TelemetryConfig) -> Result<TelemetryGuard, TelemetryError> {
    let filter = build_filter(config)?;
    let provider = otel::build_provider(config)?;
    let tracer = provider.tracer("snail");
    let events = EventCounter::new();

    tracing_subscriber::registry()
        .with(filter)
        .with(fmt::layer().json())
        .with(tracing_opentelemetry::layer().with_tracer(tracer))
        .with(events.clone())
        .try_init()
        .map_err(|_| TelemetryError::AlreadyInitialised)?;

    Ok(TelemetryGuard { provider, events })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::data::TelemetryConfig;

    #[test]
    fn rejects_invalid_log_filter() {
        let mut cfg = TelemetryConfig::stdout("t");
        cfg.log_filter = "snail=notalevel".to_string();
        let err = build_filter(&cfg).unwrap_err();
        assert!(matches!(err, TelemetryError::Filter(_)));
    }

    #[test]
    fn accepts_valid_log_filter() {
        let cfg = TelemetryConfig::stdout("t");
        assert!(build_filter(&cfg).is_ok());
    }
}
