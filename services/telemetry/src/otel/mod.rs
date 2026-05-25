//! OpenTelemetry tracer-provider construction.

use opentelemetry::KeyValue;
use opentelemetry_sdk::Resource;
use opentelemetry_sdk::trace::TracerProvider;

use crate::core_api::TelemetryError;
use crate::data::{ExporterKind, TelemetryConfig};
use crate::exporters;

/// Build a tracer provider for the configured exporter, tagged with the service name.
///
/// Both exporters are attached with a *simple* (synchronous) span processor so
/// `init` needs no async runtime. Batching belongs with the future long-running
/// collector, not this foundation.
///
/// # Errors
/// Returns [`TelemetryError::Exporter`] if an exporter fails to build.
pub fn build_provider(config: &TelemetryConfig) -> Result<TracerProvider, TelemetryError> {
    let resource = Resource::new(vec![KeyValue::new(
        "service.name",
        config.service_name.clone(),
    )]);
    let builder = TracerProvider::builder().with_resource(resource);

    let provider = match &config.exporter {
        ExporterKind::Stdout => builder.with_simple_exporter(exporters::stdout()).build(),
        ExporterKind::Otlp { endpoint } => builder
            .with_simple_exporter(exporters::otlp(endpoint)?)
            .build(),
    };

    Ok(provider)
}
