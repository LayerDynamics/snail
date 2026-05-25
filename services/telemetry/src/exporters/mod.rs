//! Span-exporter builders for the configured destination.

use opentelemetry_otlp::WithExportConfig;

use crate::core_api::TelemetryError;

/// Build the stdout span exporter (default; no network).
#[must_use]
pub fn stdout() -> opentelemetry_stdout::SpanExporter {
    opentelemetry_stdout::SpanExporter::default()
}

/// Build the OTLP/gRPC span exporter targeting `endpoint`.
///
/// # Errors
/// Returns [`TelemetryError::Exporter`] if the exporter cannot be constructed.
pub fn otlp(endpoint: &str) -> Result<opentelemetry_otlp::SpanExporter, TelemetryError> {
    opentelemetry_otlp::SpanExporter::builder()
        .with_tonic()
        .with_endpoint(endpoint.to_string())
        .build()
        .map_err(|e| TelemetryError::Exporter(e.to_string()))
}
