//! Telemetry configuration and value types.

use std::time::Duration;

/// Destination for exported telemetry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExporterKind {
    /// Spans/logs written to stdout. Default; requires no network.
    Stdout,
    /// OTLP/gRPC export to a collector at `endpoint`.
    Otlp {
        /// Collector endpoint URL, e.g. `http://localhost:4317`.
        endpoint: String,
    },
}

impl ExporterKind {
    /// Parse the `SNAIL_TELEMETRY_EXPORTER` convention: `stdout` or `otlp:<endpoint>`.
    #[must_use]
    pub fn parse(raw: &str) -> Option<Self> {
        let raw = raw.trim();
        if raw.eq_ignore_ascii_case("stdout") {
            return Some(Self::Stdout);
        }
        if let Some(endpoint) = raw.strip_prefix("otlp:") {
            if endpoint.is_empty() {
                return None;
            }
            return Some(Self::Otlp {
                endpoint: endpoint.to_string(),
            });
        }
        None
    }
}

/// Telemetry configuration for a single service.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TelemetryConfig {
    /// Logical service name attached to every span (e.g. `snail-server`).
    pub service_name: String,
    /// `tracing` env-filter directive (e.g. `info`, `snail=debug`).
    pub log_filter: String,
    /// Selected exporter.
    pub exporter: ExporterKind,
    /// Maximum time to wait for a flush on shutdown.
    pub flush_timeout: Duration,
}

impl TelemetryConfig {
    /// A stdout-only config for `service_name` — always works, no network.
    #[must_use]
    pub fn stdout(service_name: impl Into<String>) -> Self {
        Self {
            service_name: service_name.into(),
            log_filter: "info".to_string(),
            exporter: ExporterKind::Stdout,
            flush_timeout: Duration::from_secs(5),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_stdout_is_case_insensitive() {
        assert_eq!(ExporterKind::parse("STDOUT"), Some(ExporterKind::Stdout));
    }

    #[test]
    fn parse_otlp_extracts_endpoint() {
        assert_eq!(
            ExporterKind::parse("otlp:http://localhost:4317"),
            Some(ExporterKind::Otlp {
                endpoint: "http://localhost:4317".into()
            })
        );
    }

    #[test]
    fn parse_rejects_empty_otlp_and_garbage() {
        assert_eq!(ExporterKind::parse("otlp:"), None);
        assert_eq!(ExporterKind::parse("kafka"), None);
    }

    #[test]
    fn stdout_config_defaults() {
        let c = TelemetryConfig::stdout("snail-test");
        assert_eq!(c.service_name, "snail-test");
        assert_eq!(c.log_filter, "info");
        assert_eq!(c.exporter, ExporterKind::Stdout);
    }
}
