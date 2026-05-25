//! Snail observability backbone: structured logging + distributed tracing.
//!
//! Library surface that every Snail crate links against to emit telemetry.
//! A process initialises telemetry once at start-up and holds the returned
//! guard for its lifetime so spans and logs are flushed on shutdown.

pub mod data;
pub mod exporters;
pub mod listeners;
pub mod otel;

pub use data::{ExporterKind, TelemetryConfig};
