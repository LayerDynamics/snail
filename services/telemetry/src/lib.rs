//! Snail observability backbone: structured logging + distributed tracing.
//!
//! Library surface that every Snail crate links against to emit telemetry.
//! A process initialises telemetry once at start-up and holds the returned
//! guard for its lifetime so spans and logs are flushed on shutdown.

pub mod data;
pub mod exporters;
pub mod listeners;
pub mod otel;

// The scaffold names one module directory `lib/`; a module path of `telemetry::lib`
// would read like a typo, so the directory is mounted under the saner name `core_api`.
#[path = "lib/mod.rs"]
mod core_api;

pub use core_api::{TelemetryError, TelemetryGuard, init};
pub use data::{ExporterKind, TelemetryConfig};
