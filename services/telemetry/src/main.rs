//! `telemetry` — one-shot self-test for the Snail observability pipeline.
//!
//! Usage: `telemetry selftest` — initialises telemetry (stdout exporter), emits
//! a span and several events, then reports how many events the pipeline observed.

use anyhow::{Context, Result, bail};
use telemetry::{TelemetryConfig, init};
use tracing::{info, info_span, warn};

fn main() -> Result<()> {
    let mode = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "selftest".to_string());
    match mode.as_str() {
        "selftest" => selftest(),
        other => bail!("unknown command `{other}` (expected `selftest`)"),
    }
}

fn selftest() -> Result<()> {
    let config = TelemetryConfig::stdout("snail-telemetry-selftest");
    let guard = init(&config).context("initialising telemetry")?;

    {
        let span = info_span!("selftest", component = "telemetry");
        let _enter = span.enter();
        info!(check = "startup", "telemetry pipeline online");
        warn!(
            check = "synthetic",
            "synthetic warning to exercise the layer stack"
        );
        info!(check = "shutdown", "selftest complete");
    }

    let observed = guard.events.count();
    if observed == 0 {
        bail!("self-test emitted no events — pipeline is not wired");
    }
    println!(
        "telemetry selftest OK: {observed} events observed (exporter: {:?})",
        config.exporter
    );
    Ok(())
}
