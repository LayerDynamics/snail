//! Wiring proof for the foundation: the `mail` crate depends on both
//! `utilities` and `telemetry` and uses them together — loading process
//! configuration, bringing telemetry online, and emitting a traced log. The
//! real MTA entrypoint grows from here.

use anyhow::Result;
use telemetry::{TelemetryConfig, init};
use tracing::info;
use utilities::Config;

fn main() -> Result<()> {
    // `utilities::UtilError` converts into `anyhow::Error` via `?`.
    let app_config = Config::from_env()?;
    // Hold the guard for the process lifetime so telemetry flushes on exit.
    let _guard = init(&TelemetryConfig::stdout("snail-mail"))?;

    info!(
        data_dir = %app_config.data_dir.display(),
        log_level = %app_config.log_level,
        "mail crate online — foundation wired"
    );
    Ok(())
}
