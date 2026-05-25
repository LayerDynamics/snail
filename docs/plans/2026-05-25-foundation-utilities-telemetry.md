# Foundation: `utilities` + `telemetry` Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use `lore:execute` to implement this plan task-by-task.
> **Scope guard:** Do ONLY what is listed here. If you discover adjacent issues (other empty crates, the TypeScript workspace, a real OTLP collector), note them as a TODO and continue. Do NOT fix them.

**Goal:** Take the Snail repo from "nothing builds" to a compiling Cargo workspace whose two foundation crates — `crates/utilities` (shared primitives) and `services/telemetry` (observability backbone) — are real, tested, and proven depend-on-able by a downstream crate.

**Architecture:** A virtual Cargo workspace at the repo root owns shared dependency versions, lint rules, and package metadata. `utilities` is a dependency-free library exposing a typed error enum (`UtilError`) and process `Config`. `telemetry` is a library exposing `init() -> TelemetryGuard` (a `tracing` + OpenTelemetry pipeline) plus a `telemetry selftest` binary that exercises that pipeline end-to-end. Every other Snail crate will depend on both.

**Tech Stack:** Rust (edition 2024, cargo 1.95), `thiserror` (typed lib errors) + `anyhow` (binary errors), `tracing` + `tracing-subscriber` (stable core), OpenTelemetry 0.27 cohort + `tracing-opentelemetry` 0.28 (OTLP/stdout export).

**Practices:** TDD (failing test → implement → pass) + typed-interfaces-first (types/signatures before logic) + contract-first (lock the public `lib.rs` surface before internals). Bootstrap/entrypoint tasks (git, workspace manifest, binaries, wiring) have no business logic to test-drive, so they use a build/run-verification structure instead — this is noted per task.

**Required skills:** none (no plugin/MCP/agent/hook/SDK surface in this plan).

**Error model (decided):** `thiserror` typed enums in library crates (`utilities`, `telemetry` lib); `anyhow::Result` in binaries (`telemetry` bin, the Task 8 wiring bin). Typed errors auto-convert into `anyhow` via `?` because they implement `std::error::Error`.

**Quality gates (decided, run every task before commit):**
- `cargo fmt --check`
- `cargo clippy -p <crate> --all-targets -- -D warnings`

---

## Task ordering invariant

After **every** task, the workspace must build clean (`cargo build`). To preserve this, a crate is added to `[workspace.members]` only in the task that first makes it compile. Members grow: `utilities` (Task 1) → `telemetry` (Task 4) → `mail` (Task 8). The other empty scaffold crates stay out of `members` until their own future plans populate them.

---

## Task 0: Initialize git + .gitignore

No business logic — verification is "git tracks the tree and ignores build output."

**Files:**
- Create: `.gitignore`
- Init: git repository at repo root

**Step 1: Initialize the repo**
```bash
git init
```
→ Expected: `Initialized empty Git repository in /Users/ryanoboyle/snail/.git/`

**Step 2: Write `.gitignore`**
```gitignore
# Rust
/target/
**/*.rs.bk

# Node / TypeScript (future workspace)
node_modules/
dist/
*.tsbuildinfo

# OS / editor
.DS_Store
*.log
```
> Note: `Cargo.lock` is intentionally NOT ignored — this workspace produces binaries, so the lockfile is committed.

**Step 3: Verify**
```bash
git status --short
```
→ Expected: untracked entries listed (README.md, CLAUDE.md, Cargo.toml, crates/, etc.); `target/` absent.

**Step 4: Commit**
```bash
git add .gitignore && git commit -m "chore: initialize git repository and .gitignore"
```

---

## Task 1: Workspace manifest + `utilities` crate skeleton

Bootstrap task (config, not TDD). Establishes the workspace and turns `utilities` into a compiling **library** crate. The `main.rs → lib.rs` swap is the load-bearing move: a `main.rs`-only crate cannot be a dependency.

**Files:**
- Create: `Cargo.toml` (root, currently 0 bytes)
- Create: `crates/utilities/Cargo.toml` (currently 0 bytes)
- Delete: `crates/utilities/src/main.rs` (empty placeholder)
- Create: `crates/utilities/src/lib.rs`

**Step 1: Write the root workspace manifest `Cargo.toml`**
```toml
[workspace]
resolver = "3"
members = [
    "crates/utilities",
    # "services/telemetry"  -> added in Task 4
    # "crates/mail"         -> added in Task 8
]

[workspace.package]
version = "0.1.0"
edition = "2024"
rust-version = "1.95"
publish = false

[workspace.dependencies]
# Error handling
thiserror = "2"
anyhow = "1"

# Tracing core — stable API, pinned exactly
tracing = "=0.1.41"
tracing-subscriber = { version = "=0.3.19", features = ["env-filter", "fmt", "json"] }

# OpenTelemetry — ONE cohesive cohort (these break in lockstep; do not mix minors)
opentelemetry = "0.27"
opentelemetry_sdk = { version = "0.27", features = ["trace"] }
opentelemetry-otlp = { version = "0.27", features = ["grpc-tonic", "trace"] }
opentelemetry-stdout = "0.27"
tracing-opentelemetry = "0.28"

# Internal crates
utilities = { path = "crates/utilities" }
telemetry = { path = "services/telemetry" }

[workspace.lints.rust]
unsafe_code = "deny"
unused_must_use = "deny"

[workspace.lints.clippy]
all = { level = "deny", priority = -1 }
```

**Step 2: Write `crates/utilities/Cargo.toml`**
```toml
[package]
name = "utilities"
version.workspace = true
edition.workspace = true
rust-version.workspace = true
publish = false

[dependencies]
thiserror.workspace = true

[lints]
workspace = true
```

**Step 3: Replace the binary placeholder with a library root**
Delete `crates/utilities/src/main.rs`, then create `crates/utilities/src/lib.rs`:
```rust
//! Shared primitives for the Snail email server.
//!
//! `utilities` is the dependency-free foundation that every other Snail crate
//! builds on: a typed error type ([`error::UtilError`]) and process
//! configuration ([`config::Config`]).

pub mod config;
pub mod error;

pub use config::Config;
pub use error::{Result, UtilError};
```
> `config` and `error` are referenced here but created in Tasks 2–3. To keep this task green, also create empty module files now so the crate compiles:
> - `crates/utilities/src/error.rs` containing only `//! Error types. (implemented in Task 2)`
> - `crates/utilities/src/config.rs` containing only `//! Configuration. (implemented in Task 3)`
> These minimal files compile; the `pub use` lines referencing `Config`/`UtilError`/`Result` would NOT — so for THIS task, comment out the two `pub use` lines and the `error`/`config` re-exports, leaving only `pub mod config;` / `pub mod error;`. Re-enable each `pub use` in its task below.

**Step 4: Verify build**
```bash
cargo build
```
→ Expected: PASS (`Compiling utilities v0.1.0`, `Finished`).

**Step 5: Gate + commit**
```bash
cargo fmt --check && cargo clippy -p utilities --all-targets -- -D warnings
git add Cargo.toml Cargo.lock crates/utilities && git commit -m "chore: bootstrap cargo workspace and utilities library crate"
```

---

## Task 2: `utilities` typed error (`UtilError`) — TDD

**Files:**
- Modify: `crates/utilities/src/error.rs`
- Modify: `crates/utilities/src/lib.rs` (re-enable `pub use error::{Result, UtilError};`)

**Step 1: Contract (typed-first) — define the surface, then the failing test**
Write `crates/utilities/src/error.rs` test module FIRST (implementation block empty/absent so it fails to compile = a failing test):
```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_error_displays_message() {
        let e = UtilError::Config("missing data_dir".into());
        assert_eq!(e.to_string(), "invalid configuration: missing data_dir");
    }

    #[test]
    fn io_error_converts_via_from() {
        let io = std::io::Error::new(std::io::ErrorKind::NotFound, "nope");
        let e: UtilError = io.into();
        assert!(matches!(e, UtilError::Io(_)));
        assert!(e.to_string().starts_with("i/o error:"));
    }

    #[test]
    fn env_error_formats_named_fields() {
        let e = UtilError::Env {
            name: "SNAIL_LOG".into(),
            reason: "not a level".into(),
        };
        assert_eq!(
            e.to_string(),
            "environment variable `SNAIL_LOG` is invalid: not a level"
        );
    }
}
```

**Step 2: Run to verify it fails**
```bash
cargo test -p utilities
```
→ Expected: FAIL (compile error: `UtilError` not found).

**Step 3: Implement (prepend above the test module in `error.rs`)**
```rust
//! Error types shared across Snail.

use thiserror::Error;

/// Errors produced by the shared utilities layer.
#[derive(Debug, Error)]
pub enum UtilError {
    /// A configuration value was missing or invalid.
    #[error("invalid configuration: {0}")]
    Config(String),

    /// An underlying I/O operation failed.
    #[error("i/o error: {0}")]
    Io(#[from] std::io::Error),

    /// An environment variable held a value that could not be used.
    #[error("environment variable `{name}` is invalid: {reason}")]
    Env {
        /// The offending variable name.
        name: String,
        /// Why it was rejected.
        reason: String,
    },
}

/// Convenience alias for results that fail with [`UtilError`].
pub type Result<T> = std::result::Result<T, UtilError>;
```
Then in `lib.rs`, re-enable: `pub use error::{Result, UtilError};`

**Step 4: Run to verify it passes**
```bash
cargo test -p utilities
```
→ Expected: PASS (3 tests).

**Step 5: Gate + commit**
```bash
cargo fmt --check && cargo clippy -p utilities --all-targets -- -D warnings
git add crates/utilities && git commit -m "feat(utilities): typed UtilError with Config/Io/Env variants"
```

---

## Task 3: `utilities` process `Config` — TDD

`from_env` is split into a pure `from_source(getter)` so it is testable without mutating global env (note: in edition 2024 `std::env::set_var` is `unsafe`, which `unsafe_code = "deny"` forbids — the pure getter sidesteps this entirely).

**Files:**
- Modify: `crates/utilities/src/config.rs`
- Modify: `crates/utilities/src/lib.rs` (re-enable `pub use config::Config;`)

**Step 1: Failing test first (append to `config.rs`)**
```rust
#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn default_has_sensible_values() {
        let c = Config::default();
        assert_eq!(c.data_dir, PathBuf::from("/var/lib/snail"));
        assert_eq!(c.log_level, "info");
    }

    #[test]
    fn from_source_overrides_set_vars() {
        let c = Config::from_source(|k| match k {
            "SNAIL_DATA_DIR" => Some("/data/snail".to_string()),
            "SNAIL_LOG" => Some("snail=debug".to_string()),
            _ => None,
        })
        .unwrap();
        assert_eq!(c.data_dir, PathBuf::from("/data/snail"));
        assert_eq!(c.log_level, "snail=debug");
    }

    #[test]
    fn from_source_rejects_empty_var() {
        let err = Config::from_source(|k| match k {
            "SNAIL_DATA_DIR" => Some("   ".to_string()),
            _ => None,
        })
        .unwrap_err();
        assert!(matches!(err, UtilError::Env { .. }));
    }
}
```

**Step 2: Run to verify it fails**
```bash
cargo test -p utilities
```
→ Expected: FAIL (`Config` not found).

**Step 3: Implement (prepend in `config.rs`)**
```rust
//! Process-wide configuration shared across Snail services.

use std::path::PathBuf;

use crate::error::{Result, UtilError};

/// Configuration shared across Snail services.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    /// Directory under which mail and state are stored.
    pub data_dir: PathBuf,
    /// `tracing` env-filter directive (e.g. `info`, `snail=debug`).
    pub log_level: String,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            data_dir: PathBuf::from("/var/lib/snail"),
            log_level: "info".to_string(),
        }
    }
}

impl Config {
    /// Build configuration from the process environment, falling back to [`Default`].
    ///
    /// Recognised variables: `SNAIL_DATA_DIR`, `SNAIL_LOG`.
    pub fn from_env() -> Result<Self> {
        Self::from_source(|k| std::env::var(k).ok())
    }

    /// Build configuration from an arbitrary variable source. Pure and testable.
    ///
    /// # Errors
    /// Returns [`UtilError::Env`] if a recognised variable is present but blank.
    pub fn from_source(get: impl Fn(&str) -> Option<String>) -> Result<Self> {
        let mut cfg = Self::default();

        if let Some(dir) = get("SNAIL_DATA_DIR") {
            if dir.trim().is_empty() {
                return Err(UtilError::Env {
                    name: "SNAIL_DATA_DIR".into(),
                    reason: "must not be empty".into(),
                });
            }
            cfg.data_dir = PathBuf::from(dir);
        }

        if let Some(level) = get("SNAIL_LOG") {
            if level.trim().is_empty() {
                return Err(UtilError::Env {
                    name: "SNAIL_LOG".into(),
                    reason: "must not be empty".into(),
                });
            }
            cfg.log_level = level;
        }

        Ok(cfg)
    }
}
```
Then in `lib.rs`, re-enable: `pub use config::Config;`

**Step 4: Run to verify it passes**
```bash
cargo test -p utilities
```
→ Expected: PASS (6 tests total).

**Step 5: Gate + commit**
```bash
cargo fmt --check && cargo clippy -p utilities --all-targets -- -D warnings
git add crates/utilities && git commit -m "feat(utilities): process Config with pure, testable from_source/from_env"
```

---

## Task 4: `telemetry` crate skeleton (`[lib]` + `[[bin]]`)

Bootstrap task. Adds `telemetry` to the workspace and lays down the module map honoring the scaffold directories (`data/ otel/ exporters/ listeners/ lib/`). The `lib/` directory is mounted under the module name **`core_api`** via `#[path]` so no code ever reads `telemetry::lib::*` (which would look like a typo).

**Files:**
- Modify: `Cargo.toml` (root — add `services/telemetry` to members)
- Create: `services/telemetry/Cargo.toml`
- Create: `services/telemetry/src/lib.rs`
- Create: `services/telemetry/src/data/mod.rs`, `src/otel/mod.rs`, `src/exporters/mod.rs`, `src/listeners/mod.rs`, `src/lib/mod.rs`
- Create: `services/telemetry/src/main.rs`

**Step 1: Add the member AND the path dependency** in root `Cargo.toml`. During m1 the `telemetry` entry in `[workspace.dependencies]` was deliberately deferred (its manifest was still empty), so uncomment it now in addition to adding the member:
```toml
members = [
    "crates/utilities",
    "services/telemetry",
    # "crates/mail"  -> added in Task 8
]
```
```toml
# in [workspace.dependencies] — uncomment now that services/telemetry/Cargo.toml exists:
telemetry = { path = "services/telemetry" }
```

**Step 2: Write `services/telemetry/Cargo.toml`**
```toml
[package]
name = "telemetry"
version.workspace = true
edition.workspace = true
rust-version.workspace = true
publish = false

[lib]
name = "telemetry"
path = "src/lib.rs"

[[bin]]
name = "telemetry"
path = "src/main.rs"

[dependencies]
utilities.workspace = true
thiserror.workspace = true
anyhow.workspace = true
tracing.workspace = true
tracing-subscriber.workspace = true
tracing-opentelemetry.workspace = true
opentelemetry.workspace = true
opentelemetry_sdk.workspace = true
opentelemetry-otlp.workspace = true
opentelemetry-stdout.workspace = true

[lints]
workspace = true
```

**Step 3: Write `src/lib.rs` (the contract — lock the public surface)**
```rust
//! Snail observability backbone: structured logging + distributed tracing.
//!
//! Library surface that every Snail crate links against to emit telemetry, plus
//! the `telemetry` binary (a one-shot pipeline self-test). Initialise once at
//! process start with [`init`] and hold the returned [`TelemetryGuard`] for the
//! process lifetime.

pub mod data;
pub mod exporters;
pub mod listeners;
pub mod otel;

// The scaffold names this directory `lib/`. A module path of `telemetry::lib`
// reads like a typo, so the directory is mounted under the saner name `core_api`.
#[path = "lib/mod.rs"]
mod core_api;

pub use core_api::{init, TelemetryError, TelemetryGuard};
pub use data::{ExporterKind, TelemetryConfig};
```

**Step 4: Minimal compiling module stubs** (filled by Tasks 5–7; keep them tiny but real so the crate builds now):
- `src/data/mod.rs`: `//! Telemetry configuration and value types. (Task 5)`
- `src/otel/mod.rs`: `//! OpenTelemetry tracer-provider construction. (Task 6)`
- `src/exporters/mod.rs`: `//! Span-exporter builders. (Task 6)`
- `src/listeners/mod.rs`: `//! In-process telemetry listeners. (Task 6)`
- `src/lib/mod.rs`: `//! Core init/guard. (Task 6)`

> Because `lib.rs` re-exports symbols not yet defined, comment out the two `pub use` lines for this task and re-enable them in Tasks 5–6 as the symbols land (same pattern as Task 1).

**Step 5: Minimal `src/main.rs`** (real entrypoint, fleshed out in Task 7):
```rust
//! `telemetry` — observability self-test binary (see Task 7).
fn main() -> anyhow::Result<()> {
    println!("telemetry binary placeholder — implemented in Task 7");
    Ok(())
}
```

**Step 6: Verify, gate, commit**
```bash
cargo build
cargo fmt --check && cargo clippy -p telemetry --all-targets -- -D warnings
git add Cargo.toml services/telemetry && git commit -m "chore(telemetry): scaffold lib+bin crate and module map"
```
→ Expected: build PASS.

---

## Task 5: `telemetry::data` — config + exporter types — TDD

**Files:**
- Modify: `services/telemetry/src/data/mod.rs`
- Modify: `services/telemetry/src/lib.rs` (re-enable `pub use data::{ExporterKind, TelemetryConfig};`)

**Step 1: Failing test first (append to `data/mod.rs`)**
```rust
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
            Some(ExporterKind::Otlp { endpoint: "http://localhost:4317".into() })
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
```

**Step 2: Run to verify it fails**
```bash
cargo test -p telemetry
```
→ Expected: FAIL (types not found).

**Step 3: Implement (prepend in `data/mod.rs`)**
```rust
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
            return Some(Self::Otlp { endpoint: endpoint.to_string() });
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
```
Re-enable in `lib.rs`: `pub use data::{ExporterKind, TelemetryConfig};`

**Step 4: Run to verify it passes**
```bash
cargo test -p telemetry
```
→ Expected: PASS (4 tests).

**Step 5: Gate + commit**
```bash
cargo fmt --check && cargo clippy -p telemetry --all-targets -- -D warnings
git add services/telemetry && git commit -m "feat(telemetry): ExporterKind + TelemetryConfig value types"
```

---

## Task 6: `telemetry` core pipeline (`init` / `TelemetryGuard`) + exporters/otel/listeners

This task wires `tracing` to OpenTelemetry. The `tracing` core is stable; the OpenTelemetry builder calls are the **one** place where version drift can occur. There is a dedicated build-verification step (Step 4) for exactly that — it is a build instruction, not a license to stub.

**Files:**
- Modify: `services/telemetry/src/listeners/mod.rs`
- Modify: `services/telemetry/src/exporters/mod.rs`
- Modify: `services/telemetry/src/otel/mod.rs`
- Modify: `services/telemetry/src/lib/mod.rs` (the `core_api` module)
- Modify: `services/telemetry/src/lib.rs` (re-enable `pub use core_api::{...}`)

**Step 1: Failing tests first** — the global subscriber can only be installed once per process, so unit tests target the side-effect-free pieces; the live `init()` path is verified by running the binary (Task 7) and the wiring crate (Task 8).

Append to `listeners/mod.rs`:
```rust
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
```

Append to `lib/mod.rs` (`core_api`):
```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_invalid_log_filter() {
        let mut cfg = crate::data::TelemetryConfig::stdout("t");
        cfg.log_filter = "not a valid !! filter".to_string();
        let err = build_filter(&cfg).unwrap_err();
        assert!(matches!(err, TelemetryError::Filter(_)));
    }

    #[test]
    fn accepts_valid_log_filter() {
        let cfg = crate::data::TelemetryConfig::stdout("t");
        assert!(build_filter(&cfg).is_ok());
    }
}
```

**Step 2: Run to verify it fails**
```bash
cargo test -p telemetry
```
→ Expected: FAIL (`EventCounter`, `build_filter`, `TelemetryError` not found).

**Step 3: Implement**

`listeners/mod.rs`:
```rust
//! In-process listeners that tap the live telemetry stream.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

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
```

`exporters/mod.rs`:
```rust
//! Span-exporter builders for the configured destination.

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
```

`otel/mod.rs`:
```rust
//! OpenTelemetry tracer-provider construction.

use opentelemetry_sdk::trace::SdkTracerProvider;
use opentelemetry_sdk::Resource;

use crate::core_api::TelemetryError;
use crate::data::{ExporterKind, TelemetryConfig};
use crate::exporters;

/// Build a tracer provider for the configured exporter, tagged with the service name.
///
/// # Errors
/// Returns [`TelemetryError::Exporter`] if an exporter fails to build.
pub fn build_provider(config: &TelemetryConfig) -> Result<SdkTracerProvider, TelemetryError> {
    let resource = Resource::builder()
        .with_service_name(config.service_name.clone())
        .build();

    let provider = match &config.exporter {
        ExporterKind::Stdout => SdkTracerProvider::builder()
            .with_simple_exporter(exporters::stdout())
            .with_resource(resource)
            .build(),
        ExporterKind::Otlp { endpoint } => SdkTracerProvider::builder()
            .with_batch_exporter(exporters::otlp(endpoint)?)
            .with_resource(resource)
            .build(),
    };

    Ok(provider)
}
```

`lib/mod.rs` (`core_api`):
```rust
//! Core initialisation: wire `tracing` + OpenTelemetry into one subscriber.

use opentelemetry::trace::TracerProvider as _;
use opentelemetry_sdk::trace::SdkTracerProvider;
use thiserror::Error;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::EnvFilter;

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
    provider: SdkTracerProvider,
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
    let otel_layer = tracing_opentelemetry::layer().with_tracer(tracer);
    let events = EventCounter::new();

    tracing_subscriber::registry()
        .with(filter)
        .with(tracing_subscriber::fmt::layer().json())
        .with(otel_layer)
        .with(events.clone())
        .try_init()
        .map_err(|_| TelemetryError::AlreadyInitialised)?;

    Ok(TelemetryGuard { provider, events })
}
```
Re-enable in `lib.rs`: `pub use core_api::{init, TelemetryError, TelemetryGuard};`

**Step 4: Build-verification of the OpenTelemetry cohort (the one drift point)**
```bash
cargo build -p telemetry
```
→ Expected: PASS.
> If this fails inside `otel/mod.rs`, `exporters/mod.rs`, or the `otel_layer`/`tracer` lines, the cause is **API drift in the OpenTelemetry 0.27 / tracing-opentelemetry 0.28 cohort** (these crates rename builders between minor versions). Resolve by checking the resolved versions (`cargo tree -p opentelemetry -p tracing-opentelemetry`) against docs.rs for those exact versions and adjusting the builder calls (`Resource::builder` vs `Resource::new`, `SdkTracerProvider` vs `TracerProvider`, `with_batch_exporter` signature, `layer().with_tracer(...)`). **Do not stub or comment out the OTLP path** — adjust it to the real API.

**Step 5: Run tests, gate, commit**
```bash
cargo test -p telemetry
cargo fmt --check && cargo clippy -p telemetry --all-targets -- -D warnings
git add services/telemetry && git commit -m "feat(telemetry): init() + TelemetryGuard wiring tracing to OpenTelemetry"
```
→ Expected: tests PASS (4 + 3 = 7 telemetry tests).

---

## Task 7: `telemetry selftest` binary

Entrypoint task (verified by running it). A one-shot CLI that initialises the stdout pipeline, emits a span + events, and asserts the pipeline observed them. (The full long-running OTLP **collector** is deliberately out of scope — see "Deferred".)

**Files:**
- Modify: `services/telemetry/src/main.rs`

**Step 1: Implement**
```rust
//! `telemetry` — one-shot self-test for the Snail observability pipeline.
//!
//! Usage: `telemetry selftest` — initialises telemetry (stdout exporter), emits
//! a span and several events, then reports how many events the pipeline observed.

use anyhow::{bail, Context, Result};
use telemetry::{init, TelemetryConfig};
use tracing::{info, info_span, warn};

fn main() -> Result<()> {
    let mode = std::env::args().nth(1).unwrap_or_else(|| "selftest".to_string());
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
        warn!(check = "synthetic", "synthetic warning to exercise the layer stack");
        info!(check = "shutdown", "selftest complete");
    }

    let observed = guard.events.count();
    if observed == 0 {
        bail!("self-test emitted no events — pipeline is not wired");
    }
    println!("telemetry selftest OK: {observed} events observed (exporter: {:?})", config.exporter);
    Ok(())
}
```

**Step 2: Run it (real end-to-end verification of `init`)**
```bash
cargo run -p telemetry --bin telemetry -- selftest
```
→ Expected: JSON log lines on stdout, then `telemetry selftest OK: 3 events observed (exporter: Stdout)`, exit code 0.

**Step 3: Verify the error path**
```bash
cargo run -p telemetry --bin telemetry -- bogus; echo "exit=$?"
```
→ Expected: error mentioning `unknown command \`bogus\``, `exit=1`.

**Step 4: Gate + commit**
```bash
cargo fmt --check && cargo clippy -p telemetry --all-targets -- -D warnings
git add services/telemetry && git commit -m "feat(telemetry): selftest binary exercising the live pipeline"
```

---

## Task 8: Prove the wiring — `crates/mail` depends on the foundation

Verifies the whole point of this plan: a downstream crate can depend on **both** foundation crates and use them together. This is a minimal, clearly-labelled proof entrypoint, not the real MTA.

**Files:**
- Modify: `Cargo.toml` (root — add `crates/mail` to members)
- Create: `crates/mail/Cargo.toml`
- Modify: `crates/mail/src/main.rs` (currently an empty placeholder)

> Scope guard: `crates/mail` has many other empty files (`transport/`, `storage/`, `snailmail.rs`, …). Do NOT populate them. Only `Cargo.toml` and `main.rs` are touched here.

**Step 1: Add the member** in root `Cargo.toml`:
```toml
members = [
    "crates/utilities",
    "services/telemetry",
    "crates/mail",
]
```

**Step 2: Write `crates/mail/Cargo.toml`**
```toml
[package]
name = "mail"
version.workspace = true
edition.workspace = true
rust-version.workspace = true
publish = false

[dependencies]
utilities.workspace = true
telemetry.workspace = true
anyhow.workspace = true
tracing.workspace = true

[lints]
workspace = true
```

**Step 3: Write `crates/mail/src/main.rs`**
```rust
//! Wiring proof: confirms `mail` can depend on the foundation (utilities +
//! telemetry) and use both together. Replace with the real MTA entrypoint later.

use anyhow::Result;
use telemetry::{init, TelemetryConfig};
use tracing::info;
use utilities::Config;

fn main() -> Result<()> {
    let app_config = Config::from_env()?; // utilities: typed error -> anyhow via `?`
    let _telemetry = init(&TelemetryConfig::stdout("snail-mail"))?; // telemetry: pipeline up

    info!(
        data_dir = %app_config.data_dir.display(),
        log_level = %app_config.log_level,
        "mail crate online — foundation wired"
    );
    Ok(())
}
```

**Step 4: Build the whole workspace + run the proof**
```bash
cargo build
cargo run -p mail
```
→ Expected: build PASS for all three members; `cargo run -p mail` prints a JSON log line containing `"mail crate online — foundation wired"` with `data_dir`/`log_level` fields, exit 0.

**Step 5: Full-workspace test + gate + commit**
```bash
cargo test
cargo fmt --check && cargo clippy --workspace --all-targets -- -D warnings
git add Cargo.toml crates/mail && git commit -m "test(mail): prove mail depends on utilities + telemetry foundation"
```
→ Expected: all tests PASS across the workspace.

---

## Definition of done

- `cargo build` compiles the workspace (`utilities`, `telemetry`, `mail`) clean.
- `cargo test` passes (utilities: 6, telemetry: 7).
- `cargo clippy --workspace --all-targets -- -D warnings` is clean; `cargo fmt --check` is clean.
- `cargo run -p telemetry -- selftest` reports `OK` with a non-zero event count.
- `cargo run -p mail` emits a traced log proving both foundation crates are usable together.
- `utilities/src/main.rs` no longer exists; `utilities` is a library crate.
- `services/telemetry` exposes a `[lib]` (depended on by `mail`) and a `[[bin]]` (`selftest`); no code references `telemetry::lib`.

## Deferred (explicitly OUT of scope — note as TODO if encountered, do not build)

- A real long-running OTLP **collector** (network receiver) in the `telemetry` binary — `selftest` is the only command this plan ships.
- Populating any other empty crate (`access`, `identity`, `security`, `network`, `filter`, `client`) or the `services/snail_server` binary.
- The TypeScript/pnpm workspace (`packages/`, `apps/`) — `pnpm-workspace.yaml` stays empty here.
- The shared domain model (`Message`/`Mailbox`/`Domain`/`Account`) and the `utilities`-vs-new-`core`-crate decision — parked from the earlier discussion.
