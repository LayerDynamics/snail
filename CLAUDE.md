# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What Snail is

Snail is a **self-hosted, privacy-first email server you own** — built so individuals can run their own mail without a large provider reading their lives. Per the README, it aims to be compatible with as many email hosts and clients as possible, deploy as cheaply and easily as possible, and be extended through a plugin integration service. The engine is **Rust**; the tooling, SDK, and clients are **TypeScript**.

There is intentionally **no built-in `@<company>.com`** — a **custom domain is a hard requirement**, not an option.

## Current state — READ THIS FIRST

The repo is an early scaffold with a **working Rust foundation**. Most of the tree is still empty placeholders, but the base layer compiles, tests, and runs:

- **Built, tested, committed:** `crates/utilities` (typed `UtilError` + process `Config`) and `services/telemetry` (a `tracing` + OpenTelemetry pipeline: `init()` → `TelemetryGuard`, plus a `telemetry selftest` binary). `crates/mail` has a wiring-proof `main.rs` that depends on both and emits a traced log. All clippy/fmt-clean.
- **Still 0-byte empty scaffold (untracked until populated):** every other crate — `crates/{access,client,filter,identity,network,security}` — plus `services/snail_server`, the whole TypeScript side (`packages/`, `apps/`, `pnpm-workspace.yaml`), `plugins/`, and most of `crates/mail`'s submodules (`transport/`, `storage/`, `security/`, `observability/`, `snailmail.rs`).

What this means for working here:

- In the **empty** areas, the default task is to *populate* a placeholder, not edit existing logic — a Grep for a symbol there finds nothing yet, and the directory/file names are the design spec.
- The build is **real** — see commands below. A new crate joins `[workspace.members]` in the root `Cargo.toml` only once it compiles; keep the workspace green at every step.
- Implementation followed the plan at `docs/plans/2026-05-25-foundation-utilities-telemetry.md` (milestones m0–m8).

## Build, test, lint (Rust workspace)

A Cargo workspace (edition 2024, resolver `"3"`) defined by the root `Cargo.toml`. Shared dependency versions and lint rules live in `[workspace.dependencies]` / `[workspace.lints]`; each member inherits via `[lints] workspace = true` and `<dep>.workspace = true`.

- Build / test everything: `cargo build` · `cargo test`
- One crate: `cargo test -p utilities` (or `-p telemetry`)
- A single test by name: `cargo test -p telemetry parse_otlp_extracts_endpoint`
- Lint gate (must be clean): `cargo clippy --workspace --all-targets -- -D warnings`
- Format: `cargo fmt --check` (verify) · `cargo fmt` (apply)
- Run the telemetry self-test: `cargo run -p telemetry -- selftest`
- Run the mail wiring proof: `cargo run -p mail`

**Error-handling convention:** `thiserror` typed errors in **library** crates, `anyhow` in **binaries** (typed errors convert via `?`). The TypeScript workspace (pnpm) is not set up yet.

## Architecture (by role, derived from the skeleton)

### Foundation — everything builds on these two (implemented)

The base layer; every other crate depends on them. Both are independent of each other (`mail` uses both).

- **`crates/utilities/`** — shared primitives, dependency-free. `error::UtilError` (thiserror; `Config`/`Io`/`Env` variants) + `Result` alias, and `config::Config` (`data_dir`, `log_level`) built via a pure, testable `from_source(getter)` behind `from_env` (reads `SNAIL_DATA_DIR`, `SNAIL_LOG`). `from_source` is pure specifically to avoid edition-2024's now-`unsafe` `std::env::set_var` in tests.
- **`services/telemetry/`** — the observability backbone (a **library**, not a top-layer service). `init(&TelemetryConfig) -> Result<TelemetryGuard>` wires `tracing` → OpenTelemetry: `EnvFilter` + JSON `fmt` layer + OTel layer + an `EventCounter` listener; the guard flushes on drop. Exporters (`data::ExporterKind`): `Stdout` (default) and `Otlp`, both attached with a **simple/synchronous** span processor so `init` needs no async runtime — batching is deferred to the future collector. OTel stack is the **0.27 cohort + tracing-opentelemetry 0.28**, pinned together in `[workspace.dependencies]` (they break in lockstep — verify API against the installed source in `~/.cargo/registry` before changing). The scaffold's `lib/` directory is mounted as the module **`core_api`** (never `telemetry::lib`). Also ships a `telemetry selftest` binary.

### Rust engine

- **Mail core — `crates/mail/`**: the heart of the server. *Currently only a wiring-proof `src/main.rs` (depends on the foundation, emits one traced log); the submodules below are empty scaffold awaiting their own plan.*
  - `transport/` — `mta.rs`, `smtp.rs`, `inbound.rs`, `outbound.rs` (mail transfer agent and SMTP send/receive paths)
  - `storage/` — `mda.rs` (mail delivery agent), `store.rs` (mailbox persistence)
  - `security/` — `certs.rs`, `tls.rs`, `scanner.rs` (message scanning)
  - `observability/`, plus `snailmail.rs`
- **Client access protocols — `crates/access/`**: how mail clients talk to the server — `imap.rs`, `pop.rs`, `msa.rs` (mail submission agent), `dovecot.rs`, `web.rs`, coordinated by `manager.rs`.
- **Identity / auth — `crates/identity/`**: `auth.rs`, `oauth.rs`, `sals.rs` (**likely SASL**), `connect.rs`, `check.rs`, `data.rs`.
- **Security — `crates/security/`**: `encryption/` (`encrypt`, `decrypt`, `salt`, `hash`, `algos/`), `credential/` (`provider`, `manager`, `reciever.rs`), `firewall/` (`allow`, `block`, `track`, `trace`, `pause`), and `audit/` (`audit_logger.rs`). Identity is **not** here — it lives solely in the `crates/identity/` crate.
- **Deliverability — `crates/network/`**: `dns/` with `mx.rs`, `a.rs`, `txt.rs`, `dkim.rs`, `dmark.rs` (**likely DMARC**), `reverse.rs`, `lookup.rs` — the DNS records a mail server needs to be trusted — plus `tls/`.
- **Spam — `crates/filter/`**: `spam/` filtering.
- **Native client — `crates/client/`**: has `build.rs`, `bind.rs`, and a `bindings/` dir → **almost certainly Rust↔JS FFI bindings** for the SDK / clients. Treat changes here as crossing the language boundary.

### Rust binaries — `services/`

- `snail_server/` — the composition root: the main server binary that wires all crates together and initializes telemetry at startup. *Still empty scaffold — the natural next milestone.*
- `telemetry/` — its `telemetry selftest` `[[bin]]` lives here, but treat it as a **foundation** crate (see above), not a top-layer consumer. A long-running OTLP collector is deferred.

### TypeScript side

- **`packages/cli/`** — the operator CLI (`bin/snail.ts`). Commands present as files: `start`, `stop`, `restart`, `status`, `logs`, `configure`, `settings`, `domain`, `send`, `get`, `export`, `compress`, `reset`.
- **`packages/sdk/`** — programmatic SDK, organized into `api/`, `core/`, `data/`, `plugin/`, `utils/`. The `plugin/` module is where the README's plugin-extensibility surface lives.
- **`apps/web-client/`** and **`apps/desktop-client/`** — end-user email clients.

### Extensibility & ops

- **`plugins/`** — the plugin integration service described in the README (currently empty).
- **`tools/`** — `deploy/`, `install/`, `wizard/` — deployment and guided setup, supporting the "easy and cheap to self-host" goal.
- **`docs/`** — empty.

## Naming gotchas (real filenames — do not "correct" blindly)

These spellings are the actual files; Grep/Glob against the conventional spelling will miss them:

- `crates/network/src/dns/dmark.rs` — DMARC
- `crates/identity/src/sals.rs` — SASL
- `crates/security/src/credential/reciever.rs` — receiver

## Identity location (resolved)

Identity is consolidated into the standalone **`crates/identity/`** crate. An earlier duplicate `crates/security/src/identity/` module was removed — do not recreate it. All authentication and identity logic belongs in `crates/identity/`.
