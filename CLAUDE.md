# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What Snail is

Snail is a **self-hosted, privacy-first email server you own** — built so individuals can run their own mail without a large provider reading their lives. Per the README, it aims to be compatible with as many email hosts and clients as possible, deploy as cheaply and easily as possible, and be extended through a plugin integration service. The engine is **Rust**; the tooling, SDK, and clients are **TypeScript**.

There is intentionally **no built-in `@<company>.com`** — a **custom domain is a hard requirement**, not an option.

## Current state — READ THIS FIRST

The **entire Rust engine is built, tested, and runs as a full internet MTA** (milestones m0–m16). The composition root boots and serves mail end-to-end — local delivery, retrieval, **outbound relay to remote MX**, and **inbound MX reception over STARTTLS** behind a firewall. The TypeScript tooling and the FFI client binding are the only parts still empty.

- **Built, tested, committed (9 workspace members, ~151 tests, all clippy `-D warnings` + fmt clean):**
  - `crates/utilities` — typed `UtilError` + process `Config`.
  - `services/telemetry` — `tracing` + OpenTelemetry pipeline (`init()` → `TelemetryGuard`) + `telemetry selftest` binary.
  - `crates/network` — async DNS (hickory `DnsResolver`, MX lookup) + rustls/rcgen TLS config (m9).
  - `crates/security` — argon2 `PasswordHasher`, chacha20poly1305 `SecretCipher`, `CredentialStore`, governor `Firewall`, `AuditLog` (m10).
  - `crates/identity` — account model, password auth, SASL `PLAIN`/`LOGIN`/`XOAUTH2`, connection state (m11).
  - `crates/mail` — RFC 5322 message model, `MailStore` + in-memory store, MDA delivery, SMTP parser + server session, inbound DATA collection, outbound relay script, `Mta` local/remote routing, content scanner, STARTTLS policy, mail-flow metrics (m12).
  - `crates/access` — POP3, IMAP, MSA submission sessions, Dovecot Maildir++ mapping, web access, `AccessManager` (m13).
  - `crates/filter` — content-based spam scoring implementing `mail::MessageFilter` (m14).
  - `services/snail_server` — the **composition root**: `Server` wires auth + shared store + `Mta`/filter + access + STARTTLS certs + outbound relay + firewall; async TCP listeners for submission/POP3/IMAP/**inbound-MX** with ctrl-C shutdown; `snail-server` binary. Verified e2e (submit→deliver→retrieve) in-process and over TCP (m15). **m16 wired the full internet MTA**: `outbound.rs` (SMTP client `relay_to` + MX-resolving `relay`), `spool.rs` (durable qmail-style retry queue surviving restart), `worker.rs` (background relay worker with exponential backoff + bounce), `serve_inbound` (no-auth port-25 receiver, no open relay, STARTTLS upgrade via the `SmtpStream` enum), and a firewall-gated accept. A two-server submission→relay→inbound e2e proves it.
- **Still empty scaffold (untracked until populated):** `crates/client` (the FFI client binding — `build.rs`, `bind.rs`, `src/main.rs`), the whole TypeScript side (`packages/{cli,sdk}`, `apps/{desktop-client,web-client}`, `pnpm-workspace.yaml`), and `plugins/`.

What this means for working here:

- In the **empty** areas (TS + `crates/client`), the default task is to *populate* a placeholder, not edit existing logic — a Grep for a symbol there finds nothing yet, and the directory/file names are the design spec.
- The build is **real** — see commands below. A crate joins `[workspace.members]` in the root `Cargo.toml` only once it compiles; keep the workspace green at every step.
- Implementation followed three plans: `docs/plans/2026-05-25-foundation-utilities-telemetry.md` (m0–m8), `docs/plans/2026-05-25-engine-phase-roadmap-m9-m15.md` (m9–m15), and `docs/plans/2026-05-25-m16-mta-internet-wiring.md` (m16 — the internet MTA wiring).
- **Outbound relay & inbound MX are now wired into the running server (m16):** authenticated submission spools remote recipients per-domain to a durable on-disk queue (`<data_dir>/spool`); a background worker resolves MX via `network` and relays them, retrying with exponential backoff and bouncing on exhaustion. The inbound MX listener (default `127.0.0.1:2525`; `:25` in production) accepts external mail to local recipients only — refusing non-local `RCPT` so Snail is never an open relay — advertises and performs STARTTLS, and is rate-limited by `security::Firewall` at accept time. **Remaining hardening (future):** the exchange→IP hop uses the OS resolver (not hickory); SPF/DKIM verification on inbound, greylisting, and per-message size caps are not yet implemented.

## Build, test, lint (Rust workspace)

A Cargo workspace (edition 2024, resolver `"3"`) defined by the root `Cargo.toml`. Shared dependency versions and lint rules live in `[workspace.dependencies]` / `[workspace.lints]`; each member inherits via `[lints] workspace = true` and `<dep>.workspace = true`.

- Build / test everything: `cargo build --workspace` · `cargo test --workspace`
- One crate: `cargo test -p mail` (any of `utilities telemetry network security identity mail access filter snail_server`)
- A single test by name: `cargo test -p telemetry parse_otlp_extracts_endpoint`
- Lint gate (must be clean): `cargo clippy --workspace --all-targets -- -D warnings`
- Format: `cargo fmt --check` (verify) · `cargo fmt` (apply)
- Run the telemetry self-test: `cargo run -p telemetry -- selftest`
- **Run the mail server:** `cargo run -p snail_server --bin snail-server`. Configured via env: `SNAIL_DOMAIN` (local domain), `SNAIL_USERS` (`user:pass,user2:pass2` to provision at boot), `SNAIL_SUBMISSION_ADDR`/`SNAIL_POP3_ADDR`/`SNAIL_IMAP_ADDR`/`SNAIL_INBOUND_ADDR` (bind addrs, default `127.0.0.1:587`/`:110`/`:143`/`:2525`), `SNAIL_SPOOL_DIR` (outbound queue, default `<data_dir>/spool`), `SNAIL_TLS_CERT`/`SNAIL_TLS_KEY` (PEM for STARTTLS; self-signed generated if unset), plus `SNAIL_DATA_DIR`/`SNAIL_LOG`. Logs structured JSON; ctrl-C for graceful shutdown. Outbound relay self-disables (with a warning) if the system DNS resolver can't be built. Run the `#[ignore]`d live test with `cargo test -p snail_server -- --ignored`.

**Error-handling convention:** `thiserror` typed errors in **library** crates, `anyhow` in **binaries** (typed errors convert via `?`). The TypeScript workspace (pnpm) is not set up yet.

## Architecture (by role, derived from the skeleton)

### Foundation — everything builds on these two (implemented)

The base layer; every other crate depends on them. Both are independent of each other (`mail` uses both).

- **`crates/utilities/`** — shared primitives, dependency-free. `error::UtilError` (thiserror; `Config`/`Io`/`Env` variants) + `Result` alias, and `config::Config` (`data_dir`, `log_level`) built via a pure, testable `from_source(getter)` behind `from_env` (reads `SNAIL_DATA_DIR`, `SNAIL_LOG`). `from_source` is pure specifically to avoid edition-2024's now-`unsafe` `std::env::set_var` in tests.
- **`services/telemetry/`** — the observability backbone (a **library**, not a top-layer service). `init(&TelemetryConfig) -> Result<TelemetryGuard>` wires `tracing` → OpenTelemetry: `EnvFilter` + JSON `fmt` layer + OTel layer + an `EventCounter` listener; the guard flushes on drop. Exporters (`data::ExporterKind`): `Stdout` (default) and `Otlp`, both attached with a **simple/synchronous** span processor so `init` needs no async runtime — batching is deferred to the future collector. OTel stack is the **0.27 cohort + tracing-opentelemetry 0.28**, pinned together in `[workspace.dependencies]` (they break in lockstep — verify API against the installed source in `~/.cargo/registry` before changing). The scaffold's `lib/` directory is mounted as the module **`core_api`** (never `telemetry::lib`). Also ships a `telemetry selftest` binary.

### Rust engine

- **Mail core — `crates/mail/`** (implemented; the heart of the server, a **library** — no `main.rs`):
  - `transport/` — `mta.rs` (`Mta` local/remote routing), `smtp.rs` (`SmtpCommand` parser + `SmtpSession` state machine), `inbound.rs` (`InboundCollector` DATA accumulation), `outbound.rs` (`relay_script` client dialog)
  - `storage/` — `mda.rs` (delivery pipeline), `store.rs` (`MailStore` trait + `MemoryMailStore`; `impl MailStore for Arc<T>` so the store is shared between MTA and access servers)
  - `security/` — `certs.rs`, `tls.rs` (STARTTLS policy), `scanner.rs` (content scanner implementing `MessageFilter`)
  - `observability/` — mail-flow metrics; plus the message model in `snailmail.rs`
- **Client access protocols — `crates/access/`** (implemented): how mail clients talk to the server — `imap.rs`, `pop.rs`, `msa.rs` (mail submission agent), `dovecot.rs` (Maildir++ mapping), `web.rs`, coordinated by `manager.rs` (`AccessManager`).
- **Identity / auth — `crates/identity/`** (implemented): `auth.rs`, `oauth.rs` (XOAUTH2), `sals.rs` (**SASL** — `PLAIN`/`LOGIN`), `connect.rs`, `check.rs`, `data.rs`.
- **Security — `crates/security/`**: `encryption/` (`encrypt`, `decrypt`, `salt`, `hash`, `algos/`), `credential/` (`provider`, `manager`, `reciever.rs`), `firewall/` (`allow`, `block`, `track`, `trace`, `pause`), and `audit/` (`audit_logger.rs`). Identity is **not** here — it lives solely in the `crates/identity/` crate.
- **Deliverability — `crates/network/`**: `dns/` with `mx.rs`, `a.rs`, `txt.rs`, `dkim.rs`, `dmark.rs` (**likely DMARC**), `reverse.rs`, `lookup.rs` — the DNS records a mail server needs to be trusted — plus `tls/`.
- **Spam — `crates/filter/`**: `spam/` filtering.
- **Native client — `crates/client/`**: has `build.rs`, `bind.rs`, and a `bindings/` dir → **almost certainly Rust↔JS FFI bindings** for the SDK / clients. Treat changes here as crossing the language boundary.

### Rust binaries — `services/`

- `snail_server/` — the composition root (implemented): `lib.rs` exposes `Server` (wires auth + shared store + `Mta`/filter + access + STARTTLS certs + relay context + firewall) and `install_crypto_provider()`; `serve.rs` has the async listeners (`run`/`serve_submission`/`serve_pop`/`serve_imap`/`serve_inbound`/`serve_inbound_firewalled`) plus the `SmtpStream` STARTTLS-upgrade enum; `outbound.rs` is the SMTP client (`relay_to` + MX-resolving `relay`); `spool.rs` is the durable `OutboundSpool` retry queue; `worker.rs` is the background `relay_due`/`spawn_relay_worker`; `main.rs` is the `snail-server` binary (rustls provider, telemetry, certs, spool, system resolver, users, listeners, ctrl-C). The `tests/relay_e2e.rs` integration test drives submission→relay→inbound across two servers.
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
