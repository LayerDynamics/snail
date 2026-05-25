# m9 — `crates/network` (DNS + TLS) Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use `lore:execute` to implement this plan task-by-task.
> **Scope guard:** Implements milestone m9 of `docs/plans/2026-05-25-engine-phase-roadmap-m9-m15.md`. Do ONLY DNS + TLS for `crates/network`. If you spot work for other crates, note it and continue.

**Goal:** Turn `crates/network` into a working library that resolves the DNS records an email server needs (MX, A/AAAA, TXT, DKIM, DMARC, PTR) and builds/uses TLS (rustls) for secured connections — fully tested, clippy/fmt-clean, and depended-on-able by the future mail engine.

**Architecture:** A `DnsResolver` **trait** (async) is the public contract; a `HickoryResolver` implements it over `hickory-resolver`. All hickory-record → typed-struct conversion is **pure** and unit-tested offline; live resolution is exercised only by `#[ignore]`d integration tests. TLS is a `TlsConfig` (PEM → rustls `ServerConfig`/`ClientConfig`) plus thin `tokio-rustls` accept/connect stream helpers.

**Tech Stack:** Rust edition 2024. `hickory-resolver` (DNS) + `tokio` (first async runtime in the workspace) + `rustls` / `tokio-rustls` / `rustls-pemfile` (TLS). `thiserror` for the library error type.

**Practices:** TDD (red→green) · typed-interfaces-first + contract-first · `cargo clippy --workspace --all-targets -- -D warnings` + `cargo fmt --check` gate per task · `thiserror` typed errors (library crate).

**Required skills:** none.

---

## External-API reality (READ FIRST — lesson carried from m6)

`hickory-resolver` and the `rustls` stack change APIs across minor versions, exactly like the OpenTelemetry cohort did in m6. The code blocks below are **best-effort against the pinned versions**; do not trust them blindly. In the tasks that touch these crates (T0 resolve, T3 hickory impl, T5 TLS), there is an explicit **verify-against-installed-source** step:

```bash
# find the unpacked source cargo actually resolved, then read the real API:
find ~/.cargo/registry/src -maxdepth 1 -type d -name 'index.crates.io-*'
ls ~/.cargo/registry/src/index.crates.io-*/hickory-resolver-*/src
```

Read the resolved crate's real signatures (`AsyncResolver`/`TokioAsyncResolver`, `lookup_ip`, `mx_lookup`, `txt_lookup`, `reverse_lookup`; rustls `ServerConfig::builder()`, `tokio_rustls::TlsAcceptor`) and adjust the code to match. **Never stub or comment out an integration path to make it compile** — fix it to the real API.

**Pinned cohort (root `[workspace.dependencies]`):**
```toml
tokio = { version = "1", features = ["rt-multi-thread", "net", "io-util", "macros", "time"] }
hickory-resolver = "0.24"
rustls = "0.23"
tokio-rustls = "0.26"
rustls-pemfile = "2"
network = { path = "crates/network" }
```
If `hickory-resolver = "0.24"` resolves to an API materially different from the blocks here (e.g. a 0.25 was pulled), pin the exact `0.24.x` that matches, or adapt the code — decide in T0 once `cargo tree -p hickory-resolver` shows the resolved version.

---

## Task 0: Workspace deps + `network` crate bootstrap

Config task (no business logic → no TDD). Establishes the crate as a compiling library member and proves the dep cohort resolves before any API-specific code is written.

**Files:**
- Modify: root `Cargo.toml` (`[workspace.members]` + `[workspace.dependencies]`)
- Create: `crates/network/Cargo.toml`
- Delete: `crates/network/src/main.rs`; Create `crates/network/src/lib.rs`
- Create minimal module files so it compiles (filled in later tasks)

**Step 1:** Add the pinned external deps above to root `[workspace.dependencies]` plus `network = { path = "crates/network" }`. Do **not** add `"crates/network"` to `[workspace.members]` yet, and run no `cargo` command until Step 4 — a declared member with no (valid) manifest breaks every `cargo` invocation (the m1 trap). Create the crate files first.

**Step 2:** `crates/network/Cargo.toml`:
```toml
[package]
name = "network"
version.workspace = true
edition.workspace = true
rust-version.workspace = true
publish = false

[dependencies]
utilities.workspace = true
telemetry.workspace = true
thiserror.workspace = true
tokio.workspace = true
hickory-resolver.workspace = true
rustls.workspace = true
tokio-rustls.workspace = true
rustls-pemfile.workspace = true

[lints]
workspace = true
```
> The workspace `tokio` features (`rt-multi-thread`, `macros`, …) already cover `#[tokio::test]`, so no separate `[dev-dependencies]` tokio entry is needed. `rcgen` is added as a dev-dependency in Task 4.

**Step 3:** Delete `crates/network/src/main.rs`. Create `crates/network/src/lib.rs`:
```rust
//! DNS resolution and TLS configuration for the Snail mail server.
//!
//! `dns` exposes a [`dns::DnsResolver`] trait (typed MX/A/TXT/DKIM/DMARC/PTR
//! lookups) with a hickory-backed implementation; `tls` builds rustls configs
//! and wraps tokio-rustls accept/connect.

pub mod dns;
pub mod error;
pub mod tls;

pub use error::{NetworkError, Result};
```
Create `crates/network/src/error.rs`:
```rust
//! Error type for the network layer.

use thiserror::Error;

/// Errors produced by DNS resolution and TLS setup.
#[derive(Debug, Error)]
pub enum NetworkError {
    /// A DNS lookup failed.
    #[error("dns lookup failed for `{name}`: {reason}")]
    Resolve {
        /// The queried name.
        name: String,
        /// Underlying cause.
        reason: String,
    },
    /// A DNS record could not be parsed into the expected shape.
    #[error("malformed {kind} record: {reason}")]
    Record {
        /// Record kind (e.g. `DKIM`, `DMARC`).
        kind: String,
        /// What was wrong.
        reason: String,
    },
    /// A TLS configuration error (cert/key load or builder).
    #[error("tls configuration error: {0}")]
    Tls(String),
    /// An I/O error (PEM file read, socket).
    #[error("i/o error: {0}")]
    Io(#[from] std::io::Error),
}

/// Convenience alias.
pub type Result<T> = std::result::Result<T, NetworkError>;
```
Create `crates/network/src/dns/mod.rs` and `crates/network/src/tls/mod.rs` each with just a `//!` purpose doc comment (empty modules, filled in later tasks). The T0 `lib.rs` is exactly as written above: all three `pub mod`s are declared (the empty `dns`/`tls` files satisfy them) and only `error` is re-exported, since it is the only module with real items yet.

**Step 4 — add the member, then resolve + verify cohort:** Now that `crates/network/Cargo.toml` and `src/lib.rs` exist, add `"crates/network"` to root `[workspace.members]`, then:
```bash
cargo build -p network
cargo tree -p hickory-resolver -p rustls -p tokio-rustls --depth 0
```
→ Expected: PASS. Record the resolved `hickory-resolver` version; if it is not a `0.24.x`, pin the exact version that matches the T3 code (see "External-API reality").

**Step 5 — gate + commit:**
```bash
cargo fmt --check && cargo clippy -p network --all-targets -- -D warnings
git add Cargo.toml Cargo.lock crates/network && git commit -m "chore(network): bootstrap DNS+TLS library crate in workspace"
```

---

## Task 1: DNS record types + DKIM/DMARC parsing — TDD

The pure core: typed record structs, and parsers for the structured TXT records (DKIM, DMARC) — fully offline-testable.

**Files:** `crates/network/src/dns/{mx,a,txt,dkim,dmark,reverse}.rs`, wired via `dns/mod.rs`.

**Step 1 — failing tests first** (in `dkim.rs` and `dmark.rs`):
```rust
// dkim.rs
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn parses_rsa_dkim_record() {
        let r = DkimRecord::parse("v=DKIM1; k=rsa; p=MIGfMA0GCSq").unwrap();
        assert_eq!(r.version.as_deref(), Some("DKIM1"));
        assert_eq!(r.key_type.as_deref(), Some("rsa"));
        assert_eq!(r.public_key, "MIGfMA0GCSq");
    }
    #[test]
    fn rejects_dkim_without_public_key() {
        assert!(DkimRecord::parse("v=DKIM1; k=rsa").is_err());
    }
}
```
```rust
// dmark.rs  (DMARC — note the filename spelling)
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn parses_reject_policy_with_rua() {
        let r = DmarcRecord::parse("v=DMARC1; p=reject; rua=mailto:dmarc@example.com").unwrap();
        assert_eq!(r.policy, DmarcPolicy::Reject);
        assert_eq!(r.rua.as_deref(), Some("mailto:dmarc@example.com"));
    }
    #[test]
    fn rejects_non_dmarc_txt() {
        assert!(DmarcRecord::parse("v=spf1 -all").is_err());
    }
}
```

**Step 2:** `cargo test -p network` → Expected: FAIL (types undefined).

**Step 3 — implement.** Each record file defines a typed struct; DKIM/DMARC add a `parse(&str)` over the `tag=value; …` TXT grammar. A shared tiny tag-map helper lives in `txt.rs`:
```rust
// txt.rs
//! TXT record value + the `tag=value; …` parser shared by DKIM/DMARC.
use std::collections::BTreeMap;

/// A raw TXT record (one or more concatenated character-strings).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TxtRecord(pub String);

/// Parse a `tag=value; tag=value` string into an ordered map (values trimmed).
#[must_use]
pub fn parse_tag_map(raw: &str) -> BTreeMap<String, String> {
    raw.split(';')
        .filter_map(|kv| kv.split_once('='))
        .map(|(k, v)| (k.trim().to_string(), v.trim().to_string()))
        .filter(|(k, _)| !k.is_empty())
        .collect()
}
```
```rust
// dkim.rs
//! DKIM key record (a TXT record at `<selector>._domainkey.<domain>`).
use crate::dns::txt::parse_tag_map;
use crate::error::{NetworkError, Result};

/// A parsed DKIM public-key record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DkimRecord {
    /// `v=` (usually `DKIM1`).
    pub version: Option<String>,
    /// `k=` key type (e.g. `rsa`, `ed25519`).
    pub key_type: Option<String>,
    /// `p=` base64 public key (required).
    pub public_key: String,
}

impl DkimRecord {
    /// Parse a DKIM TXT record body.
    ///
    /// # Errors
    /// [`NetworkError::Record`] if the required `p=` tag is missing.
    pub fn parse(raw: &str) -> Result<Self> {
        let tags = parse_tag_map(raw);
        let public_key = tags.get("p").cloned().ok_or_else(|| NetworkError::Record {
            kind: "DKIM".into(),
            reason: "missing public key (p=)".into(),
        })?;
        Ok(Self {
            version: tags.get("v").cloned(),
            key_type: tags.get("k").cloned(),
            public_key,
        })
    }
}
```
```rust
// dmark.rs
//! DMARC policy record (a TXT record at `_dmarc.<domain>`). File name keeps the
//! scaffold spelling `dmark`; the type is `DmarcRecord`.
use crate::dns::txt::parse_tag_map;
use crate::error::{NetworkError, Result};

/// DMARC `p=` policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DmarcPolicy {
    /// `none`
    None,
    /// `quarantine`
    Quarantine,
    /// `reject`
    Reject,
}

/// A parsed DMARC record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DmarcRecord {
    /// `p=` policy (required; identifies the record as DMARC).
    pub policy: DmarcPolicy,
    /// `rua=` aggregate-report URI.
    pub rua: Option<String>,
}

impl DmarcRecord {
    /// Parse a DMARC TXT record body.
    ///
    /// # Errors
    /// [`NetworkError::Record`] if `v=DMARC1` / `p=` are absent or `p=` is unknown.
    pub fn parse(raw: &str) -> Result<Self> {
        let tags = parse_tag_map(raw);
        if tags.get("v").map(String::as_str) != Some("DMARC1") {
            return Err(NetworkError::Record { kind: "DMARC".into(), reason: "not a DMARC1 record".into() });
        }
        let policy = match tags.get("p").map(String::as_str) {
            Some("none") => DmarcPolicy::None,
            Some("quarantine") => DmarcPolicy::Quarantine,
            Some("reject") => DmarcPolicy::Reject,
            other => return Err(NetworkError::Record { kind: "DMARC".into(), reason: format!("invalid policy `{}`", other.unwrap_or("<missing>")) }),
        };
        Ok(Self { policy, rua: tags.get("rua").cloned() })
    }
}
```
```rust
// mx.rs
//! MX record: a mail-exchange host with a preference.
/// A mail-exchange record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MxRecord {
    /// Lower preference = higher priority.
    pub preference: u16,
    /// Exchange hostname (trailing dot stripped).
    pub exchange: String,
}
```
```rust
// a.rs
//! A/AAAA address record.
use std::net::IpAddr;
/// A host address record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AddressRecord(pub IpAddr);
```
```rust
// reverse.rs
//! PTR (reverse-DNS) record.
/// A reverse-DNS name for an IP.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PtrRecord(pub String);
```
Wire them in `dns/mod.rs`: `pub mod a; pub mod dkim; pub mod dmark; pub mod mx; pub mod reverse; pub mod txt;` and re-export the record types.

**Step 4:** `cargo test -p network` → Expected: PASS (DKIM/DMARC parser tests).

**Step 5 — gate + commit** (`feat(network): DNS record types + DKIM/DMARC parsers`).

---

## Task 2: `DnsResolver` trait + record-mapping contract — TDD

Lock the public async contract and the pure hickory→typed mapping (the mapping is unit-tested without touching the network).

**Files:** `crates/network/src/dns/lookup.rs` (trait), `crates/network/src/dns/mapping.rs` (pure converters), `dns/mod.rs`.

**Step 1 — define the trait (contract-first), then failing mapping tests.** The trait:
```rust
// lookup.rs
use async_trait::async_trait;          // add async-trait to deps in this task
use crate::dns::{AddressRecord, DkimRecord, DmarcRecord, MxRecord, PtrRecord, TxtRecord};
use crate::error::Result;
use std::net::IpAddr;

/// Async DNS resolution contract used across Snail. Implemented by `HickoryResolver`
/// (live) and by test doubles. Implementers provide the four *raw* lookups; the
/// DKIM/DMARC convenience methods are **default methods** built on `lookup_txt`.
#[async_trait]
pub trait DnsResolver: Send + Sync {
    // --- required: raw lookups an implementation must provide ---
    async fn lookup_mx(&self, domain: &str) -> Result<Vec<MxRecord>>;
    /// Resolve a host to its addresses (A **and** AAAA), matching hickory's `lookup_ip`.
    async fn lookup_ip(&self, host: &str) -> Result<Vec<AddressRecord>>;
    async fn lookup_txt(&self, name: &str) -> Result<Vec<TxtRecord>>;
    async fn reverse_lookup(&self, ip: IpAddr) -> Result<Vec<PtrRecord>>;

    // --- default: convenience lookups (DO NOT override — tested via the defaults) ---
    /// Fetch `<selector>._domainkey.<domain>` TXT and parse the first valid DKIM record.
    async fn lookup_dkim(&self, selector: &str, domain: &str) -> Result<DkimRecord> {
        let name = format!("{selector}._domainkey.{domain}");
        let txts = self.lookup_txt(&name).await?;
        txts.iter()
            .find_map(|t| DkimRecord::parse(&t.0).ok())
            .ok_or_else(|| NetworkError::Record {
                kind: "DKIM".into(),
                reason: format!("no parseable DKIM record at {name}"),
            })
    }
    /// Fetch `_dmarc.<domain>` TXT and parse the first `v=DMARC1` record (multiple TXTs are legal).
    async fn lookup_dmarc(&self, domain: &str) -> Result<DmarcRecord> {
        let name = format!("_dmarc.{domain}");
        let txts = self.lookup_txt(&name).await?;
        txts.iter()
            .find_map(|t| DmarcRecord::parse(&t.0).ok())
            .ok_or_else(|| NetworkError::Record {
                kind: "DMARC".into(),
                reason: format!("no parseable DMARC record at {name}"),
            })
    }
}
```
> Add `async-trait = "0.1"` to `[workspace.dependencies]` and `async-trait.workspace = true` to the crate in this task (first use). `lookup_dkim`/`lookup_dmarc` are **default trait methods** — implementations must NOT override them, so the test exercises the real routing+parsing, not a mock's canned value.

Failing test in `mapping.rs` — a hand-written mock implements **only** the four required lookups (returning canned TXT for the expected `_domainkey`/`_dmarc` names); the test then calls the **default** `lookup_dkim`/`lookup_dmarc` and asserts they construct the right query name and parse correctly (fully offline):
```rust
#[cfg(test)]
mod tests {
    use super::*;
    // struct MockResolver { txt: BTreeMap<String, Vec<TxtRecord>> }
    // impl DnsResolver for MockResolver { /* only lookup_mx/lookup_ip/lookup_txt/reverse_lookup */ }
    // #[tokio::test] async fn lookup_dkim_queries_domainkey_and_parses() { ... }
    // #[tokio::test] async fn lookup_dmarc_picks_first_dmarc1_among_multiple_txt() { ... }
}
```

**Step 2:** `cargo test -p network` → FAIL.

**Step 3 — implement** the trait, the dkim/dmarc helper logic, and `mapping.rs` pure converters (`hickory MX → MxRecord`, strip trailing dots, etc.). Keep converters as free functions taking hickory types so they can be unit-tested by constructing hickory records directly.

**Step 4:** `cargo test -p network` → PASS. **Step 5 — gate + commit** (`feat(network): DnsResolver trait + pure record mapping`).

---

## Task 3: `HickoryResolver` implementation + live integration test

**Files:** `crates/network/src/dns/manager.rs` (the `HickoryResolver` + a `DnsManager` wrapper), `dns/mod.rs`.

**Step 1 — verify the hickory API against installed source** (per "External-API reality"): read `hickory-resolver-*/src/lib.rs` and the resolver/lookup modules for the real constructor (`TokioAsyncResolver::tokio_from_system_conf()` or `AsyncResolver::tokio(...)`), and the `mx_lookup`/`txt_lookup`/`lookup_ip` (combined A+AAAA)/`reverse_lookup` method names + return iterators.

**Step 2 — implement** `HickoryResolver` over the verified API, mapping hickory records via T2's pure converters and hickory errors into `NetworkError::Resolve`. Implement `DnsResolver` for it.

**Step 3 — live integration test, `#[ignore]`d** (does not run in normal `cargo test`):
```rust
#[tokio::test]
#[ignore = "hits live DNS; run with --ignored"]
async fn resolves_real_mx() {
    let r = HickoryResolver::from_system().unwrap();
    let mx = r.lookup_mx("gmail.com").await.unwrap();
    assert!(!mx.is_empty());
}
```

**Step 4 — verify:** `cargo test -p network` (passes; live test skipped) and `cargo test -p network -- --ignored` (run once manually with network to confirm live resolution). **Step 5 — gate + commit** (`feat(network): hickory-backed DnsResolver implementation`).

---

## Task 4: TLS config + tokio-rustls stream helpers — TDD + loopback

Scope chosen: **config builders AND stream helpers.**

**Files:** `crates/network/src/tls/mod.rs` (+ `tls/config.rs`, `tls/stream.rs` if it reads cleaner).

**Step 1 — verify the rustls/tokio-rustls API** against installed source (`rustls-0.23`, `tokio-rustls-0.26`): `ServerConfig::builder().with_no_client_auth().with_single_cert(certs, key)`, `rustls_pemfile::certs`/`private_key`, `tokio_rustls::{TlsAcceptor, TlsConnector}`, the `CertificateDer`/`PrivateKeyDer` types.

**Step 2 — failing tests first** (add `rcgen = "0.13"` to `[workspace.dependencies]` and as a network `[dev-dependencies]` — generate certs in-process, no committed fixture, no expiry):
- `TlsConfig::server_from_pem(cert_pem, key_pem)` builds a `ServerConfig` from PEM. The test generates a self-signed cert+key with `rcgen`, serializes to PEM, and feeds it in.
- A loopback integration test: generate a self-signed cert via `rcgen` with SAN `localhost`; build the server config from it and a client config whose root store trusts that generated cert; bind a `TcpListener`, `TlsAcceptor::accept` one side while `TlsConnector::connect` (SNI = `localhost`) drives the other; write/read a byte through the encrypted stream. `#[tokio::test]` — local sockets only, safe to run by default.

**Step 3 — implement** `TlsConfig` (server: PEM→`ServerConfig`; client: root store→`ClientConfig`) and `accept`/`connect` helpers wrapping `tokio_rustls::{TlsAcceptor, TlsConnector}`. Map rustls errors into `NetworkError::Tls`.

**Step 4:** `cargo test -p network` → PASS (config + loopback handshake). **Step 5 — gate + commit** (`feat(network): rustls TlsConfig + tokio-rustls accept/connect helpers`).

---

## Task 5: Public surface + workspace gate + finalize

**Files:** `crates/network/src/lib.rs`, `dns/mod.rs`, `tls/mod.rs`.

**Step 1 — lock the re-exports** in `lib.rs`: `pub use dns::{DnsResolver, HickoryResolver, DnsManager, MxRecord, AddressRecord, TxtRecord, DkimRecord, DmarcRecord, DmarcPolicy, PtrRecord};` and `pub use tls::TlsConfig;` (and the stream helpers). Ensure module docs are present.

**Step 2 — full workspace verification:**
```bash
cargo build
cargo test                       # network unit + loopback; live DNS skipped
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --check
```
→ all clean. **Step 3 — commit** (`feat(network): finalize DNS+TLS public surface`).

---

## Definition of done

- `network` is a workspace member library; `src/main.rs` is gone.
- `cargo test` passes (DKIM/DMARC parsers, mapping with mock resolver, TLS config + loopback handshake); the live-DNS test passes under `-- --ignored`.
- `DnsResolver` trait + `HickoryResolver` resolve MX/A/TXT/DKIM/DMARC/PTR; raw DKIM/DMARC records are exposed for m12.
- `TlsConfig` + accept/connect helpers build and complete a loopback TLS handshake.
- `cargo clippy --workspace --all-targets -- -D warnings` + `cargo fmt --check` clean.

## Notes for the next milestone

- The DKIM/DMARC **signing & verification** logic (not just record lookup) is deferred to m12 per the roadmap — m9 only exposes the raw records.
- `async-trait` and `tokio` are now in the workspace; downstream crates (mail transport, access) build on this runtime.
