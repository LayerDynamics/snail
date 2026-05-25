# Snail Engine Phase Roadmap (m9–m15)

> **For Claude:** This is a **roadmap**, not a directly-executable plan. Each milestone below is a whole subsystem larger than the entire m0–m8 foundation. **Before coding any milestone, run `/lore:plan` for that subsystem to produce its own detailed, TDD-able plan, then `lore:execute` it.** Do not start coding a milestone directly from this file.
> **Scope guard:** This phase completes the **Rust engine**. The TypeScript side (`packages/`, `apps/`), `crates/client` (FFI), and `plugins/` are out of scope here — they belong to a later phase.

**Goal:** Take Snail from "working foundation" (utilities + telemetry + mail wiring proof) to a **runnable, end-to-end mail server**: it resolves DNS, secures connections, authenticates users, transfers and stores mail, serves it over IMAP/POP/MSA/web, filters spam, and boots as one composed process.

**Architecture:** Seven subsystem crates built bottom-up in dependency order. Each is a library depended on by those above it; `services/snail_server` is the composition root that wires them into a process. The two foundation pillars (`utilities`, `telemetry`) underpin all of them.

**Tech Stack:** Rust (edition 2024, cargo 1.95). External crates per subsystem are chosen in each subsystem's own plan (candidates noted below).

**Practices (mandated for every milestone, carried from m0–m8):** TDD (red→green) · typed-interfaces-first + contract-first (lock the public `lib.rs` surface before internals) · `cargo clippy --workspace --all-targets -- -D warnings` + `cargo fmt --check` gate per task · **`thiserror` typed errors in libraries, `anyhow` in binaries**.

**Required skills:** `/lore:plan` per subsystem before execution; `lore:execute` for each resulting plan.

---

## Dependency order & milestone map

```
foundation: utilities ── telemetry        (m0–m8, DONE)
                 │            │
   m9  network ──┤            │   DNS (MX/A/TXT/DKIM/DMARC/reverse) + TLS
   m10 security ─┤            │   crypto, credentials, firewall, audit
                 ▼            ▼
   m11 identity  ───────────────  auth, SASL, oauth        (needs security)
   m12 mail engine ─────────────  message model, transport, storage
                                  (needs network + security)
   m13 access ──────────────────  IMAP/POP/MSA/web         (needs identity + mail)
   m14 filter ──────────────────  spam scoring             (needs mail; see note)
   m15 snail_server ────────────  composition root         (needs all of the above)
```

m9 and m10 are independent (both depend only on the foundation) and may be built in either order or in parallel sessions. Everything else is strictly ordered as drawn.

## Recurring structural notes (apply in the milestone that first touches each crate)

A crate can only be a dependency if it has a **library root** (`src/lib.rs`). The scaffold left these in non-library shapes — fix as part of each crate's milestone, exactly as m1 converted `utilities` from `main.rs` to `lib.rs`:

| Crate | Scaffold root today | Action |
|-------|--------------------|--------|
| `network` | `src/main.rs` | replace with `src/lib.rs` |
| `filter` | `src/main.rs` | `src/lib.rs` (lib consumed by the mail pipeline) |
| `mail` | `src/main.rs` (wiring proof) | add `src/lib.rs` (the engine); retire or repurpose the proof bin |
| `identity` | `src/mod.rs` only | establish `src/lib.rs` (the `mod.rs` is not a crate root) |
| `access` | `src/mod.rs` only | establish `src/lib.rs` |
| `security` | `src/lib.rs` + `src/main.rs` | already a lib; drop the vestigial `main.rs` |

Also recurring: a crate joins `[workspace.members]` (and gets its `telemetry`/`utilities`/sibling path-deps) **only in the milestone that makes it compile** — keep the workspace green at every commit. Each crate inherits `[lints] workspace = true` and `<dep>.workspace = true`; new external deps are pinned once in the root `[workspace.dependencies]`.

---

## m9 — `crates/network` (DNS + TLS)

**Scope:** The deliverability layer. DNS records an email server must read/serve: `mx.rs` (mail routing), `a.rs` (host A/AAAA), `txt.rs` (SPF/policy TXT), `dkim.rs` (DKIM key records by selector), `dmark.rs` (**DMARC** — note the spelling), `reverse.rs` (PTR for sender validation), `lookup.rs` (generic resolver entry), `manager.rs` (orchestration). Plus `tls/` — TLS config/connector/acceptor for secured connections.

**Public surface (contract to lock first):** an async `DnsResolver`/`DnsManager` with `lookup_mx`, `lookup_a`, `lookup_txt`, `lookup_dkim(selector, domain)`, `lookup_dmarc(domain)`, `reverse_lookup(ip)`, each returning typed record structs; a `TlsConfig` builder yielding a server acceptor and client connector.

**Depends on:** `utilities`, `telemetry`. **External candidates (decide in m9's plan):** `hickory-resolver` (DNS), `rustls` + `tokio-rustls` (TLS), an async runtime (`tokio`).

**Acceptance:** record types parse correctly (unit tests against fixture responses); resolver returns expected records against a mock/integration resolver; TLS config builds a working acceptor+connector; gate clean.

## m10 — `crates/security` (encryption · credential · firewall · audit)

**Scope:** `encryption/` — password hashing (`hash.rs`, `salt.rs`), symmetric encryption of stored secrets (`encrypt.rs`/`decrypt.rs`), algorithm registry (`algos/`), `manager.rs`. `credential/` — credential storage and retrieval (`provider.rs`, `manager.rs`, `reciever.rs` — note: "receiver"). `firewall/` — connection policy: `allow.rs`/`block.rs`/`track.rs`/`trace.rs`/`pause.rs`, rate limiting and IP filtering for the public-facing server. `audit/` — security event logging (`audit_logger.rs`).

**Public surface:** `PasswordHasher` (hash/verify), `SecretCipher` (encrypt/decrypt), `CredentialStore`, `Firewall` (check/allow/block/track an address), `AuditLog` (record security events).

**Depends on:** `utilities`, `telemetry`. **External candidates:** `argon2` (password hashing), a RustCrypto AEAD (`aes-gcm` or `chacha20poly1305`) for secret encryption.

**Acceptance:** hash↔verify and encrypt↔decrypt round-trip; firewall allow/block/rate-limit decisions tested; audit log records and serializes events; gate clean.

## m11 — `crates/identity` (auth · SASL · oauth)

**Scope:** Authentication. `auth.rs` (verify credentials → identity), `sals.rs` (**SASL** mechanisms — PLAIN/LOGIN/CRAM/SCRAM used by SMTP/IMAP/POP), `oauth.rs` (XOAUTH2 for modern clients), `connect.rs` (per-connection auth state), `check.rs` (credential checks), `data.rs` (the `Identity`/`Account` model).

**Public surface:** `Authenticator::authenticate(credentials) -> Result<Identity>`, a SASL mechanism dispatcher, OAuth token validation, the `Identity` type.

**Depends on:** `security` (credential store + password hashing), `utilities`, `telemetry`.

**Types-location ripple:** `data.rs` defines `Identity`/`Account`. If m12 extracts a shared `crates/core` types crate (its open decision), these likely belong there too — m11's plan should flag the question so the identity types aren't stranded in `identity` and moved later.

**Acceptance:** PLAIN/LOGIN SASL round-trip against a seeded `CredentialStore`; bad credentials rejected; an OAuth token path validated against a stub issuer; gate clean.

## m12 — `crates/mail` engine (message model · transport · storage)

**The largest milestone — its own plan will likely sub-split into several sessions.**

**Scope:** `snailmail.rs` — the core `Message`/envelope model (RFC 5322 headers + MIME body). `transport/` — `mta.rs` (mail transfer agent), `smtp.rs` (SMTP server for inbound + client for outbound), `inbound.rs`/`outbound.rs` (receive/send pipelines). `storage/` — `mda.rs` (mail delivery agent: deliver a message to a mailbox), `store.rs` (mailbox persistence, e.g. Maildir). `security/` — `certs.rs`, `tls.rs` (SMTP TLS), `scanner.rs` (content pre-scan). `observability/` — mail-specific metrics over `telemetry`.

**Public surface:** the `Message` type; an SMTP `Mta` (inbound server + outbound sender); a `MailStore` (`deliver`, `fetch`, `list`); a **`MessageFilter` trait with a `NullFilter` no-op default**; the delivery pipeline, generic over `impl MessageFilter`, that ties scan → filter → deliver.

**Depends on:** `network` (MX lookup for outbound routing), `security` (TLS/certs, secret encryption, scanner), `utilities`, `telemetry`. Submission auth integrates via `identity` at the access layer, not here.

**Cycle-avoidance contract (owned by m12):** `mail` defines the `MessageFilter` trait + the `NullFilter` default and makes the delivery pipeline generic over `impl MessageFilter`. `crates/filter` (m14) *implements* that trait; `snail_server` (m15) *injects* the concrete filter. `mail` must never depend on `filter`. These three pieces must exist in m12 or m14 has nothing to implement and m15 nothing to inject.

**Open decision (resurfaced from the foundation):** where the shared `Message`/`Mailbox`/`Domain`/`Account` types live. Options: keep them in `mail` and let `access`/`filter` depend on `mail`, **or** extract a light `crates/core` (or `crates/types`) crate beneath `mail`. Resolve at the start of m12's plan — it affects m13 and m14 (and m11's identity types, see below).

**DKIM/SPF/DMARC signing & verification home (decide in m12's plan):** m9 provides only the DNS *record lookups* (DKIM keys, DMARC/SPF policy in TXT). The *outbound signing* and *inbound verification/alignment* (computing auth-results) logic is not yet placed — it most naturally lives with `transport` here in `mail`, consuming m9's lookups. m12's plan picks the home; m9's public surface must expose the raw records that logic will need.

**External candidates:** `mail-parser`/`mail-builder` or hand-rolled RFC 5322 + MIME; `tokio` for the SMTP servers.

**Acceptance:** build and parse a Message round-trip; SMTP inbound accepts a session and persists via MDA→store; outbound resolves MX and connects; store fetch returns delivered mail; gate clean.

## m13 — `crates/access` (IMAP · POP · MSA · web)

**Scope:** Client-facing access protocols. `imap.rs` (IMAP4 server), `pop.rs` (POP3 server), `msa.rs` (Mail Submission Agent — authenticated SMTP submission on 587), `dovecot.rs` (Dovecot interop/compat layer), `web.rs` (HTTP/webmail access API), `manager.rs` (binds and runs the protocol servers).

**Public surface:** `ImapServer`, `Pop3Server`, `Msa`, `WebAccess`, and an `AccessManager` that owns their listeners and lifecycle.

**Depends on:** `identity` (authenticate every session), `mail` (`MailStore` for IMAP/POP reads; MSA injects into transport), `security` (TLS), `utilities`, `telemetry`.

**First decision in m13's plan:** define what `dovecot.rs` actually is — anywhere from a thin compat shim to a full Dovecot auth-backend or wire-protocol integration. This is the highest-variance unknown in the milestone and can materially change its size; scope it explicitly before estimating.

**Acceptance:** IMAP and POP sessions authenticate and list/fetch messages from a seeded store; MSA accepts an authenticated submission and hands it to transport; gate clean.

## m14 — `crates/filter` (spam)

**Scope:** Spam analysis over the `Message` model — scoring, classification, and blocklist checks. `spam/` holds the rules/heuristics (and any Bayesian/RBL logic).

**Public surface:** `SpamFilter::score(&Message) -> Verdict` (score + classification), suitable to plug into the delivery pipeline.

**Depends on:** `mail` (the `Message` model), `network` (DNS/RBL blocklist lookups), `utilities`, `telemetry`.

**Cycle-avoidance note:** the inbound delivery pipeline must call the filter, but `mail` must **not** depend on `filter`. Use dependency inversion: define a `MessageFilter` trait in `mail`, have `filter` implement it, and wire the concrete filter in at the `snail_server` composition root (m15). This keeps the graph acyclic (`filter → mail`, `snail_server → both`).

**Acceptance:** scores known-spam vs known-ham fixtures on the correct side of the threshold; an RBL lookup integrates via `network`; the `MessageFilter` impl satisfies the `mail` trait; gate clean.

## m15 — `services/snail_server` (composition root)

**Scope:** The main server binary (`src/` is currently empty). Loads `utilities::Config`, calls `telemetry::init`, constructs the DNS resolver (`network`), security services (`security`), the `Authenticator` (`identity`), the mail engine (`mail`), injects the `SpamFilter` into delivery, starts the access protocol servers (`access`), and manages process lifecycle: startup ordering, signal handling, graceful shutdown, and binding all configured listeners.

**Public surface:** a binary (`main.rs`); optionally a thin `lib.rs` holding the composition/bootstrap logic so it is testable.

**Depends on:** every crate above.

**TLS crypto-provider (decide and install here):** rustls 0.23 needs a process-default `CryptoProvider`. Today only `aws-lc-rs` is in the dependency graph (via `network`/`rustls` defaults), so `network::TlsConfig`'s builders work implicitly — but the moment m12 pulls a mail crate that also enables `ring`, `ServerConfig::builder()` will **panic at runtime** ("multiple providers"). Install it once at startup here, before any TLS config is built — `rustls::crypto::aws_lc_rs::default_provider().install_default().ok();` — or switch `network::TlsConfig` to `builder_with_provider(...)` so the choice is locked at the library level (m9 left it implicit).

**Acceptance (firm — this is why snail_server exists):** server boots and binds every configured listener (SMTP/IMAP/POP/MSA/web); each accepts a connection; the **end-to-end path works** — authenticated submission via MSA/SMTP → delivery (MDA→store, filter applied) → retrieval of that message via IMAP; graceful shutdown on SIGTERM flushes telemetry; gate clean. The e2e path is not optional; if it proves too large to land with m15, split it into an explicit follow-up milestone rather than weakening this bar.

---

## How to use this roadmap

1. Pick the next milestone in dependency order (m9, or m10 in parallel).
2. Run `/lore:plan` scoped to **that subsystem only** — it produces the detailed, TDD-able plan (with full code, like the m0–m8 foundation plan).
3. `lore:execute` that plan; commit per task behind the gate.
4. Return here for the next milestone.

## Deferred to a later phase (explicitly OUT of scope)

- `crates/client` (Rust↔JS FFI: `build.rs`/`bind.rs`/`bindings/`).
- The TypeScript/pnpm workspace: `packages/cli`, `packages/sdk`, `apps/web-client`, `apps/desktop-client`, `pnpm-workspace.yaml`.
- `plugins/` (the plugin integration service).
- Production deployment wiring (`containers/`, `tools/{deploy,install,wizard}`).
