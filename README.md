# Snail

**A self-hosted, privacy-first email server you own.** Snail lets an individual run
their own mail — sending, receiving, and retrieval — without handing the private
details of their life to a large provider. It aims to be compatible with as many
email hosts and clients as reasonably possible, to deploy as cheaply and easily as
possible, and to be extensible through a plugin integration service.

A **custom domain is required** — there is intentionally no built-in
`@<company>.com`. Your domain, your server, your mail.

The engine is **Rust**; the tooling, SDK, and clients are **TypeScript**.

## Status

The **Rust engine is complete and runs as a full internet MTA**: it submits,
relays, receives, and serves mail end to end — now with **authenticated outbound
TLS** (DANE and MTA-STS) and **inbound sender authentication** (SPF, DKIM, DMARC) —
and is covered by the workspace test suite (clippy `-D warnings` + `rustfmt` clean).

The **TypeScript tooling and clients** (operator CLI, SDK, web/desktop clients) and
the native Rust↔JS FFI client binding (`crates/client`) are **still in progress**.

## What works today (the Rust engine)

- **Send & receive over the internet** — authenticated submission (SMTP, `:587`),
  outbound relay to remote MX with DNS/MX resolution and a **durable on-disk retry
  queue** (exponential backoff, DSN bounce to the sender on exhaustion, survives
  restart), and an inbound MX receiver (`:25`).
- **Retrieval** — POP3 (`:110`) and IMAP (`:143`) over a shared mail store, with
  Dovecot-style Maildir++ path mapping.
- **Encrypted in transit** — **STARTTLS/STLS** on submission, POP3, and IMAP, and
  STARTTLS on outbound relay. When a certificate is configured the server **refuses
  plaintext credentials** until the connection is encrypted, so logins never cross
  the wire in the clear.
- **Authenticated outbound TLS** — optional **DANE** (RFC 7672, DNSSEC-validated
  TLSA) and **MTA-STS** (RFC 8461) on the relay: when a recipient publishes a policy,
  mail is delivered only over a verified TLS connection to an authorized mail
  exchange, with **no cleartext fallback** (a failure defers and retries). DANE takes
  precedence over MTA-STS.
- **Inbound sender authentication** — **SPF** (RFC 7208), **DKIM** (RFC 6376 +
  Ed25519, RFC 8463), and **DMARC** (RFC 7489) are evaluated on inbound mail and
  stamped into `Received-SPF` / `Authentication-Results`; an SPF `Fail` or a DMARC
  `reject` disposition can be enforced by configuration, and DMARC **aggregate (rua)
  reports** are generated. Optional **greylisting** (RFC 6647) defers first contact
  from unseen senders.
- **Not an open relay, no spoofing** — the inbound receiver refuses non-local
  recipients; authenticated submission binds `MAIL FROM` to the logged-in user
  (RFC 6409), so a user can only send as themselves.
- **Hardened SMTP & anti-abuse** — a strict `<CRLF>.<CRLF>` end-of-data terminator
  defends against SMTP smuggling / message-splitting; per-line, per-message (`552`),
  and per-transaction recipient (`452`) caps bound resource use; a per-IP connection
  firewall rate-limits the public port and a per-IP throttle locks out brute-force
  credential guessing; content-based spam scoring runs on delivery.
- **Operable** — argon2 password hashing, a credential store with chacha20poly1305
  secret encryption, an audit log, structured JSON logging with an OpenTelemetry
  pipeline, and graceful (Ctrl-C) shutdown.

## Build & run

Requires a recent Rust toolchain (edition 2024, `rustc` ≥ 1.95).

```bash
# build and test the whole workspace
cargo build --workspace
cargo test  --workspace

# lint + format gates
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --check

# run the server
cargo run -p snail_server --bin snail-server
```

The server is configured entirely through environment variables:

| Variable | Purpose | Default |
| --- | --- | --- |
| `SNAIL_DOMAIN` | the domain you host mail for | `localhost` |
| `SNAIL_USERS` | accounts to provision at boot, `user:pass,user2:pass2` | — |
| `SNAIL_SUBMISSION_ADDR` | submission (SMTP+AUTH) bind address | `127.0.0.1:587` |
| `SNAIL_POP3_ADDR` | POP3 bind address | `127.0.0.1:110` |
| `SNAIL_IMAP_ADDR` | IMAP bind address | `127.0.0.1:143` |
| `SNAIL_INBOUND_ADDR` | inbound MX bind address (`:25` in production) | `127.0.0.1:2525` |
| `SNAIL_SPOOL_DIR` | outbound relay queue directory | `<data_dir>/spool` |
| `SNAIL_TLS_CERT` / `SNAIL_TLS_KEY` | PEM cert + key for STARTTLS (a self-signed cert is generated off the production port if unset) | — |
| `SNAIL_SPF_ENFORCE` | reject (`550`) inbound mail on SPF `Fail` (otherwise stamp `Received-SPF` only) | off |
| `SNAIL_DMARC_ENFORCE` | reject (`550`) inbound mail on a DMARC `reject` disposition (otherwise stamp only) | off |
| `SNAIL_GREYLIST` | greylist the inbound port: defer (`451`) first contact for an unseen sender | off |
| `SNAIL_MTA_STS` | enforce outbound MTA-STS (RFC 8461) — verified TLS to policy-matched MX | off |
| `SNAIL_DANE` | enable outbound DANE (RFC 7672); takes precedence over MTA-STS | off |
| `SNAIL_DATA_DIR` / `SNAIL_LOG` | data directory / log level | — |

## Architecture

A Cargo workspace of nine Rust members, layered:

- **Foundation** — `crates/utilities` (config, errors) and `services/telemetry`
  (tracing + OpenTelemetry).
- **Mail engine** — `crates/mail` (message model, SMTP, delivery, store, STARTTLS
  policy, content scanner).
- **Deliverability** — `crates/network` (async DNS/MX lookups with optional DNSSEC
  validation, rustls TLS configs, SPF/DKIM/DMARC verification, MTA-STS policy fetch,
  and DANE TLSA certificate verification).
- **Security & identity** — `crates/security` (argon2, encryption, credentials,
  firewall, audit) and `crates/identity` (accounts, SASL `PLAIN`/`LOGIN`/`XOAUTH2`).
- **Client access** — `crates/access` (POP3, IMAP, MSA submission, web) and spam
  `crates/filter`.
- **Composition root** — `services/snail_server`, which wires everything together
  and exposes the `snail-server` binary (listeners, outbound relay worker, DMARC
  aggregate-report worker, graceful shutdown).

The TypeScript side (`packages/{cli,sdk}`, `apps/{web,desktop}-client`) and the
native FFI client (`crates/client`) sit alongside and are being built out.

## Roadmap / not yet

- Durable mailbox storage on disk (the mailbox store is currently in-memory; only
  the outbound relay queue is persisted).
- The TypeScript operator CLI, SDK, web/desktop clients, and the plugin integration
  service, plus the native Rust↔JS FFI client binding (`crates/client`).
- Finer deliverability reporting — **TLSRPT**, and MTA-STS `testing`-mode report
  collection (DANE/MTA-STS enforcement itself is implemented).

## License

No license has been chosen yet.

Built with Rust and TypeScript.
