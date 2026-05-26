# m16 — Wiring the full internet MTA into the running snail-server

> Plan authored 2026-05-25 (work runs into 2026-05-26 UTC). Follows
> `2026-05-25-engine-phase-roadmap-m9-m15.md`. Closes the one engine gap noted in
> `CLAUDE.md`: the running server speaks submission/POP3/IMAP but cannot yet
> **send mail to the internet** or **receive mail from it**.

## What this milestone makes Snail do

Today `snail-server` is a *local* mail server: a user submits over :587, mail to a
hosted domain is delivered, and POP3/IMAP read it back. It cannot talk to other
mail servers. **m16 makes Snail a real internet MTA**: it **relays** mail
addressed to other domains out to their MX hosts (durably, with retries), and it
**receives** mail from other servers on port 25 — over STARTTLS, refusing to be
an open relay, behind a rate-limiting firewall.

Concretely, after m16 the running server:

1. **Relays outbound** — a submitted message to `someone@elsewhere.org` is spooled
   to a durable on-disk queue and a background worker resolves `elsewhere.org`'s MX
   (via `network`'s hickory resolver), connects, and runs the SMTP client dialog
   (`mail::relay_script`). Transient failures are retried with exponential backoff;
   permanent failures / exhausted attempts are bounced. The queue **survives
   restart**.
2. **Receives inbound** — a no-auth SMTP receiver on :25 accepts mail from external
   senders **to local recipients only** (non-local `RCPT` ⇒ `550`, no open relay),
   advertises and performs **STARTTLS**, and is gated by `security::Firewall` at
   accept time.

## Decisions locked (verified against source this session)

- **Relay failure handling: a persistent retry spool** (user choice). Not a single
  attempt — a durable on-disk queue + background worker with exponential backoff,
  max-attempts, and bounce. Accept-then-relay-async: submission spools and returns
  `250` immediately; the worker delivers.
- **Inbound :25 transport: STARTTLS now** (user choice). `serve_inbound` advertises
  `STARTTLS` in EHLO and upgrades the socket before `MAIL FROM`.
- **Port-25 abuse: firewall-gated accepts** (user choice). `Firewall::check(peer_ip)`
  at each inbound accept; over-limit peers get `421` and are dropped.
- **Resolver injection seam.** `Server` gains an *optional* relay capability
  (`Option<Arc<dyn DnsResolver>>` + spool + `helo` + `relay_port`). `Server::new`
  leaves it unset, so **every existing test stays untouched and never calls
  `HickoryResolver::from_system()`** (which can fail in a sandbox). Verified this
  session: `Arc<dyn DnsResolver>` is object-safe (the async-trait default methods
  `lookup_dkim`/`lookup_dmarc` are dyn-callable) — a throwaway `cargo check` passed.
- **`relay_port` is a real parameter** (default 25). Production relays to MX:25;
  tests inject an ephemeral port + a mock resolver returning `exchange="127.0.0.1"`,
  which makes the **whole submission→spool→relay→inbound path loopback-testable over
  real TCP** without DNS or privileged ports.
- **No serde** in the workspace → the spool uses a **hand-rolled, two-file on-disk
  format** (qmail-style): `<id>.eml` (raw `message.to_bytes()`) + `<id>.ctrl`
  (line-based control: sender, recipients, attempts, next-attempt-at, created-at).
  Written temp-then-`rename` for atomicity; the `.ctrl` file's presence marks a
  committed entry.
- **Per-domain message reconstruction is mandatory.** `relay_script` consumes
  `message.envelope.recipients` wholesale into `RCPT TO` lines, so one SMTP session
  targets one MX. `relay()` groups `result.relay` by `mailbox.domain` and builds a
  fresh `Message { envelope: Envelope::new(sender.clone(), domain_rcpts), headers,
  body }` per domain.
- **Inbound default bind is `127.0.0.1:2525`, not `:25`.** Port 25 needs root on
  Unix; `:25` is documented as the production target (privilege / `setcap`). Tests
  use ephemeral ports regardless.
- **Intentional resolver split:** `relay()` resolves *MX* via the injected hickory
  `DnsResolver`, but the final exchange→IP hop uses `TcpStream::connect("{host}:{port}")`
  (the OS resolver). Acceptable for m16; noted so it isn't mistaken for a gap.

## Standards (carried forward, mandatory)

TDD red→green per task; typed-interfaces-first; `thiserror` in libs / `anyhow` in
the binary; **every task ends green**: `cargo clippy --workspace --all-targets --
-D warnings` **and** `cargo fmt --check` **and** `cargo test --workspace`. No
stubs — real socket I/O, real SMTP dialog, real on-disk queue. Verify any
unfamiliar external API against `~/.cargo/registry` before writing.

## New dependencies for `services/snail_server`

Add to its `Cargo.toml` (all already pinned in `[workspace.dependencies]`):
`network` (DNS + TLS helpers), `tokio-rustls`, `rcgen` (self-signed dev cert),
`rustls` (already present). `mail` already exports `relay_script`, `SmtpSession`,
`MailCerts`, `TlsPolicy`.

---

## Task breakdown

### T1 — Outbound SMTP client (`outbound.rs`: `relay_to` + multiline `read_reply`)

New module `services/snail_server/src/outbound.rs`.

- `read_reply<R: AsyncBufRead + Unpin>(&mut R) -> io::Result<(u16, Vec<String>)>` —
  reads a (possibly multiline) SMTP reply: continuation lines have `-` at index 3,
  the final line has a space. **Unit-tested independently** against a
  `tokio::io::BufReader` over a byte slice (single-line and `250-`…`250 ` cases).
- `RelayReport` — typed per-attempt outcome: `Delivered`, `Deferred { code, text }`
  (4xx / connect failure), `Failed { reason }` (5xx / protocol error). No silent
  drops.
- `relay_to(addr: &str, helo: &str, message: &Message) -> io::Result<RelayReport>` —
  `TcpStream::connect(addr)`, split, read 220 greeting, drive `relay_script`
  commands (each awaiting a positive reply via `read_reply`), send `script.data`,
  read the final reply, map to `RelayReport`.

**Tests (red→green):** `read_reply` unit tests; a loopback `relay_to` test that
stands up a minimal byte-script SMTP responder on an ephemeral port and asserts
`Delivered` + that the bytes received match the dialog.

### T2 — Inbound MX receiver, plaintext (`serve_inbound`, no open relay)

In `serve.rs`. `serve_inbound(stream, Arc<Server>) -> io::Result<()>` using a raw
`mail::SmtpSession` (no auth):

- Greet `220`. Loop reading lines.
- Intercept `SmtpCommand::RcptTo(mbox)`: if `!server.is_local(&mbox)` ⇒ reply
  `550 relay not permitted` and **do not** pass to the session (no open relay).
  Otherwise `session.handle`.
- On `354`, collect via `InboundCollector`; on the lone `.`, `take_envelope()` ⇒
  `server.accept_inbound(message)` (delivers local). `QUIT` ⇒ `221`, break.

**Tests:** TCP e2e — connect, EHLO/MAIL/`RCPT`(local)⇒250/DATA⇒delivered (assert
in the store); a second transaction with a non-local `RCPT` ⇒ `550` and asserts
nothing stored for it (**open-relay refusal**).

### T3 — STARTTLS on the inbound receiver

- `enum SmtpStream { Plain(TcpStream), Tls(Box<ServerTlsStream<TcpStream>>) }` with
  hand-written `AsyncRead`/`AsyncWrite` delegating via `match self.get_mut()` +
  `Pin::new(inner)` — sound because both variants are `Unpin` (no `pin-project`
  dep needed).
- `Server` holds optional `tls: Option<Arc<rustls::ServerConfig>>` built from
  `MailCerts` via `network::TlsConfig::server_from_pem`. EHLO advertises
  `250-STARTTLS` when configured (`TlsPolicy::Optional`).
- On `STARTTLS`: ensure the line buffer is drained, reply `220 ready`,
  `network::tls::accept(config, tcp)`, swap to `SmtpStream::Tls`, **reset the SMTP
  session** (RFC 3207: client re-EHLOs over TLS).

**Tests:** STARTTLS e2e — client EHLO sees `STARTTLS`, sends it, gets `220`,
completes the handshake with `network::tls::connect` trusting the self-signed cert,
re-EHLOs over TLS, MAIL/RCPT/DATA, asserts delivery over the encrypted channel.

### T4 — `OutboundSpool` (durable retry queue)

New module `services/snail_server/src/spool.rs`. Sync `std::fs` for deterministic
unit-testing; brief ops called from the async worker.

- `SpoolEntry { id, sender: Option<Mailbox>, recipients: Vec<Mailbox>, attempts,
  next_attempt_at: SystemTime, created_at }` + the raw message bytes.
- `OutboundSpool::open(dir) -> io::Result<Self>` (creates `dir`).
- `enqueue(&self, message: &Message) -> io::Result<String>` — write `<id>.eml`
  then `<id>.ctrl` temp-then-rename; `id` = monotonic timestamp + counter.
- `due_now(&self, now) -> io::Result<Vec<SpoolEntry>>` — scan, parse `.ctrl`, filter
  `next_attempt_at <= now`.
- `load_message(&self, id) -> io::Result<Message>` — re-parse `<id>.eml` + ctrl
  envelope.
- `defer(&self, id, attempts, next_attempt_at)` — rewrite `.ctrl` atomically.
- `remove(&self, id)` (delivered) / `bounce(&self, id)` (move to `bounced/`).
- `backoff(attempts) -> Duration` — exponential, capped (e.g. `min(base·2^n, cap)`).

**Tests (sync, injected `now`):** round-trip enqueue→`due_now`→`load_message`;
`defer` pushes `next_attempt_at` out of the due window then back in; `remove`
deletes both files; `bounce` relocates; control-file parse rejects malformed input;
`backoff` is monotonic and capped.

### T5 — Relay worker + MX-resolving `relay()` + `Server` relay wiring

- `relay(resolver: &dyn DnsResolver, helo, relay_port, message) -> Vec<(String, RelayReport)>`
  — group recipients by `domain`; per domain `lookup_mx`, sort by `preference`,
  build the per-domain `Message`, try `relay_to("{exchange}:{relay_port}", …)` until
  one MX yields `Delivered`/`Failed` (stop) or all `Deferred`.
- `Server` builder: `with_relay(resolver: Arc<dyn DnsResolver>, spool: Arc<OutboundSpool>)`,
  `with_relay_port(u16)`, plus accessors. `helo` = first local domain.
- `spawn_relay_worker(server, shutdown) -> JoinHandle` — `tokio::select!` loop:
  every tick, `spool.due_now(now)`; for each, `relay(...)`:
  `Delivered`⇒`remove`; `Deferred`⇒`defer(attempts+1, now+backoff)` (or `bounce`
  past max-attempts); `Failed`⇒`bounce`. Honors a shutdown signal.

**Tests:** worker drains a one-entry spool to a stub receiver (mock resolver →
`127.0.0.1`, ephemeral `relay_port`); a deferred entry (receiver refusing once)
is retried and then delivered.

### T6 — Submission wiring + listener orchestration + entrypoint + full e2e

- `serve_submission`: after `accept_inbound`, if `result.relay` non-empty and relay
  is configured ⇒ reconstruct the remote `Message` and `spool.enqueue(...)`; reply
  `250` (accept-then-relay-async). If relay is **not** configured, `tracing::warn!`
  the un-relayed recipients (visible, never silent).
- `Listeners` gains `inbound: String`; `run()` adds the inbound accept arm
  (firewall-gated, see T7) **and spawns the relay worker**, all under the existing
  ctrl-C `select!`.
- `main.rs`: add `SNAIL_INBOUND_ADDR` (default `127.0.0.1:2525`), `SNAIL_SPOOL_DIR`
  (default `<data_dir>/spool`), `SNAIL_TLS_CERT`/`SNAIL_TLS_KEY` (PEM paths; if
  unset, generate a self-signed cert for the domain via `rcgen` and log a warning).
  Build `HickoryResolver::from_system()` **gracefully**: on success
  `server.with_relay(...)`; on failure `tracing::warn!` and run without outbound
  relay (inbound + local still work). Update the module doc-comment env list.

**The headline e2e (`submission_relays_to_inbound_receiver`):** two `Server`s over
real TCP — a *receiver* (`local=["remote.test"]`, `serve_inbound` on ephemeral port
`P`) and a *sender* (`local=["example.com"]`, mock resolver →`127.0.0.1`,
`relay_port=P`, temp spool, relay worker running). A client submits to
`u@remote.test` via `serve_submission`; assert it lands in the **receiver's** store.
Proves submission→spool→worker→relay→inbound→delivery end to end. Plus an
`#[ignore]`d `relay_live_mx` using `HickoryResolver::from_system()` against a real
domain.

### T7 — Firewall gate + final green + docs

- Build `security::Firewall` from `FirewallConfig` (held by `Server` or `run`).
  In the inbound accept arm: `match firewall.check(peer.ip())` — `Decision::Deny` ⇒
  write `421 too many connections` and drop; else spawn `serve_inbound`.
- **Regression test:** rapid repeated accepts from one IP trip the limiter (`421`),
  proving the gate (use a tight `FirewallConfig` so the test is fast/deterministic).
- Full workspace green; update `CLAUDE.md` (remove the "known gap" paragraph,
  document :25/:2525 + STARTTLS + spool + the new env vars); update memory
  `snail-engine-state`.

---

## Acceptance bar

- `snail-server` boots and binds **all four** listeners (submission/POP3/IMAP +
  inbound) and spawns the relay worker; graceful ctrl-C stops listeners **and**
  worker.
- A submitted remote message is **relayed** to a (loopback) MX receiver, which
  **delivers** it — proven by the two-server TCP e2e.
- The inbound receiver **rejects open-relay** attempts (`550`) and **performs
  STARTTLS** — proven by tests.
- The spool **persists across process restart** (a reopened `OutboundSpool` sees a
  prior `enqueue`) and retries with backoff — proven by spool + worker tests.
- The firewall **rate-limits** the public port — proven by a regression test.
- `cargo clippy --workspace --all-targets -- -D warnings`, `cargo fmt --check`, and
  `cargo test --workspace` all clean.

## Risks / watch-items

- **STARTTLS buffer drain:** the line reader must not have buffered bytes past
  `STARTTLS\r\n` before the TLS handshake — assert/verify the buffer is empty at
  upgrade.
- **Spool atomicity:** always write `.eml` then `.ctrl` (temp+rename); a lone
  `.eml` without `.ctrl` is an incomplete entry and is ignored/cleaned.
- **Worker vs. ctrl-C:** the worker must observe shutdown promptly — share a
  `tokio::sync::Notify`/watch with `run()` rather than only a sleep.
- **Test flakiness:** drive the worker tick from a short, explicit interval in tests
  and poll the receiver store with a bounded timeout, not a fixed sleep.
