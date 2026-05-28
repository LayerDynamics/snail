//! `client` — the Snail native client binding for JavaScript/TypeScript.
//!
//! Compiled to WebAssembly with `wasm-bindgen`, this crate exposes the engine's
//! `mail` logic (RFC 5322 parsing, address handling, SMTP-script construction) to
//! the SDK and the web/desktop clients. The public API lives in
//! [`bind`](../bind.rs); it is re-exported here so the native `rlib` (used by the
//! demo binary and the test harness) sees the same items.
//!
//! Build the JS package with:
//!
//! ```text
//! wasm-pack build crates/client --target web --out-dir bindings
//! ```

// The binding surface lives in `bind.rs` at the crate root (a sibling of `src/`),
// matching the scaffold layout; mount it as a module here.
#[path = "../bind.rs"]
mod bind;

pub use bind::{
    EmailAddress, ParsedMessage, SmtpScript, build_smtp_script, client_info, compose_message,
};
