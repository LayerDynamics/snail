//! The Snail mail server composition root: wires every engine crate
//! (`utilities`, `identity`, `security`, `mail`, `filter`, `access`) into one
//! runnable server. The async listeners and entrypoint live alongside this in
//! the binary.

pub mod config;
pub mod outbound;
pub mod serve;
pub mod server;
pub mod spool;

pub use config::ServerConfig;
pub use outbound::{RelayReport, relay_to};
pub use serve::{Listeners, run, serve_imap, serve_inbound, serve_pop, serve_submission};
pub use server::{Server, ServerAuth, ServerMta, SharedStore};
pub use spool::{OutboundSpool, SpoolEntry, backoff};

/// Install the process-wide rustls crypto provider (aws-lc-rs). Call once at
/// startup, before any TLS configuration is built — this is the m9 carryover:
/// with one provider in the graph it is implicit, but installing it explicitly
/// keeps the choice stable if another (e.g. `ring`) ever enters the build.
pub fn install_crypto_provider() {
    // Ignore the error returned when a provider is already installed.
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
}
