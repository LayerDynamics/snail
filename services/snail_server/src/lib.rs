//! The Snail mail server composition root: wires every engine crate
//! (`utilities`, `identity`, `security`, `mail`, `filter`, `access`) into one
//! runnable server. The async listeners and entrypoint live alongside this in
//! the binary.

pub mod config;
pub mod server;

pub use config::ServerConfig;
pub use server::{Server, ServerAuth, ServerMta, SharedStore};
