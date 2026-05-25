//! Credential storage, verification, and the session-intake receiver.

pub mod manager;
pub mod provider;
pub mod reciever;

pub use manager::MemoryCredentialStore;
pub use provider::{Credential, CredentialStore};
pub use reciever::{AuthOutcome, CredentialReceiver};
