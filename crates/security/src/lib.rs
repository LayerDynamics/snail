//! Cryptography and connection policy for the Snail mail server: password
//! hashing, secret encryption, credential storage, firewall, and audit logging.

pub mod credential;
pub mod encryption;
pub mod error;
// pub mod firewall;    -> m10 T4
// pub mod audit;       -> m10 T5

pub use credential::{
    AuthOutcome, Credential, CredentialReceiver, CredentialStore, MemoryCredentialStore,
};
pub use encryption::{PasswordHasher, SecretCipher};
pub use error::{Result, SecurityError};
