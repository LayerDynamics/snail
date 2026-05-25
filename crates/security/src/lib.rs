//! Cryptography and connection policy for the Snail mail server: password
//! hashing, secret encryption, credential storage, firewall, and audit logging.

pub mod error;
// pub mod encryption;  -> m10 T1/T2
// pub mod credential;  -> m10 T3
// pub mod firewall;    -> m10 T4
// pub mod audit;       -> m10 T5

pub use error::{Result, SecurityError};
