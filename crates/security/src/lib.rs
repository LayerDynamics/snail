//! Cryptography and connection policy for the Snail mail server: password
//! hashing, secret encryption, credential storage, firewall, and audit logging.

pub mod audit;
pub mod credential;
pub mod encryption;
pub mod error;
pub mod firewall;
pub mod greylist;
pub mod throttle;

pub use audit::{AuditConfig, AuditEvent, AuditLog, AuditManager};
pub use credential::{
    AuthOutcome, Credential, CredentialReceiver, CredentialStore, MemoryCredentialStore,
};
pub use encryption::{PasswordHasher, SecretCipher};
pub use error::{Result, SecurityError};
pub use firewall::{Decision, DenyReason, Firewall, FirewallConfig, FirewallManager};
pub use greylist::{GreyDecision, Greylist, GreylistConfig};
pub use throttle::{AuthThrottle, ThrottleConfig};
