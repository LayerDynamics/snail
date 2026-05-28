//! SPF (Sender Policy Framework, RFC 7208): given a connecting IP, the HELO
//! name, and the `MAIL FROM` identity, decide whether the IP is authorized to
//! send for that domain.
//!
//! - [`record`] parses a `v=spf1` TXT record into directives + modifiers.
//! - [`macro_expand`] expands `%{...}` macros in domain-specs (§7).
//! - [`eval`] runs `check_host()` over a [`crate::dns::DnsResolver`], enforcing the
//!   mandatory DNS-lookup budget, and returns an [`SpfResult`].
//!
//! This module decides only the *result*; whether an SPF `Fail` blocks a message
//! or merely annotates it (a `Received-SPF` header for DMARC to weigh) is a policy
//! choice made by the server composition root.

pub mod eval;
pub mod macro_expand;
pub mod record;

pub use eval::{SpfResult, evaluate};
pub use record::{Directive, Mechanism, Qualifier, SpfRecord};
