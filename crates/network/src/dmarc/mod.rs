//! DMARC (RFC 7489): combine the SPF and DKIM results with identifier alignment
//! against the `From:` domain, look up the domain's published policy, and decide
//! the disposition (none / quarantine / reject).
//!
//! Alignment uses the Public Suffix List (the `psl` crate) to compute
//! organizational domains, so relaxed alignment is correct for multi-label TLDs
//! (e.g. `mail.example.co.uk` aligns with `news.example.co.uk`, but not with
//! `evil.co.uk`).

pub mod eval;

pub use eval::{DmarcDisposition, DmarcResult, evaluate, organizational_domain};
