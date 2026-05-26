//! Spam filtering for the Snail mail server.
//!
//! Implements the `mail::MessageFilter` contract (defined in m12) so the
//! delivery pipeline can scan messages through it; the composition root (m15)
//! injects a [`spam::SpamFilter`] where m12 currently uses `NullFilter`.
//!
//! This is *content*-based scoring. IP/sender reputation (DNSBL/RBL) lives in the
//! firewall layer (m10), which has the connection's source address — a
//! `MessageFilter` only sees the message, not the peer IP.

pub mod spam;

pub use spam::{SpamFilter, SpamRule};
