//! DNS resolution and TLS configuration for the Snail mail server.
//!
//! `dns` exposes a [`dns::DnsResolver`] trait (typed MX/A+AAAA/TXT/DKIM/DMARC/PTR
//! lookups) with a hickory-backed implementation; `tls` builds rustls configs and
//! wraps tokio-rustls accept/connect.

pub mod dns;
pub mod error;
pub mod tls;

pub use error::{NetworkError, Result};
