//! DNS resolution and TLS configuration for the Snail mail server.
//!
//! `dns` exposes a [`dns::DnsResolver`] trait (typed MX/A+AAAA/TXT/DKIM/DMARC/PTR
//! lookups) with a hickory-backed implementation; `spf` evaluates RFC 7208 Sender
//! Policy Framework over that resolver; `tls` builds rustls configs and wraps
//! tokio-rustls accept/connect.

pub mod dkim;
pub mod dmarc;
pub mod dns;
pub mod error;
pub mod spf;
pub mod tls;

pub use dkim::{DkimOutcome, DkimResult, verify as verify_dkim};
pub use dmarc::{DmarcDisposition, DmarcResult, evaluate as evaluate_dmarc};
pub use dns::{
    AddressRecord, AlignmentMode, DkimRecord, DmarcPolicy, DmarcRecord, DnsResolver,
    HickoryResolver, MxRecord, PtrRecord, TxtRecord,
};
pub use error::{NetworkError, Result};
pub use spf::{SpfResult, evaluate as evaluate_spf};
pub use tls::TlsConfig;
