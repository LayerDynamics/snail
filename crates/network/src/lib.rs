//! DNS resolution and TLS configuration for the Snail mail server.
//!
//! `dns` exposes a [`dns::DnsResolver`] trait (typed MX/A+AAAA/TXT/DKIM/DMARC/PTR
//! lookups) with a hickory-backed implementation; `spf` evaluates RFC 7208 Sender
//! Policy Framework over that resolver; `dkim`/`dmarc` verify inbound
//! authentication; `mta_sts` discovers, fetches, and caches RFC 8461 MTA-STS
//! policies for the outbound relay; `tls` builds rustls configs and wraps
//! tokio-rustls accept/connect.

pub mod dkim;
pub mod dmarc;
pub mod dns;
pub mod error;
pub mod mta_sts;
pub mod spf;
pub mod tls;

pub use dkim::{DkimOutcome, DkimResult, verify as verify_dkim};
pub use dmarc::{DmarcDisposition, DmarcResult, evaluate as evaluate_dmarc};
pub use dns::{
    AddressRecord, AlignmentMode, DkimRecord, DmarcPolicy, DmarcRecord, DnsResolver,
    HickoryResolver, MxRecord, PtrRecord, TxtRecord,
};
pub use error::{NetworkError, Result};
pub use mta_sts::{MtaStsMode, MtaStsPolicy, MtaStsResolver};
pub use spf::{SpfResult, evaluate as evaluate_spf};
pub use tls::TlsConfig;
