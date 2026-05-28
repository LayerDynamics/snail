//! DNS resolution: typed record types, the `DnsResolver` trait, and a
//! hickory-backed implementation.

pub mod a;
pub mod dkim;
pub mod dmark;
pub mod lookup;
pub mod manager;
pub mod mx;
pub mod reverse;
pub mod tlsa;
pub mod txt;

pub use a::AddressRecord;
pub use dkim::DkimRecord;
pub use dmark::{AlignmentMode, DmarcPolicy, DmarcRecord};
pub use lookup::DnsResolver;
pub use manager::HickoryResolver;
pub use mx::MxRecord;
pub use reverse::PtrRecord;
pub use tlsa::{TlsaMatching, TlsaRecord, TlsaSelector, TlsaUsage};
pub use txt::TxtRecord;
