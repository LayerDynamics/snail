//! PTR (reverse-DNS) record.

/// A reverse-DNS name for an IP address.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PtrRecord(pub String);
