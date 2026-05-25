//! MX record: a mail-exchange host with a preference.

/// A mail-exchange record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MxRecord {
    /// Lower preference = higher priority.
    pub preference: u16,
    /// Exchange hostname (trailing dot stripped).
    pub exchange: String,
}
