//! MX record: a mail-exchange host with a preference.

/// A mail-exchange record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MxRecord {
    /// Lower preference = higher priority.
    pub preference: u16,
    /// Exchange hostname (trailing dot stripped).
    pub exchange: String,
}

impl MxRecord {
    /// Whether this is an RFC 7505 "null MX": a `0 .` record whose root exchange
    /// reduces to an empty host once the trailing dot is stripped, signalling
    /// that the domain explicitly accepts no mail. Delivery to it is a permanent
    /// failure (the recipient should bounce), never something to retry.
    #[must_use]
    pub fn is_null(&self) -> bool {
        self.exchange.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn null_mx_is_recognised_by_empty_exchange() {
        assert!(
            MxRecord {
                preference: 0,
                exchange: String::new()
            }
            .is_null()
        );
        assert!(
            !MxRecord {
                preference: 10,
                exchange: "mx.example.com".to_string()
            }
            .is_null()
        );
    }
}
