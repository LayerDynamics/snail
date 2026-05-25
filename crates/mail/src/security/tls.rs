//! SMTP TLS (STARTTLS) policy.

/// How the SMTP server treats transport security.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsPolicy {
    /// No TLS offered (plaintext only).
    Disabled,
    /// STARTTLS advertised but not required.
    Optional,
    /// TLS required before MAIL FROM / AUTH are accepted.
    Required,
}

impl TlsPolicy {
    /// Whether the server should advertise `STARTTLS` in its EHLO response.
    #[must_use]
    pub fn advertises_starttls(self) -> bool {
        matches!(self, Self::Optional | Self::Required)
    }

    /// Whether mail-transaction / AUTH commands must be refused until TLS is active.
    #[must_use]
    pub fn requires_tls_first(self) -> bool {
        matches!(self, Self::Required)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn policy_capabilities() {
        assert!(!TlsPolicy::Disabled.advertises_starttls());
        assert!(TlsPolicy::Optional.advertises_starttls());
        assert!(!TlsPolicy::Optional.requires_tls_first());
        assert!(TlsPolicy::Required.advertises_starttls());
        assert!(TlsPolicy::Required.requires_tls_first());
    }
}
