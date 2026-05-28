//! DANE TLSA records (RFC 6698 / RFC 7672), modelled independently of the
//! resolver backend so the [`DnsResolver`](crate::dns::DnsResolver) contract and
//! the DANE certificate verifier do not depend on hickory types.

/// TLSA certificate-usage field (RFC 6698 §2.1.1, acronyms per RFC 7218).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsaUsage {
    /// `0` PKIX-TA — CA constraint: PKIX validation **plus** a CA in the chain
    /// must match. RFC 7672 §3.1.3 advises against this for SMTP.
    PkixTa,
    /// `1` PKIX-EE — service-certificate constraint: PKIX validation **plus** the
    /// end-entity must match. RFC 7672 §3.1.3 advises against this for SMTP.
    PkixEe,
    /// `2` DANE-TA — trust-anchor assertion: a certificate in the presented chain
    /// must match and the end-entity must chain to it.
    DaneTa,
    /// `3` DANE-EE — domain-issued certificate: match the end-entity directly,
    /// with no PKIX chain or name check (RFC 7672 §3.1.1). The common SMTP case.
    DaneEe,
    /// Any other (unassigned / private-use) value — unusable for SMTP DANE.
    Other(u8),
}

/// TLSA selector field (RFC 6698 §2.1.2): which part of the certificate is matched.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsaSelector {
    /// `0` — the full certificate (DER).
    Full,
    /// `1` — the `SubjectPublicKeyInfo` (DER).
    Spki,
    /// Any other (unassigned / private-use) value — unusable.
    Other(u8),
}

/// TLSA matching-type field (RFC 6698 §2.1.3): how the selected data is presented.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsaMatching {
    /// `0` — exact match on the selected DER content.
    Full,
    /// `1` — SHA-256 of the selected content.
    Sha256,
    /// `2` — SHA-512 of the selected content.
    Sha512,
    /// Any other (unassigned / private-use) value — unusable.
    Other(u8),
}

/// A TLSA resource record (RFC 6698) used to authenticate a TLS peer via DANE.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsaRecord {
    /// How the association is used (CA / EE; PKIX / DANE).
    pub usage: TlsaUsage,
    /// Which part of the certificate the association covers.
    pub selector: TlsaSelector,
    /// How `data` represents the selected content (raw DER or a digest).
    pub matching: TlsaMatching,
    /// The certificate association data: the raw selected DER, or its digest.
    pub data: Vec<u8>,
}

impl TlsaUsage {
    /// Map the on-the-wire octet to a [`TlsaUsage`].
    #[must_use]
    pub fn from_u8(value: u8) -> Self {
        match value {
            0 => Self::PkixTa,
            1 => Self::PkixEe,
            2 => Self::DaneTa,
            3 => Self::DaneEe,
            other => Self::Other(other),
        }
    }
}

impl TlsaSelector {
    /// Map the on-the-wire octet to a [`TlsaSelector`].
    #[must_use]
    pub fn from_u8(value: u8) -> Self {
        match value {
            0 => Self::Full,
            1 => Self::Spki,
            other => Self::Other(other),
        }
    }
}

impl TlsaMatching {
    /// Map the on-the-wire octet to a [`TlsaMatching`].
    #[must_use]
    pub fn from_u8(value: u8) -> Self {
        match value {
            0 => Self::Full,
            1 => Self::Sha256,
            2 => Self::Sha512,
            other => Self::Other(other),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_octets_to_named_fields() {
        assert_eq!(TlsaUsage::from_u8(3), TlsaUsage::DaneEe);
        assert_eq!(TlsaUsage::from_u8(2), TlsaUsage::DaneTa);
        assert_eq!(TlsaUsage::from_u8(9), TlsaUsage::Other(9));
        assert_eq!(TlsaSelector::from_u8(1), TlsaSelector::Spki);
        assert_eq!(TlsaMatching::from_u8(1), TlsaMatching::Sha256);
        assert_eq!(TlsaMatching::from_u8(2), TlsaMatching::Sha512);
    }
}
