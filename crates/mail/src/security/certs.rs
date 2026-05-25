//! Server TLS certificate material for SMTP.
//!
//! Holds and validates the cert chain + private key as PEM; the actual rustls
//! `ServerConfig` is built from these by `network::TlsConfig` at the composition
//! root (m15), so `mail` need not depend on `network` for this.

use crate::error::{MailError, Result};

/// The SMTP server's TLS certificate chain and private key, as PEM.
#[derive(Debug, Clone)]
pub struct MailCerts {
    /// PEM-encoded certificate chain.
    pub cert_pem: String,
    /// PEM-encoded private key.
    pub key_pem: String,
}

impl MailCerts {
    /// Validate that both PEM blocks are present and well-formed enough to use.
    ///
    /// # Errors
    /// [`MailError::Malformed`] if the certificate or key PEM markers are missing.
    pub fn new(cert_pem: impl Into<String>, key_pem: impl Into<String>) -> Result<Self> {
        let cert_pem = cert_pem.into();
        let key_pem = key_pem.into();
        if !cert_pem.contains("-----BEGIN CERTIFICATE-----") {
            return Err(MailError::Malformed(
                "certificate PEM missing BEGIN CERTIFICATE block".into(),
            ));
        }
        if !key_pem.contains("-----BEGIN") {
            return Err(MailError::Malformed(
                "private key PEM missing BEGIN block".into(),
            ));
        }
        Ok(Self { cert_pem, key_pem })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_well_formed_pem() {
        let certs = MailCerts::new(
            "-----BEGIN CERTIFICATE-----\nabc\n-----END CERTIFICATE-----",
            "-----BEGIN PRIVATE KEY-----\nxyz\n-----END PRIVATE KEY-----",
        );
        assert!(certs.is_ok());
    }

    #[test]
    fn rejects_missing_markers() {
        assert!(MailCerts::new("not a cert", "-----BEGIN PRIVATE KEY-----").is_err());
        assert!(MailCerts::new("-----BEGIN CERTIFICATE-----", "not a key").is_err());
    }
}
