//! DANE TLS authentication for outbound SMTP (RFC 7672 / RFC 6698).
//!
//! [`DaneVerifier`] is a rustls [`ServerCertVerifier`] that authenticates a mail
//! exchange's certificate against the DNSSEC-validated TLSA records published for
//! it (obtained via [`DnsResolver::secure_tlsa`](crate::dns::DnsResolver::secure_tlsa)).
//! It supports the two certificate usages RFC 7672 §3.1.3 recommends for SMTP:
//!
//! - **DANE-EE (3)** — the TLSA association must match the server's end-entity
//!   certificate directly. No PKIX chain or reference-identity check is performed
//!   (RFC 7672 §3.1.1); this is the common SMTP case.
//! - **DANE-TA (2)** — the association must match a certificate in the presented
//!   chain, which is then treated as the trust anchor; the end-entity must build a
//!   valid chain up to it (WebPKI) **and** match the mail-exchange host name.
//!
//! Usages **PKIX-TA (0)** and **PKIX-EE (1)** are deliberately treated as
//! *unusable* — RFC 7672 §3.1.3 says SMTP servers SHOULD NOT publish them and
//! clients MAY ignore them — so a record with those usages never authenticates a
//! peer here. A connection where *no* usable TLSA record matches fails the
//! handshake, which the relay turns into a deferral (never a cleartext downgrade).

use std::sync::Arc;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{CryptoProvider, verify_tls12_signature, verify_tls13_signature};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};
use sha2::{Digest, Sha256, Sha512};
use x509_cert::Certificate;
use x509_cert::der::{Decode, Encode};

use crate::dns::{TlsaMatching, TlsaRecord, TlsaSelector, TlsaUsage};

/// A rustls server-certificate verifier that authenticates a peer via DANE
/// (RFC 7672) against a set of DNSSEC-validated TLSA records.
#[derive(Debug)]
pub struct DaneVerifier {
    /// The usable TLSA records for this mail exchange (already DNSSEC-validated).
    tlsa: Vec<TlsaRecord>,
    /// The active crypto provider, used for chain and handshake-signature checks.
    provider: Arc<CryptoProvider>,
}

impl DaneVerifier {
    /// Build a verifier from a mail exchange's TLSA records and the active crypto
    /// provider. The records must already be DNSSEC-validated (`Proof::Secure`);
    /// `secure_tlsa` guarantees this.
    #[must_use]
    pub fn new(tlsa: Vec<TlsaRecord>, provider: Arc<CryptoProvider>) -> Self {
        Self { tlsa, provider }
    }

    /// Verify a DANE-TA (usage 2) association: a certificate in the presented
    /// chain must match the TLSA record and serve as the trust anchor, the
    /// end-entity must build a valid WebPKI chain to it, and the end-entity must
    /// be valid for `server_name` (RFC 7672 §3.1.1 requires the identity check
    /// for usage 2). Returns `true` on success.
    fn matches_dane_ta(
        &self,
        tlsa: &TlsaRecord,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        now: UnixTime,
    ) -> bool {
        // The trust anchor is whichever presented certificate the TLSA names.
        let chain = std::iter::once(end_entity).chain(intermediates.iter());
        let Some(ta_cert) = chain.into_iter().find(|c| cert_matches(tlsa, c.as_ref())) else {
            return false;
        };
        let Ok(anchor) = webpki::anchor_from_trusted_cert(ta_cert) else {
            return false;
        };
        let Ok(ee) = webpki::EndEntityCert::try_from(end_entity) else {
            return false;
        };
        if ee
            .verify_for_usage(
                self.provider.signature_verification_algorithms.all,
                &[anchor],
                intermediates,
                now,
                webpki::KeyUsage::server_auth(),
                None,
                None,
            )
            .is_err()
        {
            return false;
        }
        // RFC 7672 §3.1.1: usage 2 still requires the EE to match the reference
        // identity (the mail-exchange host name passed as `server_name`).
        ee.verify_is_valid_for_subject_name(server_name).is_ok()
    }
}

impl ServerCertVerifier for DaneVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, rustls::Error> {
        for tlsa in &self.tlsa {
            let matched = match tlsa.usage {
                // DANE-EE: match the end-entity directly, no PKIX/name check.
                TlsaUsage::DaneEe => cert_matches(tlsa, end_entity.as_ref()),
                // DANE-TA: the matched cert anchors a verified chain to the EE.
                TlsaUsage::DaneTa => {
                    self.matches_dane_ta(tlsa, end_entity, intermediates, server_name, now)
                }
                // PKIX-TA/PKIX-EE and any unassigned usage are unusable for SMTP.
                TlsaUsage::PkixTa | TlsaUsage::PkixEe | TlsaUsage::Other(_) => false,
            };
            if matched {
                return Ok(ServerCertVerified::assertion());
            }
        }
        Err(rustls::Error::General(
            "DANE: no usable TLSA record matched the server certificate chain".into(),
        ))
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// Whether at least one record in `records` is *usable* for DANE (RFC 6698
/// §2.2.4 / RFC 7672 §3.1.3): a `DANE-EE`/`DANE-TA` usage with a known selector
/// and matching type. If every record is unusable the host has no usable TLSA
/// RRset and DANE does not apply — the relay then falls back to its non-DANE
/// policy rather than treating delivery as impossible.
#[must_use]
pub fn has_usable_tlsa(records: &[TlsaRecord]) -> bool {
    records.iter().any(is_usable)
}

fn is_usable(record: &TlsaRecord) -> bool {
    matches!(record.usage, TlsaUsage::DaneEe | TlsaUsage::DaneTa)
        && !matches!(record.selector, TlsaSelector::Other(_))
        && !matches!(record.matching, TlsaMatching::Other(_))
}

/// Whether the certificate (raw DER) matches the TLSA association — the selected
/// content (full cert or SPKI), compared exactly or by digest.
fn cert_matches(tlsa: &TlsaRecord, cert_der: &[u8]) -> bool {
    match selected_content(tlsa.selector, cert_der) {
        Some(content) => matches_association(tlsa.matching, &content, &tlsa.data),
        None => false,
    }
}

/// The bytes the TLSA `selector` covers: the whole certificate DER (`Full`) or
/// its `SubjectPublicKeyInfo` DER (`Spki`).
fn selected_content(selector: TlsaSelector, cert_der: &[u8]) -> Option<Vec<u8>> {
    match selector {
        TlsaSelector::Full => Some(cert_der.to_vec()),
        TlsaSelector::Spki => spki_der(cert_der),
        TlsaSelector::Other(_) => None,
    }
}

/// Extract the DER-encoded `SubjectPublicKeyInfo` from a certificate's DER.
fn spki_der(cert_der: &[u8]) -> Option<Vec<u8>> {
    let cert = Certificate::from_der(cert_der).ok()?;
    cert.tbs_certificate.subject_public_key_info.to_der().ok()
}

/// Whether `content` matches the association `data` under `matching` (exact bytes
/// for `Full`, otherwise a SHA-256 / SHA-512 digest comparison).
fn matches_association(matching: TlsaMatching, content: &[u8], data: &[u8]) -> bool {
    match matching {
        TlsaMatching::Full => content == data,
        TlsaMatching::Sha256 => Sha256::digest(content).as_slice() == data,
        TlsaMatching::Sha512 => Sha512::digest(content).as_slice() == data,
        TlsaMatching::Other(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustls::pki_types::{CertificateDer, ServerName, UnixTime};

    fn provider() -> Arc<CryptoProvider> {
        Arc::new(rustls::crypto::aws_lc_rs::default_provider())
    }

    /// A self-signed leaf certificate for `name`.
    fn self_signed(name: &str) -> rcgen::Certificate {
        let key = rcgen::KeyPair::generate().unwrap();
        rcgen::CertificateParams::new(vec![name.to_string()])
            .unwrap()
            .self_signed(&key)
            .unwrap()
    }

    /// A CA certificate plus a leaf (for `mx.test`) signed by it, as DER.
    fn ca_and_leaf() -> (CertificateDer<'static>, CertificateDer<'static>) {
        let ca_key = rcgen::KeyPair::generate().unwrap();
        let mut ca = rcgen::CertificateParams::new(vec!["ca.test".to_string()]).unwrap();
        ca.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        ca.key_usages = vec![
            rcgen::KeyUsagePurpose::KeyCertSign,
            rcgen::KeyUsagePurpose::DigitalSignature,
        ];
        let ca = ca.self_signed(&ca_key).unwrap();

        let leaf_key = rcgen::KeyPair::generate().unwrap();
        let mut leaf = rcgen::CertificateParams::new(vec!["mx.test".to_string()]).unwrap();
        leaf.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];
        let leaf = leaf.signed_by(&leaf_key, &ca, &ca_key).unwrap();
        (leaf.der().clone(), ca.der().clone())
    }

    fn verify(
        verifier: &DaneVerifier,
        ee: &CertificateDer<'_>,
        chain: &[CertificateDer<'_>],
        name: &str,
    ) -> bool {
        let server_name = ServerName::try_from(name.to_string()).unwrap();
        verifier
            .verify_server_cert(ee, chain, &server_name, &[], UnixTime::now())
            .is_ok()
    }

    #[test]
    fn has_usable_tlsa_filters_unusable_usages_and_fields() {
        assert!(has_usable_tlsa(&[TlsaRecord {
            usage: TlsaUsage::DaneEe,
            selector: TlsaSelector::Spki,
            matching: TlsaMatching::Sha256,
            data: vec![0u8; 32],
        }]));
        // PKIX usages are not usable for SMTP DANE.
        assert!(!has_usable_tlsa(&[TlsaRecord {
            usage: TlsaUsage::PkixEe,
            selector: TlsaSelector::Spki,
            matching: TlsaMatching::Sha256,
            data: vec![0u8; 32],
        }]));
        // An unknown selector/matching makes a record unusable.
        assert!(!has_usable_tlsa(&[TlsaRecord {
            usage: TlsaUsage::DaneEe,
            selector: TlsaSelector::Other(9),
            matching: TlsaMatching::Sha256,
            data: vec![],
        }]));
    }

    #[test]
    fn dane_ee_accepts_matching_full_certificate() {
        let cert = self_signed("mx.test");
        let der = cert.der().clone();
        // TLSA 3 0 0: the full end-entity certificate, no PKIX/name check.
        let tlsa = TlsaRecord {
            usage: TlsaUsage::DaneEe,
            selector: TlsaSelector::Full,
            matching: TlsaMatching::Full,
            data: der.as_ref().to_vec(),
        };
        let verifier = DaneVerifier::new(vec![tlsa], provider());
        // The name is irrelevant for DANE-EE (RFC 7672 §3.1.1).
        assert!(verify(&verifier, &der, &[], "anything.invalid"));
    }

    #[test]
    fn dane_ee_accepts_matching_spki_sha256() {
        let cert = self_signed("mx.test");
        let der = cert.der().clone();
        // TLSA 3 1 1: SHA-256 of the SubjectPublicKeyInfo (the common SMTP case).
        let spki = spki_der(der.as_ref()).unwrap();
        let tlsa = TlsaRecord {
            usage: TlsaUsage::DaneEe,
            selector: TlsaSelector::Spki,
            matching: TlsaMatching::Sha256,
            data: Sha256::digest(&spki).to_vec(),
        };
        let verifier = DaneVerifier::new(vec![tlsa], provider());
        assert!(verify(&verifier, &der, &[], "mx.test"));
    }

    #[test]
    fn dane_ee_rejects_non_matching_certificate() {
        let cert = self_signed("mx.test");
        let der = cert.der().clone();
        let tlsa = TlsaRecord {
            usage: TlsaUsage::DaneEe,
            selector: TlsaSelector::Spki,
            matching: TlsaMatching::Sha256,
            data: vec![0u8; 32], // not the cert's SPKI digest
        };
        let verifier = DaneVerifier::new(vec![tlsa], provider());
        assert!(!verify(&verifier, &der, &[], "mx.test"));
    }

    #[test]
    fn dane_ta_accepts_chain_to_matched_anchor() {
        let (leaf, ca) = ca_and_leaf();
        // TLSA 2 1 1 against the CA's SPKI; the leaf must chain to it.
        let tlsa = TlsaRecord {
            usage: TlsaUsage::DaneTa,
            selector: TlsaSelector::Spki,
            matching: TlsaMatching::Sha256,
            data: Sha256::digest(spki_der(ca.as_ref()).unwrap()).to_vec(),
        };
        let verifier = DaneVerifier::new(vec![tlsa], provider());
        assert!(verify(&verifier, &leaf, &[ca], "mx.test"));
    }

    #[test]
    fn dane_ta_rejects_wrong_reference_identity() {
        let (leaf, ca) = ca_and_leaf();
        let tlsa = TlsaRecord {
            usage: TlsaUsage::DaneTa,
            selector: TlsaSelector::Spki,
            matching: TlsaMatching::Sha256,
            data: Sha256::digest(spki_der(ca.as_ref()).unwrap()).to_vec(),
        };
        let verifier = DaneVerifier::new(vec![tlsa], provider());
        // Chain is valid, but the leaf is not valid for `wrong.test` (RFC 7672 §3.1.1).
        assert!(!verify(&verifier, &leaf, &[ca], "wrong.test"));
    }

    #[test]
    fn dane_ta_rejects_when_no_chain_certificate_matches() {
        let (leaf, ca) = ca_and_leaf();
        let tlsa = TlsaRecord {
            usage: TlsaUsage::DaneTa,
            selector: TlsaSelector::Spki,
            matching: TlsaMatching::Sha256,
            data: vec![0u8; 32], // matches neither the leaf nor the CA
        };
        let verifier = DaneVerifier::new(vec![tlsa], provider());
        assert!(!verify(&verifier, &leaf, &[ca], "mx.test"));
    }
}
