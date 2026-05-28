//! `HickoryResolver`: the live [`DnsResolver`] backed by `hickory-resolver` and
//! the system resolver configuration, plus the pure hickory→typed mapping.

use std::net::IpAddr;
use std::sync::Arc;

use async_trait::async_trait;
use hickory_resolver::TokioResolver;
use hickory_resolver::proto::dnssec::TrustAnchors;
use hickory_resolver::proto::rr::rdata::{MX, TLSA, TXT};
use hickory_resolver::proto::rr::{Name, RData, Record, RecordType};

use crate::dns::lookup::DnsResolver;
use crate::dns::{
    AddressRecord, MxRecord, PtrRecord, TlsaMatching, TlsaRecord, TlsaSelector, TlsaUsage,
    TxtRecord,
};
use crate::error::{NetworkError, Result};

/// A live DNS resolver backed by hickory + the host's resolver configuration.
///
/// Holds two resolvers built from the same system configuration:
/// - `inner` does **not** validate DNSSEC and serves the hot lookup paths
///   (MX/A+AAAA/TXT/PTR), preserving prior behaviour against unsigned zones and
///   non-validating upstreams.
/// - `validating` performs DNSSEC validation (rooted at the IANA trust anchors)
///   and backs DANE (`secure_tlsa` / `secure_mx`), where an answer is only
///   trusted when it is `Proof::Secure`.
pub struct HickoryResolver {
    inner: TokioResolver,
    validating: TokioResolver,
}

impl HickoryResolver {
    /// Build a resolver from the system configuration (`/etc/resolv.conf`, etc.).
    ///
    /// This resolver does **not** perform DNSSEC validation — it preserves the
    /// behaviour of the previous releases for the hot lookup paths
    /// (MX/A/AAAA/TXT/PTR), which must keep working against unsigned zones and
    /// non-validating upstream resolvers. DANE's DNSSEC requirement is served by
    /// a separate validating resolver (see the `dane` module / `secure_tlsa`),
    /// so a stub resolver that strips RRSIG cannot break ordinary mail routing.
    ///
    /// # Errors
    /// [`NetworkError::Resolve`] if the system configuration cannot be read.
    pub fn from_system() -> Result<Self> {
        let system_err = |e: String| NetworkError::Resolve {
            name: "<system-conf>".into(),
            reason: e,
        };
        let inner = TokioResolver::builder_tokio()
            .and_then(|builder| builder.build())
            .map_err(|e| system_err(e.to_string()))?;
        // The validating resolver enables DNSSEC by supplying the IANA root trust
        // anchors (which sets `validate = true`); only `Proof::Secure` answers are
        // honoured for DANE.
        let validating = TokioResolver::builder_tokio()
            .and_then(|builder| {
                builder
                    .with_trust_anchor(Arc::new(TrustAnchors::default()))
                    .build()
            })
            .map_err(|e| system_err(e.to_string()))?;
        Ok(Self { inner, validating })
    }

    /// Run a generic lookup, returning the answer records. A `NoRecordsFound`
    /// response maps to an **empty** vector (not an error) so callers can treat
    /// "the name exists but has no records of this type" distinctly from a real
    /// failure — the MX→A/AAAA fallback in the relay depends on this.
    async fn answers(&self, name: &str, record_type: RecordType) -> Result<Vec<Record>> {
        match self.inner.lookup(name, record_type).await {
            Ok(lookup) => Ok(lookup.answers().to_vec()),
            Err(e) if e.is_no_records_found() => Ok(Vec::new()),
            Err(e) => Err(NetworkError::Resolve {
                name: name.into(),
                reason: e.to_string(),
            }),
        }
    }

    /// Run a lookup through the **validating** resolver and return the answer
    /// records of `record_type` **only if every one is DNSSEC-validated**
    /// (`Proof::Secure`). Any other outcome — an unsigned (`Insecure`) zone, a
    /// failed validation (`Bogus`), no records, or a resolver error — yields
    /// `None`, i.e. "nothing securely available". This is the gate that keeps
    /// DANE from ever trusting unauthenticated DNS data.
    async fn secure_answers(&self, name: &str, record_type: RecordType) -> Option<Vec<Record>> {
        let lookup = self.validating.lookup(name, record_type).await.ok()?;
        let answers: Vec<Record> = lookup
            .answers()
            .iter()
            .filter(|r| r.record_type() == record_type)
            .cloned()
            .collect();
        if answers.is_empty() {
            return None;
        }
        answers
            .iter()
            .all(|r| r.proof.is_secure())
            .then_some(answers)
    }
}

/// Map a hickory TLSA record to the backend-independent [`TlsaRecord`].
fn map_tlsa(tlsa: &TLSA) -> TlsaRecord {
    TlsaRecord {
        usage: TlsaUsage::from_u8(u8::from(tlsa.cert_usage)),
        selector: TlsaSelector::from_u8(u8::from(tlsa.selector)),
        matching: TlsaMatching::from_u8(u8::from(tlsa.matching)),
        data: tlsa.cert_data.clone(),
    }
}

/// Render a DNS name as a host string with the trailing root dot removed.
fn strip_root(name: &Name) -> String {
    name.to_string().trim_end_matches('.').to_string()
}

/// Map a hickory MX record to [`MxRecord`].
fn map_mx(mx: &MX) -> MxRecord {
    MxRecord {
        preference: mx.preference,
        exchange: strip_root(&mx.exchange),
    }
}

/// Map a hickory TXT record to [`TxtRecord`], concatenating its character-strings
/// (DKIM/DMARC values are frequently split across several).
fn map_txt(txt: &TXT) -> TxtRecord {
    let joined = txt
        .txt_data
        .iter()
        .map(|b| String::from_utf8_lossy(b))
        .collect::<String>();
    TxtRecord(joined)
}

#[async_trait]
impl DnsResolver for HickoryResolver {
    async fn lookup_mx(&self, domain: &str) -> Result<Vec<MxRecord>> {
        let answers = self.answers(domain, RecordType::MX).await?;
        Ok(answers
            .iter()
            .filter_map(|r| match &r.data {
                RData::MX(mx) => Some(map_mx(mx)),
                _ => None,
            })
            .collect())
    }

    async fn lookup_ip(&self, host: &str) -> Result<Vec<AddressRecord>> {
        match self.inner.lookup_ip(host).await {
            Ok(lookup) => Ok(lookup.iter().map(AddressRecord).collect()),
            Err(e) if e.is_no_records_found() => Ok(Vec::new()),
            Err(e) => Err(NetworkError::Resolve {
                name: host.into(),
                reason: e.to_string(),
            }),
        }
    }

    async fn lookup_txt(&self, name: &str) -> Result<Vec<TxtRecord>> {
        let answers = self.answers(name, RecordType::TXT).await?;
        Ok(answers
            .iter()
            .filter_map(|r| match &r.data {
                RData::TXT(txt) => Some(map_txt(txt)),
                _ => None,
            })
            .collect())
    }

    async fn reverse_lookup(&self, ip: IpAddr) -> Result<Vec<PtrRecord>> {
        // `Name::from(IpAddr)` yields the reverse-DNS pointer name
        // (`d.c.b.a.in-addr.arpa` / nibble-reversed `…ip6.arpa`).
        let name = Name::from(ip).to_string();
        let answers = self.answers(&name, RecordType::PTR).await?;
        Ok(answers
            .iter()
            .filter_map(|r| match &r.data {
                // `PTR` implements `Display` as its inner `Name`.
                RData::PTR(ptr) => {
                    Some(PtrRecord(ptr.to_string().trim_end_matches('.').to_string()))
                }
                _ => None,
            })
            .collect())
    }

    async fn secure_tlsa(&self, port: u16, host: &str) -> Result<Option<Vec<TlsaRecord>>> {
        let name = format!("_{port}._tcp.{}", host.trim_end_matches('.'));
        let Some(answers) = self.secure_answers(&name, RecordType::TLSA).await else {
            return Ok(None);
        };
        let records: Vec<TlsaRecord> = answers
            .iter()
            .filter_map(|r| match &r.data {
                RData::TLSA(tlsa) => Some(map_tlsa(tlsa)),
                _ => None,
            })
            .collect();
        Ok((!records.is_empty()).then_some(records))
    }

    async fn secure_mx(&self, domain: &str) -> Result<Option<Vec<MxRecord>>> {
        let Some(answers) = self.secure_answers(domain, RecordType::MX).await else {
            return Ok(None);
        };
        let records: Vec<MxRecord> = answers
            .iter()
            .filter_map(|r| match &r.data {
                RData::MX(mx) => Some(map_mx(mx)),
                _ => None,
            })
            .collect();
        Ok((!records.is_empty()).then_some(records))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn map_mx_strips_trailing_dot() {
        let mx = MX::new(10, Name::from_str("mail.example.com.").unwrap());
        let r = map_mx(&mx);
        assert_eq!(r.preference, 10);
        assert_eq!(r.exchange, "mail.example.com");
    }

    #[test]
    fn map_txt_concatenates_character_strings() {
        let txt = TXT::new(vec!["v=DKIM1; ".to_string(), "p=ABC".to_string()]);
        assert_eq!(map_txt(&txt).0, "v=DKIM1; p=ABC");
    }

    #[tokio::test]
    #[ignore = "hits live DNS; run with --ignored"]
    async fn resolves_real_mx() {
        let r = HickoryResolver::from_system().unwrap();
        let mx = r.lookup_mx("gmail.com").await.unwrap();
        assert!(!mx.is_empty());
    }
}
