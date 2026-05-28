//! The async `DnsResolver` contract.

use std::net::IpAddr;

use async_trait::async_trait;

use crate::dns::{
    AddressRecord, DkimRecord, DmarcRecord, MxRecord, PtrRecord, TlsaRecord, TxtRecord,
};
use crate::error::{NetworkError, Result};

/// Async DNS resolution contract used across Snail. Implementers provide the four
/// *raw* lookups; the DKIM/DMARC convenience methods are **default methods** built
/// on `lookup_txt` and must not be overridden.
#[async_trait]
pub trait DnsResolver: Send + Sync {
    /// Resolve the MX records for a domain (mail routing).
    async fn lookup_mx(&self, domain: &str) -> Result<Vec<MxRecord>>;
    /// Resolve a host to its addresses (A **and** AAAA), matching hickory's `lookup_ip`.
    async fn lookup_ip(&self, host: &str) -> Result<Vec<AddressRecord>>;
    /// Resolve the TXT records at a name.
    async fn lookup_txt(&self, name: &str) -> Result<Vec<TxtRecord>>;
    /// Resolve the PTR (reverse-DNS) records for an IP.
    async fn reverse_lookup(&self, ip: IpAddr) -> Result<Vec<PtrRecord>>;

    /// Fetch `<selector>._domainkey.<domain>` TXT and parse the first valid DKIM record.
    ///
    /// # Errors
    /// [`NetworkError::Record`] if no TXT at that name parses as a DKIM record.
    async fn lookup_dkim(&self, selector: &str, domain: &str) -> Result<DkimRecord> {
        let name = format!("{selector}._domainkey.{domain}");
        let txts = self.lookup_txt(&name).await?;
        txts.iter()
            .find_map(|t| DkimRecord::parse(&t.0).ok())
            .ok_or_else(|| NetworkError::Record {
                kind: "DKIM".into(),
                reason: format!("no parseable DKIM record at {name}"),
            })
    }

    /// Fetch `_dmarc.<domain>` TXT and parse the first `v=DMARC1` record
    /// (multiple TXTs at that name are legal).
    ///
    /// # Errors
    /// [`NetworkError::Record`] if no TXT at that name parses as a DMARC record.
    async fn lookup_dmarc(&self, domain: &str) -> Result<DmarcRecord> {
        let name = format!("_dmarc.{domain}");
        let txts = self.lookup_txt(&name).await?;
        txts.iter()
            .find_map(|t| DmarcRecord::parse(&t.0).ok())
            .ok_or_else(|| NetworkError::Record {
                kind: "DMARC".into(),
                reason: format!("no parseable DMARC record at {name}"),
            })
    }

    /// Fetch the **DNSSEC-validated** TLSA records for a mail exchange at
    /// `_<port>._tcp.<host>` (DANE, RFC 7672). Returns `Some(records)` **only**
    /// when the answer was DNSSEC-validated (`Proof::Secure`); `None` means there
    /// is no securely-published TLSA RRset and DANE MUST NOT be used (RFC 7672
    /// §2.1.1). The `Option` makes insecure data unrepresentable to callers, so a
    /// non-validating resolver cannot accidentally authenticate a peer.
    ///
    /// The default implementation returns `None`: a resolver that performs no
    /// DNSSEC validation cannot authenticate DANE associations.
    async fn secure_tlsa(&self, _port: u16, _host: &str) -> Result<Option<Vec<TlsaRecord>>> {
        Ok(None)
    }

    /// Fetch the **DNSSEC-validated** MX records for a domain (the DANE
    /// precondition, RFC 7672 §2.2: TLSA records of an MX host may only be
    /// trusted when the MX RRset itself was obtained securely, else an attacker
    /// who spoofs an insecure MX could redirect to a host bearing its own valid
    /// TLSA). Returns `Some(records)` only when the MX RRset was `Proof::Secure`.
    ///
    /// The default implementation returns `None` (no secure MX → no DANE).
    async fn secure_mx(&self, _domain: &str) -> Result<Option<Vec<MxRecord>>> {
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns::DmarcPolicy;
    use std::collections::BTreeMap;

    /// A resolver whose TXT answers are canned; the other lookups are unused here.
    struct MockResolver {
        txt: BTreeMap<String, Vec<TxtRecord>>,
    }

    #[async_trait]
    impl DnsResolver for MockResolver {
        async fn lookup_mx(&self, _domain: &str) -> Result<Vec<MxRecord>> {
            Ok(vec![])
        }
        async fn lookup_ip(&self, _host: &str) -> Result<Vec<AddressRecord>> {
            Ok(vec![])
        }
        async fn lookup_txt(&self, name: &str) -> Result<Vec<TxtRecord>> {
            Ok(self.txt.get(name).cloned().unwrap_or_default())
        }
        async fn reverse_lookup(&self, _ip: IpAddr) -> Result<Vec<PtrRecord>> {
            Ok(vec![])
        }
    }

    fn resolver_with(name: &str, txts: &[&str]) -> MockResolver {
        let mut txt = BTreeMap::new();
        txt.insert(
            name.to_string(),
            txts.iter().map(|s| TxtRecord((*s).to_string())).collect(),
        );
        MockResolver { txt }
    }

    #[tokio::test]
    async fn lookup_dkim_queries_domainkey_and_parses() {
        let r = resolver_with("sel._domainkey.example.com", &["v=DKIM1; k=rsa; p=ABC"]);
        let rec = r.lookup_dkim("sel", "example.com").await.unwrap();
        assert_eq!(rec.public_key, "ABC");
    }

    #[tokio::test]
    async fn lookup_dmarc_picks_first_dmarc1_among_multiple_txt() {
        let r = resolver_with(
            "_dmarc.example.com",
            &["v=spf1 -all", "v=DMARC1; p=quarantine"],
        );
        let rec = r.lookup_dmarc("example.com").await.unwrap();
        assert_eq!(rec.policy, DmarcPolicy::Quarantine);
    }

    #[tokio::test]
    async fn lookup_dkim_errors_when_absent() {
        let r = resolver_with("unrelated", &[]);
        assert!(r.lookup_dkim("sel", "example.com").await.is_err());
    }
}
