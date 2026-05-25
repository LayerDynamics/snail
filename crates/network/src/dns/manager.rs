//! `HickoryResolver`: the live [`DnsResolver`] backed by `hickory-resolver` and
//! the system resolver configuration, plus the pure hickory→typed mapping.

use std::net::IpAddr;

use async_trait::async_trait;
use hickory_resolver::Name;
use hickory_resolver::TokioAsyncResolver;
use hickory_resolver::proto::rr::rdata::{MX, TXT};

use crate::dns::lookup::DnsResolver;
use crate::dns::{AddressRecord, MxRecord, PtrRecord, TxtRecord};
use crate::error::{NetworkError, Result};

/// A live DNS resolver backed by hickory + the host's resolver configuration.
pub struct HickoryResolver {
    inner: TokioAsyncResolver,
}

impl HickoryResolver {
    /// Build a resolver from the system configuration (`/etc/resolv.conf`, etc.).
    ///
    /// # Errors
    /// [`NetworkError::Resolve`] if the system configuration cannot be read.
    pub fn from_system() -> Result<Self> {
        let inner =
            TokioAsyncResolver::tokio_from_system_conf().map_err(|e| NetworkError::Resolve {
                name: "<system-conf>".into(),
                reason: e.to_string(),
            })?;
        Ok(Self { inner })
    }
}

/// Render a DNS name as a host string with the trailing root dot removed.
fn strip_root(name: &Name) -> String {
    name.to_string().trim_end_matches('.').to_string()
}

/// Map a hickory MX record to [`MxRecord`].
fn map_mx(mx: &MX) -> MxRecord {
    MxRecord {
        preference: mx.preference(),
        exchange: strip_root(mx.exchange()),
    }
}

/// Map a hickory TXT record to [`TxtRecord`], concatenating its character-strings
/// (DKIM/DMARC values are frequently split across several).
fn map_txt(txt: &TXT) -> TxtRecord {
    let joined = txt
        .txt_data()
        .iter()
        .map(|b| String::from_utf8_lossy(b))
        .collect::<String>();
    TxtRecord(joined)
}

#[async_trait]
impl DnsResolver for HickoryResolver {
    async fn lookup_mx(&self, domain: &str) -> Result<Vec<MxRecord>> {
        let lookup = self
            .inner
            .mx_lookup(domain)
            .await
            .map_err(|e| NetworkError::Resolve {
                name: domain.into(),
                reason: e.to_string(),
            })?;
        Ok(lookup.iter().map(map_mx).collect())
    }

    async fn lookup_ip(&self, host: &str) -> Result<Vec<AddressRecord>> {
        let lookup = self
            .inner
            .lookup_ip(host)
            .await
            .map_err(|e| NetworkError::Resolve {
                name: host.into(),
                reason: e.to_string(),
            })?;
        Ok(lookup.iter().map(AddressRecord).collect())
    }

    async fn lookup_txt(&self, name: &str) -> Result<Vec<TxtRecord>> {
        let lookup = self
            .inner
            .txt_lookup(name)
            .await
            .map_err(|e| NetworkError::Resolve {
                name: name.into(),
                reason: e.to_string(),
            })?;
        Ok(lookup.iter().map(map_txt).collect())
    }

    async fn reverse_lookup(&self, ip: IpAddr) -> Result<Vec<PtrRecord>> {
        let lookup = self
            .inner
            .reverse_lookup(ip)
            .await
            .map_err(|e| NetworkError::Resolve {
                name: ip.to_string(),
                reason: e.to_string(),
            })?;
        // `PTR` implements `Display` as its inner `Name`.
        Ok(lookup
            .iter()
            .map(|ptr| PtrRecord(ptr.to_string().trim_end_matches('.').to_string()))
            .collect())
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
