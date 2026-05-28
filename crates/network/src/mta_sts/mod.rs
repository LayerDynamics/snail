//! MTA-STS (RFC 8461): discover, fetch, cache, and apply a recipient domain's
//! SMTP MTA Strict Transport Security policy.
//!
//! [`MtaStsResolver`] is the entry point used by the outbound relay. Given a
//! recipient domain it:
//!
//! 1. looks up the discovery TXT at `_mta-sts.<domain>` for the policy `id`
//!    (§3.1),
//! 2. reuses a cached policy whose `id` still matches, otherwise
//! 3. fetches `https://mta-sts.<domain>/.well-known/mta-sts.txt` over a
//!    PKIX-authenticated connection (§3.3) and parses it (§3.2),
//! 4. caches the result — positively for the policy's `max_age`, negatively for a
//!    short window when there is no usable policy — bounding both memory and the
//!    rate of network probing.
//!
//! The relay then asks the returned [`MtaStsPolicy`] whether each candidate MX is
//! authorized ([`MtaStsPolicy::allows_mx`]) and, in `enforce` mode, requires a
//! PKIX-validated TLS connection (built from [`MtaStsResolver::pkix_config`]) with
//! no cleartext fallback.

pub mod fetch;
pub mod policy;

pub use policy::{MtaStsMode, MtaStsPolicy, parse_sts_txt};

use std::collections::HashMap;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use rustls::ClientConfig;

use crate::dns::DnsResolver;
use crate::error::Result;
use crate::tls::TlsConfig;

/// Cap on the number of cached policies (positive + negative). Bounds memory
/// under a flood of mail to high-cardinality recipient domains; the oldest entry
/// by fetch time is evicted when a new domain would exceed the cap.
const MAX_CACHE: usize = 4096;

/// How long a "no usable policy" result is remembered before re-probing, so a
/// broken or absent policy host is not re-contacted once per queued message.
const NEGATIVE_TTL: Duration = Duration::from_secs(600);

/// One cached MTA-STS lookup, positive (a policy) or negative (no usable policy).
struct CacheEntry {
    /// The discovery TXT `id` this entry was stored for (`None` when there was no
    /// usable discovery record).
    id: Option<String>,
    /// The in-force policy, or `None` for a negative entry.
    policy: Option<MtaStsPolicy>,
    /// When the entry was stored.
    fetched: Instant,
    /// How long the entry stays valid (policy `max_age`, or [`NEGATIVE_TTL`]).
    ttl: Duration,
}

impl CacheEntry {
    fn is_fresh(&self) -> bool {
        self.fetched.elapsed() < self.ttl
    }
}

/// Resolves and caches MTA-STS policies (RFC 8461) for the outbound relay.
///
/// Holds a single PKIX-verifying client TLS config used both to fetch policies
/// over HTTPS and — exposed via [`Self::pkix_config`] — to enforce authenticated
/// TLS to a policy-matched MX.
pub struct MtaStsResolver {
    resolver: Arc<dyn DnsResolver>,
    pkix: Arc<ClientConfig>,
    cache: Mutex<HashMap<String, CacheEntry>>,
}

impl MtaStsResolver {
    /// Build a resolver over `resolver`, constructing a PKIX-verifying client TLS
    /// config from the bundled webpki roots.
    ///
    /// # Errors
    /// [`crate::NetworkError::Tls`] if the PKIX trust anchors are unavailable.
    pub fn new(resolver: Arc<dyn DnsResolver>) -> Result<Self> {
        Ok(Self {
            resolver,
            pkix: TlsConfig::pkix_client()?,
            cache: Mutex::new(HashMap::new()),
        })
    }

    /// The PKIX-verifying client config the relay uses for enforced (`enforce`)
    /// TLS — the same trust anchors used to fetch the policy.
    #[must_use]
    pub fn pkix_config(&self) -> &Arc<ClientConfig> {
        &self.pkix
    }

    /// Resolve the in-force MTA-STS policy for `domain`, or `None` if the domain
    /// publishes no usable policy (no discovery TXT, or the policy could not be
    /// fetched and none is cached). Results are cached: positively for the
    /// policy's `max_age`, negatively for [`NEGATIVE_TTL`]; a cached policy whose
    /// discovery `id` still matches is reused without a fetch.
    pub async fn policy_for(&self, domain: &str) -> Option<MtaStsPolicy> {
        let domain = domain.trim_end_matches('.').to_ascii_lowercase();
        let id = self.discover_id(&domain).await;

        // Reuse a fresh cache entry when it still applies.
        {
            let cache = self.lock();
            if let Some(entry) = cache.get(&domain)
                && entry.is_fresh()
            {
                match (&id, &entry.id) {
                    // Positive entry whose discovery id still matches: reuse.
                    (Some(txt_id), Some(cached_id)) if txt_id == cached_id => {
                        return entry.policy.clone();
                    }
                    // Negative entry, discovery still finds nothing: reuse.
                    (None, None) if entry.policy.is_none() => return None,
                    // id changed / (re)appeared / disappeared: re-resolve below.
                    _ => {}
                }
            }
        }

        // No discovery record → no MTA-STS. Negative-cache and report none.
        let Some(id) = id else {
            self.store(
                domain,
                CacheEntry {
                    id: None,
                    policy: None,
                    fetched: Instant::now(),
                    ttl: NEGATIVE_TTL,
                },
            );
            return None;
        };

        // Fetch + parse the policy over a PKIX-authenticated HTTPS connection.
        match self.fetch_and_parse(&domain).await {
            Ok(parsed) => {
                let ttl = Duration::from_secs(parsed.max_age.max(1));
                self.store(
                    domain,
                    CacheEntry {
                        id: Some(id),
                        policy: Some(parsed.clone()),
                        fetched: Instant::now(),
                        ttl,
                    },
                );
                Some(parsed)
            }
            // RFC 8461 §5: if a non-expired policy is cached, keep applying it
            // even when a refresh fails; otherwise treat the domain as policy-free.
            Err(_) => {
                if let Some(cached) = self.cached_policy(&domain) {
                    return Some(cached);
                }
                self.store(
                    domain,
                    CacheEntry {
                        id: None,
                        policy: None,
                        fetched: Instant::now(),
                        ttl: NEGATIVE_TTL,
                    },
                );
                None
            }
        }
    }

    async fn discover_id(&self, domain: &str) -> Option<String> {
        let name = format!("_mta-sts.{domain}");
        let txts = self.resolver.lookup_txt(&name).await.ok()?;
        txts.iter().find_map(|t| parse_sts_txt(&t.0))
    }

    async fn fetch_and_parse(&self, domain: &str) -> Result<MtaStsPolicy> {
        let body = fetch::fetch_policy(self.resolver.as_ref(), &self.pkix, domain).await?;
        MtaStsPolicy::parse(&body)
    }

    fn cached_policy(&self, domain: &str) -> Option<MtaStsPolicy> {
        self.lock()
            .get(domain)
            .filter(|e| e.is_fresh())
            .and_then(|e| e.policy.clone())
    }

    fn store(&self, domain: String, entry: CacheEntry) {
        let mut cache = self.lock();
        if cache.len() >= MAX_CACHE
            && !cache.contains_key(&domain)
            && let Some(oldest) = cache
                .iter()
                .min_by_key(|(_, e)| e.fetched)
                .map(|(k, _)| k.clone())
        {
            cache.remove(&oldest);
        }
        cache.insert(domain, entry);
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<String, CacheEntry>> {
        self.cache.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns::{AddressRecord, MxRecord, PtrRecord, TxtRecord};
    use async_trait::async_trait;
    use std::net::IpAddr;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// A resolver that returns a canned TXT for the discovery name and counts how
    /// many TXT lookups it served (to prove caching). `lookup_ip` returns nothing,
    /// so any actual HTTPS fetch fails fast — the tests exercise the discovery and
    /// caching paths, not the live network.
    struct CountingResolver {
        txt: Option<String>,
        txt_lookups: AtomicUsize,
    }

    #[async_trait]
    impl DnsResolver for CountingResolver {
        async fn lookup_mx(&self, _domain: &str) -> Result<Vec<MxRecord>> {
            Ok(vec![])
        }
        async fn lookup_ip(&self, _host: &str) -> Result<Vec<AddressRecord>> {
            Ok(vec![])
        }
        async fn lookup_txt(&self, name: &str) -> Result<Vec<TxtRecord>> {
            self.txt_lookups.fetch_add(1, Ordering::SeqCst);
            if name.starts_with("_mta-sts.") {
                Ok(self.txt.iter().cloned().map(TxtRecord).collect())
            } else {
                Ok(vec![])
            }
        }
        async fn reverse_lookup(&self, _ip: IpAddr) -> Result<Vec<PtrRecord>> {
            Ok(vec![])
        }
    }

    #[tokio::test]
    async fn no_discovery_txt_is_negative_cached() {
        let resolver = Arc::new(CountingResolver {
            txt: None,
            txt_lookups: AtomicUsize::new(0),
        });
        let sts = MtaStsResolver::new(resolver.clone()).unwrap();
        assert!(sts.policy_for("example.com").await.is_none());
        // A second call within NEGATIVE_TTL still does a (cheap) discovery TXT
        // lookup but reuses the negative cache entry rather than re-fetching.
        assert!(sts.policy_for("example.com").await.is_none());
        // Two discovery lookups, but the second short-circuited on the cache.
        assert_eq!(resolver.txt_lookups.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn fetch_failure_with_no_cache_is_none() {
        // Discovery finds a valid id, but lookup_ip yields no address so the HTTPS
        // fetch fails — with nothing cached, the domain is treated as policy-free.
        let resolver = Arc::new(CountingResolver {
            txt: Some("v=STSv1; id=abc123".to_string()),
            txt_lookups: AtomicUsize::new(0),
        });
        let sts = MtaStsResolver::new(resolver).unwrap();
        assert!(sts.policy_for("example.com").await.is_none());
    }

    #[test]
    fn cache_evicts_oldest_when_full() {
        let resolver = Arc::new(CountingResolver {
            txt: None,
            txt_lookups: AtomicUsize::new(0),
        });
        let sts = MtaStsResolver::new(resolver).unwrap();
        for i in 0..(MAX_CACHE + 10) {
            sts.store(
                format!("d{i}.example"),
                CacheEntry {
                    id: None,
                    policy: None,
                    fetched: Instant::now(),
                    ttl: NEGATIVE_TTL,
                },
            );
        }
        assert!(sts.lock().len() <= MAX_CACHE);
    }
}
