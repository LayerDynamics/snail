//! DMARC evaluation (RFC 7489 §6): record discovery (with org-domain fallback),
//! SPF/DKIM identifier alignment, and policy disposition.

use std::time::{SystemTime, UNIX_EPOCH};

use crate::dns::{AlignmentMode, DmarcPolicy, DmarcRecord, DnsResolver};
use crate::spf::SpfResult;

/// What the receiver should do with a message per DMARC.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DmarcDisposition {
    /// Deliver normally — either DMARC passed, or the domain publishes no record.
    None,
    /// Deliver but treat as suspicious (`p=quarantine` applied to a failure).
    Quarantine,
    /// Refuse the message (`p=reject` applied to a failure).
    Reject,
}

impl DmarcDisposition {
    /// The lowercase token used in an aggregate report's `<disposition>`.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            DmarcDisposition::None => "none",
            DmarcDisposition::Quarantine => "quarantine",
            DmarcDisposition::Reject => "reject",
        }
    }
}

/// The outcome of a DMARC evaluation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DmarcResult {
    /// Whether the domain published a DMARC record (`false` → `dmarc=none`).
    pub record_found: bool,
    /// Whether DMARC passed (an aligned SPF or DKIM pass).
    pub pass: bool,
    /// Whether SPF was aligned and passed.
    pub spf_aligned: bool,
    /// Whether at least one DKIM signature was aligned and passed.
    pub dkim_aligned: bool,
    /// The disposition to apply (after `pct` sampling).
    pub disposition: DmarcDisposition,
    /// The domain whose DMARC record was applied — the reporting domain. Empty
    /// when no record was found.
    pub policy_domain: String,
    /// The applied DMARC record (for an aggregate report's `policy_published`
    /// section and its `rua` address); `None` when no record was found.
    pub published: Option<DmarcRecord>,
}

impl DmarcResult {
    /// The lowercase `dmarc=` token for an `Authentication-Results` header.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        if !self.record_found {
            "none"
        } else if self.pass {
            "pass"
        } else {
            "fail"
        }
    }

    /// A "no DMARC opinion" result (domain publishes no record): deliver normally.
    fn none() -> Self {
        Self {
            record_found: false,
            pass: false,
            spf_aligned: false,
            dkim_aligned: false,
            disposition: DmarcDisposition::None,
            policy_domain: String::new(),
            published: None,
        }
    }
}

/// One verified DKIM signing domain (the `d=` of a signature that passed).
/// DMARC aligns the `From:` domain against these.
pub type DkimPassDomains<'a> = &'a [&'a str];

/// Evaluate DMARC for a received message.
///
/// - `from_domain`: the RFC 5322 `From:` header domain (the DMARC identifier).
/// - `spf_result` / `spf_domain`: the SPF result and the `MAIL FROM` domain it
///   authenticated.
/// - `dkim_pass_domains`: the `d=` domains of DKIM signatures that verified.
///
/// Returns the alignment outcome and the disposition to apply.
pub async fn evaluate(
    resolver: &dyn DnsResolver,
    from_domain: &str,
    spf_result: SpfResult,
    spf_domain: &str,
    dkim_pass_domains: DkimPassDomains<'_>,
) -> DmarcResult {
    let from_domain = from_domain.trim().trim_end_matches('.');
    if from_domain.is_empty() {
        return DmarcResult::none();
    }

    // RFC 7489 §6.6.3: query `_dmarc.<from>`; if absent, query the org domain.
    let from_org = organizational_domain(from_domain);
    let (record, at_org) = match lookup(resolver, from_domain).await {
        Some(r) => (r, false),
        None => {
            if from_org != from_domain {
                match lookup(resolver, &from_org).await {
                    Some(r) => (r, true),
                    None => return DmarcResult::none(),
                }
            } else {
                return DmarcResult::none();
            }
        }
    };

    // Alignment (§3.1): SPF aligns the MAIL FROM domain, DKIM aligns each d=.
    let spf_aligned =
        spf_result == SpfResult::Pass && aligned(spf_domain, from_domain, record.aspf);
    let dkim_aligned = dkim_pass_domains
        .iter()
        .any(|d| aligned(d, from_domain, record.adkim));
    let pass = spf_aligned || dkim_aligned;

    let disposition = if pass {
        DmarcDisposition::None
    } else {
        // The applicable policy is `sp` when the record was found at the org
        // domain and the From domain is a strict subdomain (§6.6.3); else `p`.
        let policy = if at_org && from_domain != from_org {
            record.subdomain_policy.unwrap_or(record.policy)
        } else {
            record.policy
        };
        apply_pct(policy, record.pct)
    };

    let policy_domain = if at_org {
        from_org
    } else {
        from_domain.to_string()
    };
    DmarcResult {
        record_found: true,
        pass,
        spf_aligned,
        dkim_aligned,
        disposition,
        policy_domain,
        published: Some(record),
    }
}

/// The organizational (registrable) domain of `domain` per the Public Suffix
/// List, lowercased. Falls back to the input if the PSL has no entry (e.g. an
/// unknown TLD or a bare hostname).
#[must_use]
pub fn organizational_domain(domain: &str) -> String {
    let lower = domain.trim().trim_end_matches('.').to_ascii_lowercase();
    psl::domain_str(&lower)
        .map(str::to_ascii_lowercase)
        .unwrap_or(lower)
}

/// Whether `authenticated` is aligned with `from` under `mode`.
fn aligned(authenticated: &str, from: &str, mode: AlignmentMode) -> bool {
    let a = authenticated
        .trim()
        .trim_end_matches('.')
        .to_ascii_lowercase();
    let f = from.trim().trim_end_matches('.').to_ascii_lowercase();
    if a.is_empty() {
        return false;
    }
    match mode {
        AlignmentMode::Strict => a == f,
        AlignmentMode::Relaxed => organizational_domain(&a) == organizational_domain(&f),
    }
}

/// Fetch and parse the DMARC record at `_dmarc.<domain>` (the first `v=DMARC1`).
async fn lookup(resolver: &dyn DnsResolver, domain: &str) -> Option<DmarcRecord> {
    resolver.lookup_dmarc(domain).await.ok()
}

/// Apply the `pct` sampling (§6.6.4): with probability `pct%` the full policy is
/// used; otherwise it is downgraded one step (reject→quarantine, quarantine→none).
fn apply_pct(policy: DmarcPolicy, pct: u8) -> DmarcDisposition {
    let full = match policy {
        DmarcPolicy::None => DmarcDisposition::None,
        DmarcPolicy::Quarantine => DmarcDisposition::Quarantine,
        DmarcPolicy::Reject => DmarcDisposition::Reject,
    };
    if pct >= 100 || sample_in_pct(pct) {
        full
    } else {
        match full {
            DmarcDisposition::Reject => DmarcDisposition::Quarantine,
            DmarcDisposition::Quarantine | DmarcDisposition::None => DmarcDisposition::None,
        }
    }
}

/// Best-effort `pct` sampler: `true` for ~`pct`% of calls. Uses the wall-clock
/// nanoseconds as a cheap entropy source — `pct` is a deployment rollout knob,
/// not a security control, so a non-cryptographic sample is appropriate.
fn sample_in_pct(pct: u8) -> bool {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0);
    (nanos % 100) < u32::from(pct)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns::{AddressRecord, MxRecord, PtrRecord, TxtRecord};
    use crate::error::Result;
    use async_trait::async_trait;
    use std::collections::BTreeMap;
    use std::net::IpAddr;

    struct Mock {
        txt: BTreeMap<String, String>,
    }

    #[async_trait]
    impl DnsResolver for Mock {
        async fn lookup_mx(&self, _d: &str) -> Result<Vec<MxRecord>> {
            Ok(vec![])
        }
        async fn lookup_ip(&self, _h: &str) -> Result<Vec<AddressRecord>> {
            Ok(vec![])
        }
        async fn lookup_txt(&self, name: &str) -> Result<Vec<TxtRecord>> {
            Ok(self
                .txt
                .get(name)
                .map(|v| vec![TxtRecord(v.clone())])
                .unwrap_or_default())
        }
        async fn reverse_lookup(&self, _ip: IpAddr) -> Result<Vec<PtrRecord>> {
            Ok(vec![])
        }
    }

    fn mock(records: &[(&str, &str)]) -> Mock {
        Mock {
            txt: records
                .iter()
                .map(|(n, v)| ((*n).to_string(), (*v).to_string()))
                .collect(),
        }
    }

    #[test]
    fn org_domain_uses_public_suffix_list() {
        assert_eq!(organizational_domain("mail.example.com"), "example.com");
        assert_eq!(organizational_domain("a.b.example.co.uk"), "example.co.uk");
        assert_eq!(organizational_domain("Example.COM"), "example.com");
    }

    #[test]
    fn relaxed_alignment_respects_multilabel_tlds() {
        // Same org under co.uk aligns; different registrable domains do not.
        assert!(aligned(
            "mail.example.co.uk",
            "news.example.co.uk",
            AlignmentMode::Relaxed
        ));
        assert!(!aligned(
            "evil.co.uk",
            "example.co.uk",
            AlignmentMode::Relaxed
        ));
        // Strict requires an exact match.
        assert!(!aligned(
            "mail.example.com",
            "example.com",
            AlignmentMode::Strict
        ));
        assert!(aligned("example.com", "example.com", AlignmentMode::Strict));
    }

    #[tokio::test]
    async fn no_record_is_none_disposition() {
        let r = evaluate(
            &mock(&[]),
            "example.com",
            SpfResult::Fail,
            "example.com",
            &[],
        )
        .await;
        assert!(!r.record_found);
        assert_eq!(r.disposition, DmarcDisposition::None);
        assert_eq!(r.as_str(), "none");
    }

    #[tokio::test]
    async fn passes_on_aligned_spf() {
        let r = evaluate(
            &mock(&[("_dmarc.example.com", "v=DMARC1; p=reject")]),
            "example.com",
            SpfResult::Pass,
            "mail.example.com", // relaxed-aligned with example.com
            &[],
        )
        .await;
        assert!(r.pass && r.spf_aligned);
        assert_eq!(r.disposition, DmarcDisposition::None);
        assert_eq!(r.as_str(), "pass");
    }

    #[tokio::test]
    async fn passes_on_aligned_dkim_even_if_spf_fails() {
        let r = evaluate(
            &mock(&[("_dmarc.example.com", "v=DMARC1; p=reject")]),
            "example.com",
            SpfResult::Fail,
            "bounce.other.test",
            &["example.com"], // aligned DKIM d=
        )
        .await;
        assert!(r.pass && r.dkim_aligned && !r.spf_aligned);
    }

    #[tokio::test]
    async fn fails_and_rejects_when_unaligned() {
        let r = evaluate(
            &mock(&[("_dmarc.example.com", "v=DMARC1; p=reject")]),
            "example.com",
            SpfResult::Pass,
            "attacker.test", // not aligned with example.com
            &["attacker.test"],
        )
        .await;
        assert!(!r.pass);
        assert_eq!(r.disposition, DmarcDisposition::Reject);
        assert_eq!(r.as_str(), "fail");
    }

    #[tokio::test]
    async fn strict_alignment_rejects_subdomain_spf() {
        // aspf=s: mail.example.com does NOT strictly align with example.com.
        let r = evaluate(
            &mock(&[("_dmarc.example.com", "v=DMARC1; p=quarantine; aspf=s")]),
            "example.com",
            SpfResult::Pass,
            "mail.example.com",
            &[],
        )
        .await;
        assert!(!r.pass);
        assert_eq!(r.disposition, DmarcDisposition::Quarantine);
    }

    #[tokio::test]
    async fn org_domain_fallback_and_subdomain_policy() {
        // No record at the subdomain; the org record applies `sp` to the subdomain.
        let r = evaluate(
            &mock(&[("_dmarc.example.com", "v=DMARC1; p=none; sp=reject")]),
            "sub.example.com",
            SpfResult::Fail,
            "attacker.test",
            &[],
        )
        .await;
        assert!(r.record_found && !r.pass);
        // `sp=reject` applies because the From domain is a subdomain.
        assert_eq!(r.disposition, DmarcDisposition::Reject);
    }

    #[tokio::test]
    async fn pct_zero_downgrades_reject_to_quarantine() {
        let r = evaluate(
            &mock(&[("_dmarc.example.com", "v=DMARC1; p=reject; pct=0")]),
            "example.com",
            SpfResult::Fail,
            "attacker.test",
            &[],
        )
        .await;
        // pct=0 never applies the full policy → reject downgrades to quarantine.
        assert_eq!(r.disposition, DmarcDisposition::Quarantine);
    }
}
