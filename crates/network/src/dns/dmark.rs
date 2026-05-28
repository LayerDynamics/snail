//! DMARC policy record (a TXT record at `_dmarc.<domain>`). The file keeps the
//! scaffold spelling `dmark`; the type is `DmarcRecord`.

use crate::dns::txt::parse_tag_map;
use crate::error::{NetworkError, Result};

/// DMARC `p=` policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DmarcPolicy {
    /// `none` — monitor only.
    None,
    /// `quarantine` — treat failing mail as suspicious.
    Quarantine,
    /// `reject` — refuse failing mail.
    Reject,
}

/// DMARC identifier-alignment mode (`adkim=`/`aspf=`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AlignmentMode {
    /// `r` — relaxed: the organizational domains must match (the default).
    Relaxed,
    /// `s` — strict: the domains must match exactly.
    Strict,
}

impl AlignmentMode {
    fn parse(value: Option<&str>) -> Self {
        match value {
            Some("s") => Self::Strict,
            _ => Self::Relaxed, // "r" and the default
        }
    }
}

/// A parsed DMARC record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DmarcRecord {
    /// `p=` policy (required; identifies the record as DMARC).
    pub policy: DmarcPolicy,
    /// `sp=` subdomain policy (applies when the From domain is a subdomain of the
    /// domain that published this record); falls back to `policy` when absent.
    pub subdomain_policy: Option<DmarcPolicy>,
    /// `adkim=` DKIM alignment mode (default relaxed).
    pub adkim: AlignmentMode,
    /// `aspf=` SPF alignment mode (default relaxed).
    pub aspf: AlignmentMode,
    /// `pct=` percentage of failing mail the policy is applied to (default 100).
    pub pct: u8,
    /// `rua=` aggregate-report URI(s), if present.
    pub rua: Option<String>,
}

impl DmarcRecord {
    /// Parse a DMARC TXT record body.
    ///
    /// # Errors
    /// [`NetworkError::Record`] if `v=DMARC1` or a valid `p=` policy is absent.
    pub fn parse(raw: &str) -> Result<Self> {
        let tags = parse_tag_map(raw);
        if tags.get("v").map(String::as_str) != Some("DMARC1") {
            return Err(record_err("not a DMARC1 record"));
        }
        let policy = parse_policy(tags.get("p").map(String::as_str))
            .ok_or_else(|| record_err("missing or invalid p="))?;
        // `sp=` is optional; an invalid value is ignored (falls back to `p`).
        let subdomain_policy = tags.get("sp").and_then(|s| parse_policy(Some(s)));
        let pct = match tags.get("pct") {
            Some(p) => p.parse::<u8>().ok().filter(|n| *n <= 100).unwrap_or(100),
            None => 100,
        };
        Ok(Self {
            policy,
            subdomain_policy,
            adkim: AlignmentMode::parse(tags.get("adkim").map(String::as_str)),
            aspf: AlignmentMode::parse(tags.get("aspf").map(String::as_str)),
            pct,
            rua: tags.get("rua").cloned(),
        })
    }
}

fn parse_policy(value: Option<&str>) -> Option<DmarcPolicy> {
    match value {
        Some("none") => Some(DmarcPolicy::None),
        Some("quarantine") => Some(DmarcPolicy::Quarantine),
        Some("reject") => Some(DmarcPolicy::Reject),
        _ => None,
    }
}

fn record_err(reason: impl Into<String>) -> NetworkError {
    NetworkError::Record {
        kind: "DMARC".into(),
        reason: reason.into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_reject_policy_with_rua() {
        let r = DmarcRecord::parse("v=DMARC1; p=reject; rua=mailto:dmarc@example.com").unwrap();
        assert_eq!(r.policy, DmarcPolicy::Reject);
        assert_eq!(r.rua.as_deref(), Some("mailto:dmarc@example.com"));
        // Alignment defaults to relaxed; pct defaults to 100; no sp.
        assert_eq!(r.adkim, AlignmentMode::Relaxed);
        assert_eq!(r.aspf, AlignmentMode::Relaxed);
        assert_eq!(r.pct, 100);
        assert!(r.subdomain_policy.is_none());
    }

    #[test]
    fn parses_alignment_subdomain_and_pct() {
        let r = DmarcRecord::parse("v=DMARC1; p=quarantine; sp=reject; adkim=s; aspf=s; pct=20")
            .unwrap();
        assert_eq!(r.policy, DmarcPolicy::Quarantine);
        assert_eq!(r.subdomain_policy, Some(DmarcPolicy::Reject));
        assert_eq!(r.adkim, AlignmentMode::Strict);
        assert_eq!(r.aspf, AlignmentMode::Strict);
        assert_eq!(r.pct, 20);
    }

    #[test]
    fn invalid_pct_falls_back_to_100() {
        let r = DmarcRecord::parse("v=DMARC1; p=none; pct=999").unwrap();
        assert_eq!(r.pct, 100);
    }

    #[test]
    fn rejects_non_dmarc_txt() {
        assert!(DmarcRecord::parse("v=spf1 -all").is_err());
        assert!(DmarcRecord::parse("v=DMARC1; rua=mailto:x@y").is_err()); // no p=
    }
}
