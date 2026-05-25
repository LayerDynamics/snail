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

/// A parsed DMARC record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DmarcRecord {
    /// `p=` policy (required; identifies the record as DMARC).
    pub policy: DmarcPolicy,
    /// `rua=` aggregate-report URI, if present.
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
            return Err(NetworkError::Record {
                kind: "DMARC".into(),
                reason: "not a DMARC1 record".into(),
            });
        }
        let policy = match tags.get("p").map(String::as_str) {
            Some("none") => DmarcPolicy::None,
            Some("quarantine") => DmarcPolicy::Quarantine,
            Some("reject") => DmarcPolicy::Reject,
            other => {
                return Err(NetworkError::Record {
                    kind: "DMARC".into(),
                    reason: format!("invalid policy `{}`", other.unwrap_or("<missing>")),
                });
            }
        };
        Ok(Self {
            policy,
            rua: tags.get("rua").cloned(),
        })
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
    }

    #[test]
    fn rejects_non_dmarc_txt() {
        assert!(DmarcRecord::parse("v=spf1 -all").is_err());
    }
}
