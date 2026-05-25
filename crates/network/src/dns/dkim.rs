//! DKIM key record (a TXT record at `<selector>._domainkey.<domain>`).

use crate::dns::txt::parse_tag_map;
use crate::error::{NetworkError, Result};

/// A parsed DKIM public-key record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DkimRecord {
    /// `v=` (usually `DKIM1`).
    pub version: Option<String>,
    /// `k=` key type (e.g. `rsa`, `ed25519`).
    pub key_type: Option<String>,
    /// `p=` base64 public key (required).
    pub public_key: String,
}

impl DkimRecord {
    /// Parse a DKIM TXT record body.
    ///
    /// # Errors
    /// [`NetworkError::Record`] if the required `p=` tag is missing.
    pub fn parse(raw: &str) -> Result<Self> {
        let tags = parse_tag_map(raw);
        let public_key = tags.get("p").cloned().ok_or_else(|| NetworkError::Record {
            kind: "DKIM".into(),
            reason: "missing public key (p=)".into(),
        })?;
        Ok(Self {
            version: tags.get("v").cloned(),
            key_type: tags.get("k").cloned(),
            public_key,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_rsa_dkim_record() {
        let r = DkimRecord::parse("v=DKIM1; k=rsa; p=MIGfMA0GCSq").unwrap();
        assert_eq!(r.version.as_deref(), Some("DKIM1"));
        assert_eq!(r.key_type.as_deref(), Some("rsa"));
        assert_eq!(r.public_key, "MIGfMA0GCSq");
    }

    #[test]
    fn rejects_dkim_without_public_key() {
        assert!(DkimRecord::parse("v=DKIM1; k=rsa").is_err());
    }
}
