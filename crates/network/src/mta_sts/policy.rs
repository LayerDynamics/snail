//! MTA-STS policy (RFC 8461 §3.2) and discovery TXT (§3.1) parsing, plus the
//! `mx:` pattern matching that authorizes a mail exchange under a policy.

use crate::error::{NetworkError, Result};

/// RFC 8461 §3.2 upper bound on `max_age` (one year-ish): 31557600 seconds. A
/// larger value is clamped so a typo cannot pin a bad policy for a very long time.
const MAX_AGE_CAP: u64 = 31_557_600;

/// The enforcement mode of an MTA-STS policy (RFC 8461 §3.2 `mode`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MtaStsMode {
    /// `enforce`: the sender MUST NOT deliver to a non-matching MX, and MUST use
    /// a PKIX-validated TLS connection to a matching one — no cleartext fallback.
    Enforce,
    /// `testing`: TLS failures are non-fatal (the sender still delivers) but
    /// SHOULD be reported. Snail treats `testing` as opportunistic delivery.
    Testing,
    /// `none`: the domain is explicitly *not* asserting an MTA-STS policy.
    None,
}

/// A parsed MTA-STS policy as served at
/// `https://mta-sts.<domain>/.well-known/mta-sts.txt` (RFC 8461 §3.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MtaStsPolicy {
    /// Enforcement mode.
    pub mode: MtaStsMode,
    /// Allowed MX host patterns (lowercased); a pattern may carry a single
    /// leading `*.` wildcard that matches exactly one DNS label.
    pub mx: Vec<String>,
    /// Cache lifetime in seconds (clamped to [`MAX_AGE_CAP`]).
    pub max_age: u64,
}

impl MtaStsPolicy {
    /// Parse the policy file body. Lines are `key: value`, CRLF- or LF-separated
    /// (RFC 8461 §3.2); keys are matched case-insensitively and unknown keys are
    /// ignored. `version: STSv1`, `mode`, and `max_age` are required; at least
    /// one `mx` is required when the mode is `enforce` or `testing`.
    ///
    /// # Errors
    /// [`NetworkError::Record`] if the body is missing a required field, carries
    /// an unsupported version/mode, or a value does not parse.
    pub fn parse(body: &str) -> Result<Self> {
        let mut version_ok = false;
        let mut mode = None;
        let mut max_age = None;
        let mut mx = Vec::new();

        for raw in body.lines() {
            let line = raw.trim();
            if line.is_empty() {
                continue;
            }
            let Some((key, value)) = line.split_once(':') else {
                return Err(record_err("malformed policy line (no `:`)"));
            };
            let value = value.trim();
            match key.trim().to_ascii_lowercase().as_str() {
                "version" => {
                    if !value.eq_ignore_ascii_case("STSv1") {
                        return Err(record_err(&format!("unsupported version `{value}`")));
                    }
                    version_ok = true;
                }
                "mode" => {
                    mode = Some(match value.to_ascii_lowercase().as_str() {
                        "enforce" => MtaStsMode::Enforce,
                        "testing" => MtaStsMode::Testing,
                        "none" => MtaStsMode::None,
                        other => return Err(record_err(&format!("unknown mode `{other}`"))),
                    });
                }
                "max_age" => {
                    let n: u64 = value
                        .parse()
                        .map_err(|_| record_err(&format!("invalid max_age `{value}`")))?;
                    max_age = Some(n.min(MAX_AGE_CAP));
                }
                "mx" if !value.is_empty() => mx.push(value.to_ascii_lowercase()),
                // RFC 8461 §3.2: unrecognised keys are ignored for extensibility.
                _ => {}
            }
        }

        if !version_ok {
            return Err(record_err("missing `version: STSv1`"));
        }
        let mode = mode.ok_or_else(|| record_err("missing `mode`"))?;
        let max_age = max_age.ok_or_else(|| record_err("missing `max_age`"))?;
        if matches!(mode, MtaStsMode::Enforce | MtaStsMode::Testing) && mx.is_empty() {
            return Err(record_err("policy in enforce/testing mode lists no `mx`"));
        }

        Ok(Self { mode, mx, max_age })
    }

    /// Whether `host` (an MX hostname) is authorized by this policy's `mx`
    /// patterns (RFC 8461 §4.1). Matching is case-insensitive and ignores a
    /// trailing root dot; a pattern with a leading `*.` matches exactly one label
    /// in that position — `*.example.com` matches `mx.example.com`, but neither
    /// `example.com` nor `a.b.example.com`.
    #[must_use]
    pub fn allows_mx(&self, host: &str) -> bool {
        let host = host.trim_end_matches('.').to_ascii_lowercase();
        if host.is_empty() {
            return false;
        }
        self.mx.iter().any(|pat| mx_pattern_matches(pat, &host))
    }
}

/// Match a single MTA-STS `mx` pattern against a host (host already lowercased).
fn mx_pattern_matches(pattern: &str, host: &str) -> bool {
    let pattern = pattern.trim_end_matches('.');
    if let Some(suffix) = pattern.strip_prefix("*.") {
        // `*.<suffix>` matches `<one-label>.<suffix>` and nothing else.
        match host.split_once('.') {
            Some((label, rest)) => !label.is_empty() && rest == suffix,
            None => false,
        }
    } else {
        pattern == host
    }
}

/// Parse the MTA-STS discovery TXT record at `_mta-sts.<domain>` (RFC 8461 §3.1),
/// returning the policy `id` when the record is a valid `v=STSv1` record with a
/// well-formed id (`1*32(ALPHA / DIGIT)`). Malformed fields are skipped; an
/// absent version or id yields `None`.
#[must_use]
pub fn parse_sts_txt(txt: &str) -> Option<String> {
    let mut version_ok = false;
    let mut id = None;
    for field in txt.split(';') {
        let field = field.trim();
        if field.is_empty() {
            continue;
        }
        let Some((key, value)) = field.split_once('=') else {
            continue;
        };
        match key.trim() {
            "v" => version_ok = value.trim().eq_ignore_ascii_case("STSv1"),
            "id" => id = Some(value.trim().to_string()),
            _ => {}
        }
    }
    let id = id?;
    (version_ok && is_valid_id(&id)).then_some(id)
}

/// RFC 8461 §3.1 policy id syntax: `1*32(ALPHA / DIGIT)`.
fn is_valid_id(id: &str) -> bool {
    !id.is_empty() && id.len() <= 32 && id.bytes().all(|b| b.is_ascii_alphanumeric())
}

fn record_err(reason: &str) -> NetworkError {
    NetworkError::Record {
        kind: "MTA-STS".into(),
        reason: reason.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_full_enforce_policy() {
        let body = "version: STSv1\r\nmode: enforce\r\nmx: mail.example.com\r\nmx: *.example.net\r\nmax_age: 604800\r\n";
        let p = MtaStsPolicy::parse(body).unwrap();
        assert_eq!(p.mode, MtaStsMode::Enforce);
        assert_eq!(p.max_age, 604800);
        assert_eq!(p.mx, vec!["mail.example.com", "*.example.net"]);
    }

    #[test]
    fn parses_lf_only_and_ignores_unknown_keys() {
        let body = "version: STSv1\nmode: testing\nmx: mx.example.com\nmax_age: 86400\nfuture-key: whatever\n";
        let p = MtaStsPolicy::parse(body).unwrap();
        assert_eq!(p.mode, MtaStsMode::Testing);
        assert_eq!(p.max_age, 86400);
    }

    #[test]
    fn max_age_is_clamped_to_the_cap() {
        let body = "version: STSv1\nmode: none\nmax_age: 999999999999\n";
        let p = MtaStsPolicy::parse(body).unwrap();
        assert_eq!(p.max_age, MAX_AGE_CAP);
    }

    #[test]
    fn mode_none_needs_no_mx() {
        let body = "version: STSv1\nmode: none\nmax_age: 0\n";
        assert!(MtaStsPolicy::parse(body).is_ok());
    }

    #[test]
    fn enforce_without_mx_is_rejected() {
        let body = "version: STSv1\nmode: enforce\nmax_age: 100\n";
        assert!(MtaStsPolicy::parse(body).is_err());
    }

    #[test]
    fn missing_version_is_rejected() {
        let body = "mode: enforce\nmx: mx.example.com\nmax_age: 100\n";
        assert!(MtaStsPolicy::parse(body).is_err());
    }

    #[test]
    fn unknown_mode_is_rejected() {
        let body = "version: STSv1\nmode: paranoid\nmx: m\nmax_age: 100\n";
        assert!(MtaStsPolicy::parse(body).is_err());
    }

    #[test]
    fn exact_mx_matches_case_insensitively() {
        let p = MtaStsPolicy {
            mode: MtaStsMode::Enforce,
            mx: vec!["mail.example.com".into()],
            max_age: 100,
        };
        assert!(p.allows_mx("MAIL.EXAMPLE.COM"));
        assert!(p.allows_mx("mail.example.com."));
        assert!(!p.allows_mx("other.example.com"));
    }

    #[test]
    fn wildcard_mx_matches_exactly_one_label() {
        let p = MtaStsPolicy {
            mode: MtaStsMode::Enforce,
            mx: vec!["*.example.com".into()],
            max_age: 100,
        };
        assert!(p.allows_mx("mx1.example.com"));
        assert!(p.allows_mx("mx2.EXAMPLE.com"));
        // The wildcard must not match the bare apex or a multi-label host.
        assert!(!p.allows_mx("example.com"));
        assert!(!p.allows_mx("a.b.example.com"));
        // Nor a non-empty label over a different suffix.
        assert!(!p.allows_mx("mx.example.net"));
    }

    #[test]
    fn parses_discovery_txt_id() {
        assert_eq!(
            parse_sts_txt("v=STSv1; id=20160831085700Z;"),
            Some("20160831085700Z".to_string())
        );
        assert_eq!(
            parse_sts_txt("v=STSv1; id=abc123"),
            Some("abc123".to_string())
        );
    }

    #[test]
    fn rejects_txt_without_version_or_with_bad_id() {
        assert_eq!(parse_sts_txt("id=abc123"), None);
        assert_eq!(parse_sts_txt("v=STSv1; id="), None);
        // id with a non-alphanumeric char is malformed.
        assert_eq!(parse_sts_txt("v=STSv1; id=ab.cd"), None);
        // id longer than 32 chars is malformed.
        let long = "a".repeat(33);
        assert_eq!(parse_sts_txt(&format!("v=STSv1; id={long}")), None);
    }
}
