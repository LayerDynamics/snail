//! SPF record parsing (RFC 7208 §4–§6): a `v=spf1` record is a sequence of
//! qualified mechanisms (directives) plus optional modifiers (`redirect`, `exp`).
//!
//! Parsing is deliberately total: a syntactically malformed record yields
//! [`NetworkError::Record`], which the evaluator maps to `PermError` per §4.6.

use std::net::{Ipv4Addr, Ipv6Addr};

use crate::error::{NetworkError, Result};

/// The qualifier prefixing a mechanism — determines the result when it matches.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Qualifier {
    /// `+` (the default) → `Pass`.
    Pass,
    /// `-` → `Fail`.
    Fail,
    /// `~` → `SoftFail`.
    SoftFail,
    /// `?` → `Neutral`.
    Neutral,
}

impl Qualifier {
    fn from_char(c: char) -> Option<Self> {
        match c {
            '+' => Some(Self::Pass),
            '-' => Some(Self::Fail),
            '~' => Some(Self::SoftFail),
            '?' => Some(Self::Neutral),
            _ => None,
        }
    }
}

/// One SPF mechanism (RFC 7208 §5). Domain-specs may contain macros, expanded at
/// evaluation time, so they are kept as raw strings here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Mechanism {
    /// `all` — always matches.
    All,
    /// `ip4:<network>[/prefix]`.
    Ip4 {
        /// The network address.
        net: Ipv4Addr,
        /// The CIDR prefix length (default 32).
        prefix: u8,
    },
    /// `ip6:<network>[/prefix]`.
    Ip6 {
        /// The network address.
        net: Ipv6Addr,
        /// The CIDR prefix length (default 128).
        prefix: u8,
    },
    /// `a[:domain][/v4][//v6]`.
    A {
        /// Target domain-spec (`None` = the current domain).
        domain: Option<String>,
        /// IPv4 CIDR length to match within (default 32).
        v4: u8,
        /// IPv6 CIDR length to match within (default 128).
        v6: u8,
    },
    /// `mx[:domain][/v4][//v6]`.
    Mx {
        /// Target domain-spec (`None` = the current domain).
        domain: Option<String>,
        /// IPv4 CIDR length (default 32).
        v4: u8,
        /// IPv6 CIDR length (default 128).
        v6: u8,
    },
    /// `include:<domain-spec>` — recursively evaluate another domain's policy.
    Include(String),
    /// `exists:<domain-spec>` — matches if the domain has any A record.
    Exists(String),
    /// `ptr[:domain]` — deprecated (RFC 7208 §5.5); still parsed and evaluated.
    Ptr(Option<String>),
}

/// A qualified mechanism.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Directive {
    /// The qualifier (default `+`/`Pass`).
    pub qualifier: Qualifier,
    /// The mechanism to test.
    pub mechanism: Mechanism,
}

/// A parsed `v=spf1` record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpfRecord {
    /// Directives in evaluation order (first match wins).
    pub directives: Vec<Directive>,
    /// `redirect=` modifier target, applied only if no directive matches (§6.1).
    pub redirect: Option<String>,
}

impl SpfRecord {
    /// Whether `term` is the SPF version token `v=spf1` (case-insensitive).
    #[must_use]
    pub fn is_spf_version(term: &str) -> bool {
        term.eq_ignore_ascii_case("v=spf1")
    }

    /// Parse the body of a `v=spf1` TXT record.
    ///
    /// # Errors
    /// [`NetworkError::Record`] if the version token is missing or a term is
    /// syntactically invalid (the evaluator treats this as `PermError`).
    pub fn parse(raw: &str) -> Result<Self> {
        let mut terms = raw.split_whitespace();
        match terms.next() {
            Some(v) if Self::is_spf_version(v) => {}
            _ => {
                return Err(record_err("missing v=spf1 version term"));
            }
        }

        let mut directives = Vec::new();
        let mut redirect = None;
        for term in terms {
            // Modifiers are `name=value`; mechanisms never contain `=` before any
            // `:` value, so a leading `name=` (with name a valid macro/word) is a
            // modifier. We recognise `redirect`/`exp`; unknown modifiers are
            // ignored per §6 (must be syntactically valid `name=macro-string`).
            if let Some((name, value)) = split_modifier(term) {
                match name.to_ascii_lowercase().as_str() {
                    "redirect" => redirect = Some(value.to_string()),
                    "exp" => {} // explanation text; not used in the decision
                    _ => {}     // unknown modifier: ignore (still syntactically valid)
                }
                continue;
            }
            directives.push(parse_directive(term)?);
        }
        Ok(Self {
            directives,
            redirect,
        })
    }
}

/// Recognise a modifier `name=value`. A term is a modifier only when the part
/// before the first `=` is a valid modifier name (alphanumeric, starting with a
/// letter) **and** there is no `:` before that `=` (which would make it a
/// mechanism with a value).
fn split_modifier(term: &str) -> Option<(&str, &str)> {
    let eq = term.find('=')?;
    let colon = term.find(':');
    if colon.is_some_and(|c| c < eq) {
        return None;
    }
    let (name, rest) = (&term[..eq], &term[eq + 1..]);
    let mut chars = name.chars();
    let first_ok = chars.next().is_some_and(|c| c.is_ascii_alphabetic());
    let rest_ok = chars.all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.');
    if first_ok && rest_ok {
        Some((name, rest))
    } else {
        None
    }
}

fn parse_directive(term: &str) -> Result<Directive> {
    let mut chars = term.chars();
    let first = chars
        .clone()
        .next()
        .ok_or_else(|| record_err("empty term"))?;
    let (qualifier, body) = match Qualifier::from_char(first) {
        Some(q) => {
            chars.next();
            (q, chars.as_str())
        }
        None => (Qualifier::Pass, term),
    };
    Ok(Directive {
        qualifier,
        mechanism: parse_mechanism(body)?,
    })
}

fn parse_mechanism(body: &str) -> Result<Mechanism> {
    // Split the mechanism name from any `:value` and `/cidr` suffix.
    let (name, rest) = match body.split_once(':') {
        Some((n, r)) => (n, Some(r)),
        None => {
            // No value: still may carry a `/cidr` (e.g. `a/24`).
            match body.split_once('/') {
                Some((n, _)) => (n, Some(&body[n.len()..])), // keep the leading '/'
                None => (body, None),
            }
        }
    };
    let name_lc = name.to_ascii_lowercase();
    match name_lc.as_str() {
        "all" => Ok(Mechanism::All),
        "ip4" => {
            let spec = rest.ok_or_else(|| record_err("ip4 requires an address"))?;
            let (net, prefix) = parse_ip4_cidr(spec)?;
            Ok(Mechanism::Ip4 { net, prefix })
        }
        "ip6" => {
            let spec = rest.ok_or_else(|| record_err("ip6 requires an address"))?;
            let (net, prefix) = parse_ip6_cidr(spec)?;
            Ok(Mechanism::Ip6 { net, prefix })
        }
        "a" | "mx" => {
            let (domain, v4, v6) = parse_domain_and_dual_cidr(rest)?;
            if name_lc == "a" {
                Ok(Mechanism::A { domain, v4, v6 })
            } else {
                Ok(Mechanism::Mx { domain, v4, v6 })
            }
        }
        "include" => Ok(Mechanism::Include(
            rest.filter(|r| !r.is_empty())
                .ok_or_else(|| record_err("include requires a domain"))?
                .to_string(),
        )),
        "exists" => Ok(Mechanism::Exists(
            rest.filter(|r| !r.is_empty())
                .ok_or_else(|| record_err("exists requires a domain"))?
                .to_string(),
        )),
        "ptr" => Ok(Mechanism::Ptr(
            rest.filter(|r| !r.is_empty()).map(ToString::to_string),
        )),
        other => Err(record_err(format!("unknown mechanism `{other}`"))),
    }
}

/// Parse `ip4` spec `addr[/prefix]`.
fn parse_ip4_cidr(spec: &str) -> Result<(Ipv4Addr, u8)> {
    let (addr, prefix) = match spec.split_once('/') {
        Some((a, p)) => (a, parse_prefix(p, 32)?),
        None => (spec, 32),
    };
    let net = addr
        .parse::<Ipv4Addr>()
        .map_err(|_| record_err(format!("bad ip4 address `{addr}`")))?;
    Ok((net, prefix))
}

/// Parse `ip6` spec `addr[/prefix]`.
fn parse_ip6_cidr(spec: &str) -> Result<(Ipv6Addr, u8)> {
    let (addr, prefix) = match spec.split_once('/') {
        Some((a, p)) => (a, parse_prefix(p, 128)?),
        None => (spec, 128),
    };
    let net = addr
        .parse::<Ipv6Addr>()
        .map_err(|_| record_err(format!("bad ip6 address `{addr}`")))?;
    Ok((net, prefix))
}

/// Parse the `[:domain][/v4][//v6]` tail of an `a`/`mx` mechanism. `rest` is the
/// part after the mechanism name (it may begin with the domain, or directly with
/// `/` for the dual-cidr form). The domain-spec is returned unexpanded.
fn parse_domain_and_dual_cidr(rest: Option<&str>) -> Result<(Option<String>, u8, u8)> {
    let Some(rest) = rest.filter(|r| !r.is_empty()) else {
        return Ok((None, 32, 128));
    };
    // The dual-cidr-length is a trailing `/v4` and/or `//v6`. Find the first '/'
    // that begins the cidr block; everything before it is the domain-spec.
    let (domain_part, cidr_part) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, ""),
    };
    let domain = if domain_part.is_empty() {
        None
    } else {
        Some(domain_part.to_string())
    };
    let (v4, v6) = parse_dual_cidr(cidr_part)?;
    Ok((domain, v4, v6))
}

/// Parse a dual-cidr-length block: `""`, `/v4`, `//v6`, or `/v4//v6`.
fn parse_dual_cidr(s: &str) -> Result<(u8, u8)> {
    if s.is_empty() {
        return Ok((32, 128));
    }
    // Split on the `//` that introduces the IPv6 length, if present.
    let (v4_part, v6_part) = match s.find("//") {
        Some(i) => (&s[..i], Some(&s[i + 2..])),
        None => (s, None),
    };
    let v4 = match v4_part.strip_prefix('/') {
        Some("") | None => 32,
        Some(p) => parse_prefix(p, 32)?,
    };
    let v6 = match v6_part {
        Some(p) => parse_prefix(p, 128)?,
        None => 128,
    };
    Ok((v4, v6))
}

fn parse_prefix(p: &str, max: u8) -> Result<u8> {
    let n = p
        .parse::<u8>()
        .map_err(|_| record_err(format!("bad CIDR prefix `{p}`")))?;
    if n > max {
        return Err(record_err(format!("CIDR prefix {n} exceeds {max}")));
    }
    Ok(n)
}

fn record_err(reason: impl Into<String>) -> NetworkError {
    NetworkError::Record {
        kind: "SPF".into(),
        reason: reason.into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_qualifiers_and_all() {
        let r = SpfRecord::parse("v=spf1 +a -all").unwrap();
        assert_eq!(r.directives.len(), 2);
        assert_eq!(r.directives[0].qualifier, Qualifier::Pass);
        assert_eq!(r.directives[1].qualifier, Qualifier::Fail);
        assert_eq!(r.directives[1].mechanism, Mechanism::All);
    }

    #[test]
    fn default_qualifier_is_pass() {
        let r = SpfRecord::parse("v=spf1 mx ~all").unwrap();
        assert_eq!(r.directives[0].qualifier, Qualifier::Pass);
        assert_eq!(r.directives[1].qualifier, Qualifier::SoftFail);
    }

    #[test]
    fn parses_ip4_and_ip6_with_and_without_cidr() {
        let r = SpfRecord::parse("v=spf1 ip4:192.0.2.0/24 ip4:198.51.100.7 ip6:2001:db8::/32 -all")
            .unwrap();
        assert_eq!(
            r.directives[0].mechanism,
            Mechanism::Ip4 {
                net: "192.0.2.0".parse().unwrap(),
                prefix: 24
            }
        );
        assert_eq!(
            r.directives[1].mechanism,
            Mechanism::Ip4 {
                net: "198.51.100.7".parse().unwrap(),
                prefix: 32
            }
        );
        assert_eq!(
            r.directives[2].mechanism,
            Mechanism::Ip6 {
                net: "2001:db8::".parse().unwrap(),
                prefix: 32
            }
        );
    }

    #[test]
    fn parses_a_mx_with_domain_and_dual_cidr() {
        let r = SpfRecord::parse("v=spf1 a:mail.example.com/24 mx//64 a/24//64 -all").unwrap();
        assert_eq!(
            r.directives[0].mechanism,
            Mechanism::A {
                domain: Some("mail.example.com".into()),
                v4: 24,
                v6: 128
            }
        );
        assert_eq!(
            r.directives[1].mechanism,
            Mechanism::Mx {
                domain: None,
                v4: 32,
                v6: 64
            }
        );
        assert_eq!(
            r.directives[2].mechanism,
            Mechanism::A {
                domain: None,
                v4: 24,
                v6: 64
            }
        );
    }

    #[test]
    fn parses_include_exists_ptr_and_redirect() {
        let r = SpfRecord::parse(
            "v=spf1 include:_spf.example.net exists:%{i}.example.com ptr:example.com redirect=other.example",
        )
        .unwrap();
        assert_eq!(
            r.directives[0].mechanism,
            Mechanism::Include("_spf.example.net".into())
        );
        assert_eq!(
            r.directives[1].mechanism,
            Mechanism::Exists("%{i}.example.com".into())
        );
        assert_eq!(
            r.directives[2].mechanism,
            Mechanism::Ptr(Some("example.com".into()))
        );
        assert_eq!(r.redirect.as_deref(), Some("other.example"));
    }

    #[test]
    fn rejects_missing_version_and_bad_terms() {
        assert!(SpfRecord::parse("a mx -all").is_err()); // no v=spf1
        assert!(SpfRecord::parse("v=spf1 ip4:not-an-ip").is_err());
        assert!(SpfRecord::parse("v=spf1 ip4:192.0.2.0/40").is_err()); // prefix > 32
        assert!(SpfRecord::parse("v=spf1 frobnicate").is_err()); // unknown mechanism
        assert!(SpfRecord::parse("v=spf1 include").is_err()); // include needs a domain
    }
}
