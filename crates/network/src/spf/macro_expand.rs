//! SPF macro expansion (RFC 7208 §7). Domain-specs in `a`/`mx`/`include`/
//! `exists`/`redirect`/`ptr` may embed macros like `%{i}`, `%{s}`, `%{d2r}`;
//! they are expanded against the current evaluation context just before the DNS
//! lookup the mechanism performs.
//!
//! The validated-PTR macro `%{p}` is **not** resolved (RFC 7208 §7.3 explicitly
//! discourages it and permits the literal fallback `unknown`); we use that
//! fallback rather than performing the expensive, easily-spoofed PTR validation.

use std::net::IpAddr;

use crate::error::{NetworkError, Result};

/// The values a macro can reference during one `check_host` evaluation.
pub(crate) struct MacroContext<'a> {
    /// The connecting client IP (`%{i}`, `%{v}`, `%{c}`).
    pub ip: IpAddr,
    /// Local-part of the `MAIL FROM` sender (`%{l}`).
    pub sender_local: &'a str,
    /// Domain of the `MAIL FROM` sender (`%{o}`).
    pub sender_domain: &'a str,
    /// The HELO/EHLO domain (`%{h}`).
    pub helo: &'a str,
    /// The domain currently being evaluated (`%{d}`).
    pub domain: &'a str,
}

/// Delimiters allowed in the macro transformer section (RFC 7208 §7.1).
const DELIMITERS: &[char] = &['.', '-', '+', ',', '/', '_', '='];

/// Expand all macros in `spec`. Returns the literal string ready for a DNS query.
///
/// # Errors
/// [`NetworkError::Record`] on a malformed macro (unterminated `%{`, unknown
/// macro letter, or a bad transformer) — the evaluator maps this to `PermError`.
pub(crate) fn expand(spec: &str, ctx: &MacroContext) -> Result<String> {
    let mut out = String::new();
    let mut chars = spec.chars();
    while let Some(c) = chars.next() {
        if c != '%' {
            out.push(c);
            continue;
        }
        match chars.next() {
            Some('%') => out.push('%'),
            Some('_') => out.push(' '),
            Some('-') => out.push_str("%20"),
            Some('{') => {
                let mut body = String::new();
                loop {
                    match chars.next() {
                        Some('}') => break,
                        Some(ch) => body.push(ch),
                        None => return Err(err("unterminated macro `%{`")),
                    }
                }
                out.push_str(&expand_one(&body, ctx)?);
            }
            _ => return Err(err("invalid macro escape (expected %%, %_, %-, or %{...})")),
        }
    }
    Ok(out)
}

/// Expand the body of a single `%{...}` macro: `<letter><digits?><r?><delims?>`.
fn expand_one(body: &str, ctx: &MacroContext) -> Result<String> {
    let mut it = body.chars();
    let letter = it.next().ok_or_else(|| err("empty macro `%{}`"))?;
    let rest: String = it.collect();

    // Optional digit count (keep the N right-most parts).
    let digits_end = rest
        .find(|c: char| !c.is_ascii_digit())
        .unwrap_or(rest.len());
    let keep: Option<usize> = if digits_end == 0 {
        None
    } else {
        Some(
            rest[..digits_end]
                .parse()
                .map_err(|_| err("bad macro digit count"))?,
        )
    };
    let mut tail = &rest[digits_end..];

    // Optional reverse flag.
    let reverse = tail.starts_with('r') || tail.starts_with('R');
    if reverse {
        tail = &tail[1..];
    }
    // Remaining characters are the delimiter set; they must all be valid.
    if !tail.chars().all(|c| DELIMITERS.contains(&c)) {
        return Err(err("invalid macro transformer delimiters"));
    }
    let split_on: Vec<char> = if tail.is_empty() {
        vec!['.']
    } else {
        tail.chars().collect()
    };

    let uppercase = letter.is_ascii_uppercase();
    let value = macro_value(letter.to_ascii_lowercase(), ctx)
        .ok_or_else(|| err(format!("unknown macro letter `{letter}`")))?;

    // Apply the transformer: split on delimiters, optionally reverse, optionally
    // keep the N right-most parts, rejoin with '.'.
    let mut parts: Vec<&str> = value.split(split_on.as_slice()).collect();
    if reverse {
        parts.reverse();
    }
    if let Some(n) = keep
        && n < parts.len()
    {
        parts = parts.split_off(parts.len() - n);
    }
    let joined = parts.join(".");
    Ok(if uppercase {
        url_escape(&joined)
    } else {
        joined
    })
}

/// The expansion value for a (lowercased) macro letter.
fn macro_value(letter: char, ctx: &MacroContext) -> Option<String> {
    Some(match letter {
        's' => format!("{}@{}", ctx.sender_local, ctx.sender_domain),
        'l' => ctx.sender_local.to_string(),
        'o' => ctx.sender_domain.to_string(),
        'd' => ctx.domain.to_string(),
        'h' => ctx.helo.to_string(),
        'i' => ip_dotted(ctx.ip),
        'v' => match ctx.ip {
            IpAddr::V4(_) => "in-addr".to_string(),
            IpAddr::V6(_) => "ip6".to_string(),
        },
        // The validated-PTR macro is intentionally not resolved (see module doc).
        'p' => "unknown".to_string(),
        // `c`/`r`/`t` are exp-string-only macros, never valid in a domain-spec.
        _ => return None,
    })
}

/// `%{i}` form: an IPv4 address as dotted-quad; an IPv6 address as 32 dot-joined
/// nibbles (RFC 7208 §7.3), e.g. `::1` → `0.0.….0.1`.
fn ip_dotted(ip: IpAddr) -> String {
    match ip {
        IpAddr::V4(v4) => v4.to_string(),
        IpAddr::V6(v6) => {
            let mut nibbles = Vec::with_capacity(32);
            for octet in v6.octets() {
                nibbles.push(format!("{:x}", octet >> 4));
                nibbles.push(format!("{:x}", octet & 0x0f));
            }
            nibbles.join(".")
        }
    }
}

/// Percent-encode all but the RFC 3986 "unreserved" set (for uppercase macros).
fn url_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~') {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

fn err(reason: impl Into<String>) -> NetworkError {
    NetworkError::Record {
        kind: "SPF".into(),
        reason: reason.into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    fn ctx() -> MacroContext<'static> {
        MacroContext {
            ip: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 3)),
            sender_local: "strong-bad",
            sender_domain: "email.example.com",
            helo: "mx.example.com",
            domain: "email.example.com",
        }
    }

    #[test]
    fn expands_simple_letters() {
        let c = ctx();
        assert_eq!(expand("%{s}", &c).unwrap(), "strong-bad@email.example.com");
        assert_eq!(expand("%{l}", &c).unwrap(), "strong-bad");
        assert_eq!(expand("%{o}", &c).unwrap(), "email.example.com");
        assert_eq!(expand("%{d}", &c).unwrap(), "email.example.com");
        assert_eq!(expand("%{i}", &c).unwrap(), "192.0.2.3");
        assert_eq!(expand("%{h}", &c).unwrap(), "mx.example.com");
    }

    #[test]
    fn expands_literals_and_escapes() {
        let c = ctx();
        assert_eq!(expand("%%", &c).unwrap(), "%");
        assert_eq!(expand("%_", &c).unwrap(), " ");
        assert_eq!(expand("%-", &c).unwrap(), "%20");
        assert_eq!(expand("a.%{d}.b", &c).unwrap(), "a.email.example.com.b");
    }

    #[test]
    fn applies_reverse_and_keep_transformers() {
        // RFC 7208 §7.4 worked examples.
        let c = ctx();
        assert_eq!(expand("%{d2}", &c).unwrap(), "example.com");
        assert_eq!(expand("%{dr}", &c).unwrap(), "com.example.email");
        // `r` reverses before the digit keeps the rightmost N (RFC 7208 §7.1):
        // [com, example, email] -> keep 2 -> example.email.
        assert_eq!(expand("%{d2r}", &c).unwrap(), "example.email");
        // Custom delimiter: split local-part on '-'.
        assert_eq!(expand("%{l-}", &c).unwrap(), "strong.bad");
    }

    #[test]
    fn ipv6_i_macro_is_nibble_dotted() {
        let c = MacroContext {
            ip: IpAddr::V6(Ipv6Addr::LOCALHOST),
            ..ctx()
        };
        let i = expand("%{i}", &c).unwrap();
        assert_eq!(i.split('.').count(), 32);
        assert!(i.ends_with("0.1"));
        assert_eq!(expand("%{v}", &c).unwrap(), "ip6");
    }

    #[test]
    fn uppercase_macro_is_url_escaped() {
        let c = MacroContext {
            sender_local: "a b",
            ..ctx()
        };
        // %{S} URL-escapes; the space becomes %20 and '@' becomes %40.
        assert_eq!(expand("%{S}", &c).unwrap(), "a%20b%40email.example.com");
    }

    #[test]
    fn rejects_malformed_macros() {
        let c = ctx();
        assert!(expand("%{i", &c).is_err()); // unterminated
        assert!(expand("%q", &c).is_err()); // invalid escape
        assert!(expand("%{z}", &c).is_err()); // unknown letter
    }
}
