//! Parsing of a `DKIM-Signature` header field (RFC 6376 §3.5) into its tags.

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;

use crate::dkim::canonicalize::{BodyCanon, HeaderCanon, parse_canon};
use crate::dns::txt::parse_tag_map;
use crate::error::{NetworkError, Result};

/// The signing algorithm (`a=` tag).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Algorithm {
    /// `rsa-sha256` (RFC 6376) — the dominant algorithm.
    RsaSha256,
    /// `ed25519-sha256` (RFC 8463).
    Ed25519Sha256,
}

impl Algorithm {
    fn parse(a: &str) -> Result<Self> {
        match a.to_ascii_lowercase().as_str() {
            "rsa-sha256" => Ok(Self::RsaSha256),
            "ed25519-sha256" => Ok(Self::Ed25519Sha256),
            // rsa-sha1 (RFC 6376) is deprecated and unsupported; SHA-1 is broken.
            other => Err(err(format!("unsupported algorithm `{other}`"))),
        }
    }
}

/// A parsed `DKIM-Signature`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DkimSignature {
    /// `a=` algorithm.
    pub algorithm: Algorithm,
    /// `b=` signature bytes (base64-decoded).
    pub signature: Vec<u8>,
    /// `bh=` declared body hash (base64-decoded).
    pub body_hash: Vec<u8>,
    /// Header canonicalization (from `c=`).
    pub header_canon: HeaderCanon,
    /// Body canonicalization (from `c=`).
    pub body_canon: BodyCanon,
    /// `d=` signing domain (SDID) — what DMARC aligns against.
    pub domain: String,
    /// `s=` selector (locates the public key).
    pub selector: String,
    /// `h=` signed header field names, in signing order (lowercased).
    pub signed_headers: Vec<String>,
    /// `l=` body length limit (octets of the canonicalized body that were signed).
    pub body_length: Option<usize>,
    /// `x=` signature expiration (Unix seconds), if present.
    pub expiration: Option<u64>,
    /// The raw `DKIM-Signature` field value with the `b=` value emptied — the
    /// input to the header hash (RFC 6376 §3.7).
    pub b_stripped_value: Vec<u8>,
}

impl DkimSignature {
    /// Parse a `DKIM-Signature` field value (the bytes after the `:`).
    ///
    /// # Errors
    /// [`NetworkError::Record`] if a required tag is missing/invalid or the
    /// version/algorithm is unsupported.
    pub fn parse(raw_value: &[u8]) -> Result<Self> {
        // DKIM-Signature values are ASCII; a lossy decode is harmless for parsing
        // (the verbatim bytes are kept separately in `b_stripped_value`).
        let text = String::from_utf8_lossy(raw_value);
        let tags = parse_tag_map(&text);

        if let Some(v) = tags.get("v")
            && v != "1"
        {
            return Err(err(format!("unsupported DKIM version `{v}`")));
        }
        let algorithm = Algorithm::parse(tags.get("a").ok_or_else(|| err("missing a="))?)?;
        let signature = decode_b64(tags.get("b").ok_or_else(|| err("missing b="))?)?;
        let body_hash = decode_b64(tags.get("bh").ok_or_else(|| err("missing bh="))?)?;
        let (header_canon, body_canon) = parse_canon(tags.get("c").map(String::as_str));
        let domain = tags.get("d").ok_or_else(|| err("missing d="))?.clone();
        let selector = tags.get("s").ok_or_else(|| err("missing s="))?.clone();
        let signed_headers: Vec<String> = tags
            .get("h")
            .ok_or_else(|| err("missing h="))?
            .split(':')
            .map(|h| h.trim().to_ascii_lowercase())
            .filter(|h| !h.is_empty())
            .collect();
        if signed_headers.is_empty() {
            return Err(err("h= lists no header fields"));
        }
        let body_length = match tags.get("l") {
            Some(l) => Some(l.parse().map_err(|_| err("bad l= length"))?),
            None => None,
        };
        let expiration = match tags.get("x") {
            Some(x) => Some(x.parse().map_err(|_| err("bad x= expiration"))?),
            None => None,
        };

        Ok(Self {
            algorithm,
            signature,
            body_hash,
            header_canon,
            body_canon,
            domain,
            selector,
            signed_headers,
            body_length,
            expiration,
            b_stripped_value: strip_b_value(&text).into_bytes(),
        })
    }
}

/// Decode a base64 tag value, ignoring any folding whitespace it contains.
fn decode_b64(value: &str) -> Result<Vec<u8>> {
    let compact: String = value.chars().filter(|c| !c.is_whitespace()).collect();
    BASE64
        .decode(compact.as_bytes())
        .map_err(|e| err(format!("invalid base64: {e}")))
}

/// Reproduce the field value with the `b=` tag's value removed (the `b=` itself is
/// kept). Other tags — and the original separators/whitespace — are preserved, so
/// `simple` header canonicalization still sees the verbatim field.
fn strip_b_value(value: &str) -> String {
    value
        .split(';')
        .map(|segment| match segment.split_once('=') {
            Some((key, _)) if key.trim() == "b" => format!("{key}="),
            _ => segment.to_string(),
        })
        .collect::<Vec<_>>()
        .join(";")
}

fn err(reason: impl Into<String>) -> NetworkError {
    NetworkError::Record {
        kind: "DKIM".into(),
        reason: reason.into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SIG: &[u8] = b" v=1; a=rsa-sha256; c=relaxed/relaxed; d=example.com; s=sel;\r\n\
        h=from:to:subject; bh=2jUSOH9NhtVGCQWNr9BrIAPreKQjO6Sn7XIkfJVOzv8=;\r\n\
        b=dGVzdHNpZ25hdHVyZXZhbHVl";

    #[test]
    fn parses_a_full_signature() {
        let s = DkimSignature::parse(SIG).unwrap();
        assert_eq!(s.algorithm, Algorithm::RsaSha256);
        assert_eq!(s.header_canon, HeaderCanon::Relaxed);
        assert_eq!(s.body_canon, BodyCanon::Relaxed);
        assert_eq!(s.domain, "example.com");
        assert_eq!(s.selector, "sel");
        assert_eq!(s.signed_headers, vec!["from", "to", "subject"]);
        assert!(s.body_length.is_none());
        assert!(!s.signature.is_empty());
        assert_eq!(s.body_hash.len(), 32); // SHA-256 digest
    }

    #[test]
    fn b_value_is_stripped_but_b_tag_kept() {
        let s = DkimSignature::parse(SIG).unwrap();
        let stripped = String::from_utf8(s.b_stripped_value).unwrap();
        assert!(stripped.contains("b="), "the b= tag name is retained");
        assert!(
            !stripped.contains("dGVzdHNp"),
            "the b= value is removed: {stripped}"
        );
        // bh= (a different tag) must survive intact.
        assert!(stripped.contains("bh=2jUSOH9N"));
    }

    #[test]
    fn rejects_unsupported_and_missing_tags() {
        assert!(
            DkimSignature::parse(b"v=1; a=rsa-sha1; d=x; s=y; h=from; bh=AA==; b=AA==").is_err()
        );
        assert!(
            DkimSignature::parse(b"v=2; a=rsa-sha256; d=x; s=y; h=from; bh=AA==; b=AA==").is_err()
        );
        assert!(DkimSignature::parse(b"a=rsa-sha256; d=x; s=y; h=from; b=AA==").is_err()); // no bh
        assert!(DkimSignature::parse(b"a=rsa-sha256; s=y; h=from; bh=AA==; b=AA==").is_err()); // no d
    }

    #[test]
    fn ed25519_algorithm_parses() {
        let s =
            DkimSignature::parse(b"v=1; a=ed25519-sha256; d=x.com; s=s; h=from; bh=AA==; b=AA==")
                .unwrap();
        assert_eq!(s.algorithm, Algorithm::Ed25519Sha256);
    }
}
