//! DKIM canonicalization (RFC 6376 §3.4): `simple` and `relaxed` algorithms for
//! both the header and the body. Canonicalization is byte-exact, so it operates
//! on raw bytes (the verbatim message preserved end-to-end by the mail engine).

/// Header canonicalization algorithm (the first half of a `c=` tag).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HeaderCanon {
    /// `simple` — header fields used verbatim.
    Simple,
    /// `relaxed` — lowercase name, unfold, compress WSP, strip trailing WSP.
    Relaxed,
}

/// Body canonicalization algorithm (the second half of a `c=` tag).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BodyCanon {
    /// `simple` — reduce trailing empty lines to a single CRLF.
    Simple,
    /// `relaxed` — per-line WSP normalization + trailing-empty-line removal.
    Relaxed,
}

/// Parse a `c=` tag value (e.g. `relaxed/relaxed`, `relaxed`, or absent) into the
/// header and body algorithms. Per RFC 6376 §3.5 the default is `simple/simple`,
/// and a bare `relaxed` means `relaxed/simple`.
#[must_use]
pub fn parse_canon(c: Option<&str>) -> (HeaderCanon, BodyCanon) {
    let Some(c) = c else {
        return (HeaderCanon::Simple, BodyCanon::Simple);
    };
    let (h, b) = match c.split_once('/') {
        Some((h, b)) => (h, b),
        None => (c, "simple"),
    };
    let header = if h.eq_ignore_ascii_case("relaxed") {
        HeaderCanon::Relaxed
    } else {
        HeaderCanon::Simple
    };
    let body = if b.eq_ignore_ascii_case("relaxed") {
        BodyCanon::Relaxed
    } else {
        BodyCanon::Simple
    };
    (header, body)
}

/// Canonicalize one header field for inclusion in the signed-header hash.
///
/// `name` is the raw field name (as it appeared) and `raw_value` is everything
/// after the `:` up to (but not including) the field's terminating CRLF,
/// including any folding CRLFs. The returned bytes include the terminating CRLF
/// **unless** `with_crlf` is false (used for the DKIM-Signature field itself,
/// which is hashed without its trailing CRLF — RFC 6376 §3.7).
#[must_use]
pub fn canonicalize_header(
    name: &str,
    raw_value: &[u8],
    canon: HeaderCanon,
    with_crlf: bool,
) -> Vec<u8> {
    let mut out = match canon {
        HeaderCanon::Simple => {
            // Verbatim: original name, ':', original value bytes.
            let mut v = Vec::with_capacity(name.len() + 1 + raw_value.len() + 2);
            v.extend_from_slice(name.as_bytes());
            v.push(b':');
            v.extend_from_slice(raw_value);
            v
        }
        HeaderCanon::Relaxed => {
            // Lowercase name; no WSP around the colon; unfold + compress the value;
            // strip trailing WSP.
            let mut v = Vec::with_capacity(name.len() + 1 + raw_value.len());
            v.extend_from_slice(name.trim().to_ascii_lowercase().as_bytes());
            v.push(b':');
            v.extend_from_slice(&relax_value(raw_value));
            v
        }
    };
    if with_crlf {
        out.extend_from_slice(b"\r\n");
    }
    out
}

/// Relaxed value canonicalization: unfold (drop CRLF), reduce every WSP run to a
/// single space, and strip leading/trailing WSP.
fn relax_value(raw: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(raw.len());
    let mut in_wsp = false;
    for &b in raw {
        match b {
            b'\r' | b'\n' => {} // unfold: drop line breaks
            b' ' | b'\t' => in_wsp = true,
            _ => {
                if in_wsp && !out.is_empty() {
                    out.push(b' ');
                }
                in_wsp = false;
                out.push(b);
            }
        }
    }
    out
}

/// Canonicalize the message body and return the bytes to hash (before any `l=`
/// truncation, which the caller applies).
#[must_use]
pub fn canonicalize_body(body: &[u8], canon: BodyCanon) -> Vec<u8> {
    match canon {
        BodyCanon::Simple => simple_body(body),
        BodyCanon::Relaxed => relaxed_body(body),
    }
}

/// `simple` body (RFC 6376 §3.4.3): reduce a run of trailing CRLFs to one; if the
/// body does not end in CRLF, add one; an empty body becomes a single CRLF.
fn simple_body(body: &[u8]) -> Vec<u8> {
    // Strip all trailing CRLFs, then append exactly one.
    let mut end = body.len();
    while end >= 2 && &body[end - 2..end] == b"\r\n" {
        end -= 2;
    }
    let mut out = body[..end].to_vec();
    out.extend_from_slice(b"\r\n");
    out
}

/// `relaxed` body (RFC 6376 §3.4.4): per line, compress internal WSP runs to one
/// space and strip trailing WSP; drop trailing empty lines; a non-empty result
/// ends in CRLF; an empty result is zero-length.
fn relaxed_body(body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(body.len());
    // Split into lines on CRLF (a trailing partial line with no CRLF is still a
    // line). We rebuild each canonicalized line followed by CRLF.
    let mut i = 0;
    while i < body.len() {
        // Find the next CRLF (or end of input).
        let line_end = find_crlf(&body[i..]).map(|p| i + p);
        let (line, next) = match line_end {
            Some(p) => (&body[i..p], p + 2),
            None => (&body[i..], body.len()),
        };
        out.extend_from_slice(&relax_line(line));
        out.extend_from_slice(b"\r\n");
        i = next;
    }
    // Drop trailing empty lines: peel a CRLF only when it terminates an *empty*
    // line — i.e. it is itself preceded by a CRLF (or is the whole output).
    let mut end = out.len();
    while end >= 2
        && &out[end - 2..end] == b"\r\n"
        && (end == 2 || (end >= 4 && &out[end - 4..end - 2] == b"\r\n"))
    {
        end -= 2;
    }
    out.truncate(end);
    // An all-empty body canonicalizes to zero length.
    if out == b"\r\n" {
        return Vec::new();
    }
    out
}

/// Compress internal WSP runs to a single space and strip trailing WSP in a line.
fn relax_line(line: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(line.len());
    let mut in_wsp = false;
    for &b in line {
        match b {
            b' ' | b'\t' => in_wsp = true,
            _ => {
                if in_wsp {
                    out.push(b' ');
                    in_wsp = false;
                }
                out.push(b);
            }
        }
    }
    // A trailing WSP run is dropped (we only emit a space when followed by content).
    out
}

/// Index of the first `\r\n` in `bytes`, if any.
fn find_crlf(bytes: &[u8]) -> Option<usize> {
    bytes.windows(2).position(|w| w == b"\r\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_canon_defaults_and_forms() {
        assert_eq!(parse_canon(None), (HeaderCanon::Simple, BodyCanon::Simple));
        assert_eq!(
            parse_canon(Some("relaxed")),
            (HeaderCanon::Relaxed, BodyCanon::Simple)
        );
        assert_eq!(
            parse_canon(Some("relaxed/relaxed")),
            (HeaderCanon::Relaxed, BodyCanon::Relaxed)
        );
        assert_eq!(
            parse_canon(Some("simple/relaxed")),
            (HeaderCanon::Simple, BodyCanon::Relaxed)
        );
    }

    #[test]
    fn relaxed_header_matches_rfc_example() {
        // RFC 6376 §3.4.5: "A: X\r\n" + "B : Y\t\r\n\tZ  \r\n" relaxed →
        // "a:X\r\n" and "b:Y Z\r\n".
        assert_eq!(
            canonicalize_header("A", b" X", HeaderCanon::Relaxed, true),
            b"a:X\r\n"
        );
        assert_eq!(
            canonicalize_header("B ", b" Y\t\r\n\tZ  ", HeaderCanon::Relaxed, true),
            b"b:Y Z\r\n"
        );
    }

    #[test]
    fn simple_header_is_verbatim() {
        assert_eq!(
            canonicalize_header("From", b" Alice <a@x>", HeaderCanon::Simple, true),
            b"From: Alice <a@x>\r\n"
        );
    }

    #[test]
    fn dkim_signature_header_hashed_without_trailing_crlf() {
        let h = canonicalize_header("DKIM-Signature", b" v=1; b=", HeaderCanon::Relaxed, false);
        assert_eq!(h, b"dkim-signature:v=1; b=");
        assert!(!h.ends_with(b"\r\n"));
    }

    #[test]
    fn simple_body_reduces_trailing_crlfs_and_handles_empty() {
        assert_eq!(canonicalize_body(b"", BodyCanon::Simple), b"\r\n");
        assert_eq!(canonicalize_body(b"abc", BodyCanon::Simple), b"abc\r\n");
        assert_eq!(canonicalize_body(b"abc\r\n", BodyCanon::Simple), b"abc\r\n");
        assert_eq!(
            canonicalize_body(b"abc\r\n\r\n\r\n", BodyCanon::Simple),
            b"abc\r\n"
        );
        assert_eq!(canonicalize_body(b"\r\n\r\n", BodyCanon::Simple), b"\r\n");
    }

    #[test]
    fn relaxed_body_normalizes_wsp_and_trailing_lines() {
        // RFC 6376 §3.4.5 body example → " C\r\nD E\r\n" (leading WSP is reduced to
        // a single SP, not removed; trailing WSP and trailing empty lines dropped).
        assert_eq!(
            canonicalize_body(b" C \r\nD \t E\r\n\r\n\r\n", BodyCanon::Relaxed),
            b" C\r\nD E\r\n"
        );
        // An empty (or all-blank) body canonicalizes to zero length.
        assert_eq!(canonicalize_body(b"", BodyCanon::Relaxed), b"");
        assert_eq!(canonicalize_body(b"\r\n\r\n", BodyCanon::Relaxed), b"");
        assert_eq!(canonicalize_body(b"x", BodyCanon::Relaxed), b"x\r\n");
    }
}
