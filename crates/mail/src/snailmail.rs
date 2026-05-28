//! The core RFC 5322 message model — addresses, envelope, headers, and the
//! [`Message`] itself — plus the [`MessageFilter`] contract the delivery
//! pipeline scans through.
//!
//! MIME body-structure decomposition is intentionally deferred: a [`Message`]
//! holds its body as raw bytes, which is all the MTA needs to route and relay.
//!
//! The `MessageFilter` trait + [`NullFilter`] default live here (m12 owns the
//! contract); `crates/filter` (m14) implements it and the composition root
//! (m15) injects it — so `mail` never depends on `filter`.

use crate::error::{MailError, Result};

/// An email address of the form `local@domain`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Mailbox {
    /// The local part (before the `@`).
    pub local: String,
    /// The domain part (after the `@`).
    pub domain: String,
}

impl Mailbox {
    /// Parse `local@domain`. Splits on the last `@`; both parts must be non-empty.
    ///
    /// A leading source route (RFC 5321 §4.1.1.3, e.g. `@hop1,@hop2:user@domain`)
    /// is **stripped and ignored**: the spec directs a receiver to accept the
    /// final relayed mailbox and discard the deprecated route. Stripping it here
    /// means a route can never leak into routing decisions or be re-emitted on an
    /// outbound `RCPT TO:<...>`/`MAIL FROM:<...>` line as a malformed command. A
    /// route with no terminating `:` and address is rejected as malformed.
    ///
    /// # Errors
    /// [`MailError::InvalidAddress`] if there is no `@`, either side is empty, or a
    /// source route is present but not terminated by `:<addr-spec>`.
    pub fn parse(addr: &str) -> Result<Self> {
        let trimmed = addr.trim();
        let addr_spec = match trimmed.strip_prefix('@') {
            // Source route: discard everything up to and including the route's
            // terminating colon, keeping only the final `local@domain`.
            Some(route) => route
                .split_once(':')
                .map(|(_route_hops, addr_spec)| addr_spec)
                .ok_or_else(|| MailError::InvalidAddress(trimmed.to_string()))?,
            None => trimmed,
        };
        let (local, domain) = addr_spec
            .rsplit_once('@')
            .ok_or_else(|| MailError::InvalidAddress(trimmed.to_string()))?;
        if local.is_empty() || domain.is_empty() || domain.contains('@') {
            return Err(MailError::InvalidAddress(trimmed.to_string()));
        }
        Ok(Self {
            local: local.to_string(),
            domain: domain.to_string(),
        })
    }
}

impl std::fmt::Display for Mailbox {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}@{}", self.local, self.domain)
    }
}

/// The SMTP envelope: routing information distinct from the message headers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Envelope {
    /// MAIL FROM reverse-path. `None` is the null sender (used for bounces).
    pub sender: Option<Mailbox>,
    /// RCPT TO recipients.
    pub recipients: Vec<Mailbox>,
}

impl Envelope {
    /// Construct an envelope.
    #[must_use]
    pub fn new(sender: Option<Mailbox>, recipients: Vec<Mailbox>) -> Self {
        Self { sender, recipients }
    }
}

/// RFC 5322 headers: an ordered list of `(name, value)` with case-insensitive lookup.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Headers {
    entries: Vec<(String, String)>,
}

impl Headers {
    /// An empty header set.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Append a header (order preserved; duplicates allowed, as in RFC 5322).
    pub fn push(&mut self, name: impl Into<String>, value: impl Into<String>) {
        self.entries.push((name.into(), value.into()));
    }

    /// The first value for `name` (case-insensitive).
    #[must_use]
    pub fn get(&self, name: &str) -> Option<&str> {
        self.entries
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    /// Iterate the headers in order.
    pub fn iter(&self) -> impl Iterator<Item = (&str, &str)> {
        self.entries.iter().map(|(n, v)| (n.as_str(), v.as_str()))
    }

    /// Number of headers.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether there are no headers.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// A parsed message: the SMTP [`Envelope`], the RFC 5322 [`Headers`], and the
/// raw body bytes.
///
/// **Byte fidelity:** an MTA must relay and store bytes verbatim — lossily
/// re-encoding a message corrupts legacy-charset headers and 8-bit/binary MIME
/// parts and **breaks DKIM signatures**. So the original header and body bytes
/// are retained exactly ([`Self::to_bytes`] reproduces the input byte-for-byte);
/// the parsed [`headers`](Self::headers) are only a convenience *lookup view*
/// (decoded leniently) and are never used to reconstruct the wire form.
#[derive(Debug, Clone)]
pub struct Message {
    /// SMTP routing envelope.
    pub envelope: Envelope,
    /// Parsed headers — a **lookup view only** (subject, message-id, …), decoded
    /// leniently for non-UTF-8 input. Not the wire form: use [`Self::to_bytes`]
    /// for any serialization, relay, or DKIM purpose.
    pub headers: Headers,
    /// Raw body bytes (everything after the header/body separator), verbatim.
    pub body: Vec<u8>,
    /// Verbatim header section **including** the blank-line separator, so
    /// [`Self::to_bytes`] = `raw_head + body` reproduces the input exactly,
    /// independent of CRLF/LF style.
    raw_head: Vec<u8>,
}

impl Message {
    /// Parse the header and body sections of `raw` (RFC 5322), pairing them with
    /// the SMTP `envelope`. The sections split on the first blank line; folded
    /// header values (continuation lines starting with whitespace) are unfolded.
    ///
    /// # Errors
    /// [`MailError::Malformed`] if a header line lacks a `:` separator.
    pub fn parse(envelope: Envelope, raw: &[u8]) -> Result<Self> {
        let (header_bytes, body_start) = split_header_body(raw);
        // Lenient decode only for the parsed lookup view; the wire bytes below are
        // kept verbatim.
        let header_text = String::from_utf8_lossy(header_bytes);
        let headers = parse_headers(&header_text)?;
        Ok(Self {
            envelope,
            headers,
            body: raw[body_start..].to_vec(),
            raw_head: raw[..body_start].to_vec(),
        })
    }

    /// Serialize to wire bytes, **byte-for-byte** as received: the verbatim header
    /// section (including its blank-line separator) followed by the verbatim body.
    /// No re-encoding or header reformatting, so non-UTF-8 content and DKIM
    /// signatures survive a relay round-trip intact.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.raw_head.len() + self.body.len());
        out.extend_from_slice(&self.raw_head);
        out.extend_from_slice(&self.body);
        out
    }

    /// The verbatim header section (including the trailing blank-line separator).
    /// Useful for embedding the original headers in a DSN bounce.
    #[must_use]
    pub fn raw_headers(&self) -> &[u8] {
        &self.raw_head
    }

    /// Prepend a trace header line (e.g. `Received: …`) ahead of all existing
    /// headers, in place, preserving every other byte. The caller supplies the
    /// header *without* a trailing CRLF.
    pub fn prepend_header(&mut self, line: &[u8]) {
        let mut head = Vec::with_capacity(line.len() + 2 + self.raw_head.len());
        head.extend_from_slice(line);
        head.extend_from_slice(b"\r\n");
        head.extend_from_slice(&self.raw_head);
        self.raw_head = head;
    }

    /// Number of `Received:` trace headers already present (RFC 5321 §6.3 hop
    /// count). Counts the verbatim header section so it reflects the bytes on the
    /// wire, not just the lenient lookup view.
    #[must_use]
    pub fn received_header_count(&self) -> usize {
        let head = String::from_utf8_lossy(&self.raw_head);
        head.lines()
            .filter(|line| {
                // A header field starts at column 0 (continuation lines are folded
                // with leading whitespace); match the `Received:` field name.
                !line.starts_with([' ', '\t'])
                    && line
                        .split_once(':')
                        .is_some_and(|(name, _)| name.trim().eq_ignore_ascii_case("Received"))
            })
            .count()
    }

    /// The `Subject` header, if present.
    #[must_use]
    pub fn subject(&self) -> Option<&str> {
        self.headers.get("Subject")
    }

    /// The `Message-ID` header, if present.
    #[must_use]
    pub fn message_id(&self) -> Option<&str> {
        self.headers.get("Message-ID")
    }
}

/// Split raw bytes on the first blank line (`\r\n\r\n` or `\n\n`), returning the
/// header section (for parsing the lookup view) and the index at which the body
/// begins. If there is no blank line, all of it is headers and the body is empty.
/// Returning an index (not a body slice) lets the caller keep the separator bytes
/// in the verbatim header section, so reconstruction is byte-exact.
fn split_header_body(raw: &[u8]) -> (&[u8], usize) {
    if let Some(pos) = find_subslice(raw, b"\r\n\r\n") {
        (&raw[..pos], pos + 4)
    } else if let Some(pos) = find_subslice(raw, b"\n\n") {
        (&raw[..pos], pos + 2)
    } else {
        (raw, raw.len())
    }
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

/// Parse + unfold a header block into [`Headers`].
fn parse_headers(text: &str) -> Result<Headers> {
    let mut headers = Headers::new();
    let mut current: Option<(String, String)> = None;
    for line in text.split('\n') {
        let line = line.strip_suffix('\r').unwrap_or(line);
        if line.is_empty() {
            continue;
        }
        if line.starts_with(' ') || line.starts_with('\t') {
            // Folded continuation of the previous header value.
            if let Some((_, value)) = current.as_mut() {
                value.push(' ');
                value.push_str(line.trim());
                continue;
            }
            return Err(MailError::Malformed(
                "continuation line with no preceding header".into(),
            ));
        }
        if let Some((name, value)) = current.take() {
            headers.push(name, value);
        }
        let (name, value) = line
            .split_once(':')
            .ok_or_else(|| MailError::Malformed(format!("header without ':': {line}")))?;
        current = Some((name.trim().to_string(), value.trim().to_string()));
    }
    if let Some((name, value)) = current.take() {
        headers.push(name, value);
    }
    Ok(headers)
}

/// A verdict produced by scanning a message during delivery.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FilterVerdict {
    /// Deliver the message normally.
    Accept,
    /// Deliver, but mark it suspicious (e.g. route to a junk folder).
    Flag,
    /// Refuse delivery.
    Reject,
}

/// Scans messages during delivery. Implemented by `crates/filter` (m14) and
/// injected at the composition root (m15). `mail` defines the contract but never
/// depends on `filter`, keeping the dependency graph acyclic.
pub trait MessageFilter: Send + Sync {
    /// Scan `message` and return a [`FilterVerdict`].
    fn scan(&self, message: &Message) -> FilterVerdict;
}

/// The default filter: accepts every message. Used when no filter is configured.
#[derive(Debug, Default, Clone, Copy)]
pub struct NullFilter;

impl MessageFilter for NullFilter {
    fn scan(&self, _message: &Message) -> FilterVerdict {
        FilterVerdict::Accept
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn envelope() -> Envelope {
        Envelope::new(
            Some(Mailbox::parse("alice@example.com").unwrap()),
            vec![Mailbox::parse("bob@example.org").unwrap()],
        )
    }

    #[test]
    fn mailbox_parses_and_displays() {
        let m = Mailbox::parse("  alice@example.com ").unwrap();
        assert_eq!(m.local, "alice");
        assert_eq!(m.domain, "example.com");
        assert_eq!(m.to_string(), "alice@example.com");
    }

    #[test]
    fn mailbox_rejects_malformed() {
        assert!(Mailbox::parse("no-at-sign").is_err());
        assert!(Mailbox::parse("@example.com").is_err());
        assert!(Mailbox::parse("alice@").is_err());
    }

    #[test]
    fn source_route_is_stripped_to_final_mailbox() {
        // RFC 5321 §4.1.1.3: accept the relayed mailbox, ignore the route. The
        // route must never survive into the parsed local part or be re-emitted.
        let m = Mailbox::parse("@hop1,@hop2:user@dom").unwrap();
        assert_eq!(m.local, "user");
        assert_eq!(m.domain, "dom");
        assert_eq!(m.to_string(), "user@dom");
        // A single-hop route is handled identically.
        let m = Mailbox::parse("@relay.example:bob@example.com").unwrap();
        assert_eq!(m.to_string(), "bob@example.com");
    }

    #[test]
    fn malformed_source_route_without_address_is_rejected() {
        // Previously `@hop1,@hop2` parsed as local=`hop1,` domain=`hop2` (the bug);
        // with no terminating `:` + addr-spec it must be rejected, not accepted.
        assert!(Mailbox::parse("@hop1,@hop2").is_err());
        assert!(Mailbox::parse("@hop1:").is_err()); // route ends but no addr-spec
        assert!(Mailbox::parse("@hop1:@dom").is_err()); // addr-spec has empty local
    }

    #[test]
    fn parses_headers_and_body() {
        let raw = b"Subject: Hello\r\nFrom: alice@example.com\r\n\r\nthe body\r\n";
        let msg = Message::parse(envelope(), raw).unwrap();
        assert_eq!(msg.subject(), Some("Hello"));
        assert_eq!(msg.headers.get("from"), Some("alice@example.com")); // case-insensitive
        assert_eq!(msg.body, b"the body\r\n");
    }

    #[test]
    fn unfolds_continuation_lines() {
        let raw = b"Subject: a very\r\n long subject\r\n\r\nbody";
        let msg = Message::parse(envelope(), raw).unwrap();
        assert_eq!(msg.subject(), Some("a very long subject"));
    }

    #[test]
    fn round_trips_through_bytes() {
        let raw = b"Subject: Hi\r\nMessage-ID: <abc@x>\r\n\r\nbody text";
        let msg = Message::parse(envelope(), raw).unwrap();
        let bytes = msg.to_bytes();
        let reparsed = Message::parse(envelope(), &bytes).unwrap();
        assert_eq!(reparsed.subject(), Some("Hi"));
        assert_eq!(reparsed.message_id(), Some("<abc@x>"));
        assert_eq!(reparsed.body, b"body text");
    }

    #[test]
    fn to_bytes_is_byte_identical_to_input() {
        // Verbatim serialization: even with unusual (but valid) header whitespace,
        // a folded continuation, and a CRLF body, to_bytes must reproduce the exact
        // input bytes — no header reformatting (which would break DKIM).
        let raw = b"Subject:no-space\r\nX-Folded: a\r\n  continued\r\nFrom: a@b\r\n\r\nline1\r\nline2\r\n";
        let msg = Message::parse(envelope(), raw).unwrap();
        assert_eq!(
            msg.to_bytes(),
            raw,
            "to_bytes must be byte-for-byte verbatim"
        );
    }

    #[test]
    fn preserves_non_utf8_header_and_body_bytes() {
        // The #4 regression: a lossy UTF-8 round-trip would turn 0xE9/0xFF/0xFE
        // into U+FFFD (EF BF BD) and corrupt legacy-charset mail / break DKIM.
        let raw = b"Subject: caf\xe9\r\nX-Bin: \xff\xfe\r\n\r\nbody \xe9\xff\xfe end\r\n";
        let msg = Message::parse(envelope(), raw).unwrap();
        assert_eq!(
            msg.to_bytes(),
            raw,
            "non-UTF-8 header and body bytes must survive verbatim"
        );
    }

    #[test]
    fn prepend_header_adds_a_top_trace_header_verbatim() {
        let raw = b"Subject: Hi\r\n\r\nbody";
        let mut msg = Message::parse(envelope(), raw).unwrap();
        assert_eq!(msg.received_header_count(), 0);
        msg.prepend_header(b"Received: from a by b; date");
        assert_eq!(
            msg.to_bytes(),
            b"Received: from a by b; date\r\nSubject: Hi\r\n\r\nbody"
        );
        assert_eq!(msg.received_header_count(), 1);
        // The body is untouched by prepending.
        assert_eq!(msg.body, b"body");
    }

    #[test]
    fn null_filter_accepts() {
        let msg = Message::parse(envelope(), b"Subject: x\r\n\r\nbody").unwrap();
        assert_eq!(NullFilter.scan(&msg), FilterVerdict::Accept);
    }
}
