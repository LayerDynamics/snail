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
    /// # Errors
    /// [`MailError::InvalidAddress`] if there is no `@` or either side is empty.
    pub fn parse(addr: &str) -> Result<Self> {
        let trimmed = addr.trim();
        let (local, domain) = trimmed
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
#[derive(Debug, Clone)]
pub struct Message {
    /// SMTP routing envelope.
    pub envelope: Envelope,
    /// Parsed headers.
    pub headers: Headers,
    /// Raw body (everything after the header/body separator).
    pub body: Vec<u8>,
}

impl Message {
    /// Parse the header and body sections of `raw` (RFC 5322), pairing them with
    /// the SMTP `envelope`. The sections split on the first blank line; folded
    /// header values (continuation lines starting with whitespace) are unfolded.
    ///
    /// # Errors
    /// [`MailError::Malformed`] if a header line lacks a `:` separator.
    pub fn parse(envelope: Envelope, raw: &[u8]) -> Result<Self> {
        let (header_bytes, body) = split_header_body(raw);
        let header_text = String::from_utf8_lossy(header_bytes);
        let headers = parse_headers(&header_text)?;
        Ok(Self {
            envelope,
            headers,
            body: body.to_vec(),
        })
    }

    /// Serialize to wire bytes: `Name: value` headers, a blank line, then the body.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        for (name, value) in self.headers.iter() {
            out.extend_from_slice(name.as_bytes());
            out.extend_from_slice(b": ");
            out.extend_from_slice(value.as_bytes());
            out.extend_from_slice(b"\r\n");
        }
        out.extend_from_slice(b"\r\n");
        out.extend_from_slice(&self.body);
        out
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

/// Split raw bytes into the header section and body on the first blank line
/// (`\r\n\r\n` or `\n\n`). If there is no blank line, all of it is headers.
fn split_header_body(raw: &[u8]) -> (&[u8], &[u8]) {
    if let Some(pos) = find_subslice(raw, b"\r\n\r\n") {
        (&raw[..pos], &raw[pos + 4..])
    } else if let Some(pos) = find_subslice(raw, b"\n\n") {
        (&raw[..pos], &raw[pos + 2..])
    } else {
        (raw, &[])
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
    fn null_filter_accepts() {
        let msg = Message::parse(envelope(), b"Subject: x\r\n\r\nbody").unwrap();
        assert_eq!(NullFilter.scan(&msg), FilterVerdict::Accept);
    }
}
