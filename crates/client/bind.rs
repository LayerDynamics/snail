//! The `wasm-bindgen` API surface exposed to JavaScript/TypeScript.
//!
//! This is the language boundary: every `#[wasm_bindgen]` item here becomes a JS
//! export (with a generated `.d.ts`) when the crate is built with `wasm-pack`.
//! The binding wraps the engine's [`mail`] crate so JS clients reuse Snail's
//! RFC 5322 parsing, address handling, and SMTP-script construction instead of
//! re-implementing them.
//!
//! Scope note: a browser WASM module cannot open raw TCP sockets, so this binding
//! is the **computational** mail surface — parse, inspect, compose, and build the
//! exact on-the-wire SMTP bytes. The JS host performs the actual transport (e.g.
//! over a WebSocket-to-TCP relay) by sending the [`SmtpScript`] this produces.
//!
//! Errors are surfaced as `Result<_, String>`, which `wasm-bindgen` converts into
//! a thrown JS `Error`; the same functions are plain fallible Rust off-wasm.

use mail::transport::relay_script;
use mail::{Envelope, Mailbox, Message};
use wasm_bindgen::prelude::*;

// Build metadata captured by `build.rs` (target triple + crate version).
include!(concat!(env!("OUT_DIR"), "/build_info.rs"));

/// A parsed email address (`local@domain`), validated by the engine's
/// [`Mailbox`] parser (which strips deprecated RFC 5321 source routes).
#[wasm_bindgen]
pub struct EmailAddress {
    local: String,
    domain: String,
}

#[wasm_bindgen]
impl EmailAddress {
    /// Parse `local@domain`. Throws if there is no `@`, either side is empty, or a
    /// source route is malformed.
    pub fn parse(addr: &str) -> Result<EmailAddress, String> {
        let mailbox = Mailbox::parse(addr).map_err(|e| e.to_string())?;
        Ok(Self {
            local: mailbox.local,
            domain: mailbox.domain,
        })
    }

    /// The local part (before the `@`).
    #[wasm_bindgen(getter)]
    pub fn local(&self) -> String {
        self.local.clone()
    }

    /// The domain part (after the `@`).
    #[wasm_bindgen(getter)]
    pub fn domain(&self) -> String {
        self.domain.clone()
    }

    /// The full `local@domain` address.
    #[wasm_bindgen(getter)]
    pub fn address(&self) -> String {
        format!("{}@{}", self.local, self.domain)
    }
}

/// A parsed RFC 5322 message. Wraps [`mail::Message`] for inspection and
/// byte-exact re-serialisation.
#[wasm_bindgen]
pub struct ParsedMessage {
    inner: Message,
}

#[wasm_bindgen]
impl ParsedMessage {
    /// Parse a raw message (the bytes as received). Throws on a malformed message.
    pub fn parse(raw: &[u8]) -> Result<ParsedMessage, String> {
        // Pure parsing needs no SMTP envelope; routing fields stay empty.
        let inner =
            Message::parse(Envelope::new(None, Vec::new()), raw).map_err(|e| e.to_string())?;
        Ok(Self { inner })
    }

    /// The `Subject:` header value, if present.
    #[wasm_bindgen(getter)]
    pub fn subject(&self) -> Option<String> {
        self.inner.subject().map(str::to_string)
    }

    /// The `Message-ID:` header value, if present.
    #[wasm_bindgen(getter, js_name = messageId)]
    pub fn message_id(&self) -> Option<String> {
        self.inner.message_id().map(str::to_string)
    }

    /// The raw header block (everything before the body separator), verbatim.
    #[wasm_bindgen(getter, js_name = rawHeaders)]
    pub fn raw_headers(&self) -> Vec<u8> {
        self.inner.raw_headers().to_vec()
    }

    /// The full message re-serialised to bytes (byte-exact with the parsed input).
    #[wasm_bindgen(js_name = toBytes)]
    pub fn to_bytes(&self) -> Vec<u8> {
        self.inner.to_bytes()
    }
}

/// Compose a minimal RFC 5322 message from basic fields and return its raw bytes
/// (CRLF line endings). Addresses are validated through the engine's parser; the
/// result round-trips through [`Message`] so the output is always well-formed.
/// Throws on an invalid address or with no recipients.
///
/// Date/`Message-ID` generation is intentionally left to the caller (it is a
/// client-policy concern); this builds the `From`/`To`/`Subject` + body envelope.
#[wasm_bindgen(js_name = composeMessage)]
pub fn compose_message(
    from: &str,
    to: Vec<String>,
    subject: &str,
    body: &str,
) -> Result<Vec<u8>, String> {
    // Guard the header-line fields against injection before interpolating them.
    forbid_control("subject", subject)?;
    let sender = parse_address("from", from)?;
    let recipients = parse_recipients(&to)?;
    let to_header = recipients
        .iter()
        .map(Mailbox::to_string)
        .collect::<Vec<_>>()
        .join(", ");
    // Normalise any bare newlines in the body to CRLF for RFC 5322 conformance.
    let body = normalise_crlf(body);
    let raw = format!("From: {sender}\r\nTo: {to_header}\r\nSubject: {subject}\r\n\r\n{body}");
    let message = Message::parse(Envelope::new(Some(sender), recipients), raw.as_bytes())
        .map_err(|e| e.to_string())?;
    Ok(message.to_bytes())
}

/// The SMTP submission/relay protocol script for a message: the ordered commands
/// (`EHLO`, `MAIL FROM`, `RCPT TO`…, `DATA`) and the dot-stuffed, `<CRLF>.<CRLF>`
/// terminated `DATA` payload, exactly as they must go on the wire. A JS host sends
/// these over its own transport.
#[wasm_bindgen]
pub struct SmtpScript {
    commands: Vec<String>,
    data: Vec<u8>,
}

#[wasm_bindgen]
impl SmtpScript {
    /// The ordered SMTP command lines (without trailing CRLF).
    #[wasm_bindgen(getter)]
    pub fn commands(&self) -> Vec<String> {
        self.commands.clone()
    }

    /// The dot-stuffed, terminated `DATA` payload to send after `DATA`/`354`.
    #[wasm_bindgen(getter)]
    pub fn data(&self) -> Vec<u8> {
        self.data.clone()
    }
}

/// Build the [`SmtpScript`] to submit/relay `raw_message`, announcing `helo`, from
/// `sender` to `recipients`. Throws on an invalid address or with no recipients.
#[wasm_bindgen(js_name = buildSmtpScript)]
pub fn build_smtp_script(
    helo: &str,
    sender: &str,
    recipients: Vec<String>,
    raw_message: &[u8],
) -> Result<SmtpScript, String> {
    // `helo`/`sender`/recipients go into EHLO/MAIL FROM/RCPT TO command lines —
    // reject control characters so they cannot inject extra SMTP commands.
    forbid_control("helo", helo)?;
    let sender = parse_address("sender", sender)?;
    let recipients = parse_recipients(&recipients)?;
    let message = Message::parse(Envelope::new(Some(sender), recipients), raw_message)
        .map_err(|e| e.to_string())?;
    let script = relay_script(helo, &message);
    Ok(SmtpScript {
        commands: script.commands,
        data: script.data,
    })
}

/// A human-readable identifier for this binding build (name, version, target),
/// useful for client diagnostics/telemetry.
#[wasm_bindgen(js_name = clientInfo)]
pub fn client_info() -> String {
    format!("snail-client {BUILD_VERSION} ({BUILD_TARGET})")
}

/// Reject a value destined for an SMTP command or RFC 5322 header line that
/// contains control characters (CR, LF, NUL, …). This closes header- and
/// command-injection: a `subject`/address carrying `\r\n` would otherwise splice
/// extra headers (`Bcc:`) or SMTP commands into the output. (`Mailbox::parse`
/// does not itself reject embedded control characters, so the binding guards at
/// its boundary.)
fn forbid_control(field: &str, value: &str) -> Result<(), String> {
    if value.chars().any(char::is_control) {
        return Err(format!("{field} must not contain control characters"));
    }
    Ok(())
}

/// Parse one address after rejecting control characters in the raw input.
fn parse_address(field: &str, addr: &str) -> Result<Mailbox, String> {
    forbid_control(field, addr)?;
    Mailbox::parse(addr).map_err(|e| e.to_string())
}

/// Parse a list of recipient addresses, rejecting an empty list and any address
/// carrying control characters.
fn parse_recipients(addrs: &[String]) -> Result<Vec<Mailbox>, String> {
    if addrs.is_empty() {
        return Err("at least one recipient is required".to_string());
    }
    addrs
        .iter()
        .map(|addr| parse_address("recipient", addr))
        .collect()
}

/// Normalise bare `\n` (and lone `\r`) to `\r\n` without doubling existing CRLFs.
///
/// Operates on raw bytes (not `char`s): only the ASCII `\r`/`\n` bytes are
/// rewritten and every other byte is copied verbatim, so multi-byte UTF-8
/// sequences are preserved exactly. (A naive `byte as char` would mis-decode any
/// continuation byte and corrupt non-ASCII text.)
fn normalise_crlf(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'\r' => {
                out.extend_from_slice(b"\r\n");
                // Skip a following \n so an existing CRLF is not doubled.
                if bytes.get(i + 1) == Some(&b'\n') {
                    i += 1;
                }
            }
            b'\n' => out.extend_from_slice(b"\r\n"),
            other => out.push(other),
        }
        i += 1;
    }
    // Only ASCII CR/LF were inserted and all other bytes copied verbatim, so the
    // result is still valid UTF-8.
    String::from_utf8(out).expect("CRLF normalisation preserves UTF-8 validity")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn email_address_parses_and_exposes_parts() {
        let addr = EmailAddress::parse("Alice@Example.com").unwrap();
        assert_eq!(addr.local(), "Alice");
        assert_eq!(addr.domain(), "Example.com");
        assert_eq!(addr.address(), "Alice@Example.com");
        assert!(EmailAddress::parse("not-an-address").is_err());
    }

    #[test]
    fn parsed_message_reads_subject_and_round_trips() {
        let raw = b"From: a@x.test\r\nSubject: Hello there\r\nMessage-ID: <abc@x.test>\r\n\r\nbody line\r\n";
        let msg = ParsedMessage::parse(raw).unwrap();
        assert_eq!(msg.subject().as_deref(), Some("Hello there"));
        assert_eq!(msg.message_id().as_deref(), Some("<abc@x.test>"));
        // Byte-exact re-serialisation.
        assert_eq!(msg.to_bytes(), raw);
    }

    #[test]
    fn compose_builds_a_well_formed_message() {
        let bytes = compose_message(
            "alice@example.com",
            vec![
                "bob@remote.test".to_string(),
                "carol@remote.test".to_string(),
            ],
            "Hi",
            "first line\nsecond line",
        )
        .unwrap();
        let text = String::from_utf8(bytes).unwrap();
        assert!(text.contains("From: alice@example.com\r\n"));
        assert!(text.contains("To: bob@remote.test, carol@remote.test\r\n"));
        assert!(text.contains("Subject: Hi\r\n"));
        // Bare newline in the body was normalised to CRLF.
        assert!(text.contains("first line\r\nsecond line"));
    }

    #[test]
    fn compose_rejects_bad_input() {
        assert!(compose_message("alice@example.com", vec![], "s", "b").is_err());
        assert!(compose_message("not-valid", vec!["b@x.test".into()], "s", "b").is_err());
    }

    #[test]
    fn smtp_script_has_ehlo_and_terminated_data() {
        let raw = b"Subject: hi\r\n\r\nhello world";
        let script = build_smtp_script(
            "relay.example.com",
            "alice@example.com",
            vec!["bob@remote.test".to_string()],
            raw,
        )
        .unwrap();
        let commands = script.commands();
        assert!(commands[0].starts_with("EHLO"));
        assert!(commands.iter().any(|c| c.starts_with("MAIL FROM:")));
        assert!(commands.iter().any(|c| c.starts_with("RCPT TO:")));
        assert!(commands.iter().any(|c| c == "DATA"));
        // The DATA payload is terminated by <CRLF>.<CRLF>.
        assert!(script.data().ends_with(b"\r\n.\r\n"));
    }

    #[test]
    fn client_info_includes_version() {
        assert!(client_info().starts_with("snail-client "));
    }

    #[test]
    fn compose_preserves_unicode_subject_and_body() {
        // Non-ASCII must survive verbatim — a byte-vs-char bug here silently
        // corrupts every Unicode message.
        let bytes = compose_message(
            "alice@example.com",
            vec!["bob@remote.test".to_string()],
            "Grüße — 你好",
            "héllo wörld\nzweite Zeile — 🐌",
        )
        .unwrap();
        let text = String::from_utf8(bytes).expect("output is valid UTF-8");
        assert!(text.contains("Subject: Grüße — 你好\r\n"));
        assert!(text.contains("héllo wörld\r\nzweite Zeile — 🐌"));
    }

    #[test]
    fn compose_rejects_header_injection() {
        // A CRLF in the subject would otherwise splice in a `Bcc:` header.
        assert!(
            compose_message(
                "alice@example.com",
                vec!["bob@remote.test".to_string()],
                "Hi\r\nBcc: attacker@evil.test",
                "body",
            )
            .is_err()
        );
        // …and via an address.
        assert!(
            compose_message(
                "alice@example.com\r\nBcc: attacker@evil.test",
                vec!["bob@remote.test".to_string()],
                "Hi",
                "body",
            )
            .is_err()
        );
    }

    #[test]
    fn smtp_script_rejects_command_injection() {
        let raw = b"Subject: hi\r\n\r\nhello";
        // A CRLF in the sender would otherwise inject a second SMTP command.
        assert!(
            build_smtp_script(
                "relay.example.com",
                "alice@example.com\r\nRCPT TO:<victim@x.test>",
                vec!["bob@remote.test".to_string()],
                raw,
            )
            .is_err()
        );
        // …and via the HELO name.
        assert!(
            build_smtp_script(
                "relay.example.com\r\nMAIL FROM:<spoof@x.test>",
                "alice@example.com",
                vec!["bob@remote.test".to_string()],
                raw,
            )
            .is_err()
        );
    }
}
