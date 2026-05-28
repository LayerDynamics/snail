//! Outbound relay: the SMTP *client* command script to transmit a message to a
//! downstream server. MX resolution (via `network`) and the socket dialog are
//! wired at the composition root (m15); this builds the protocol payload.

use crate::snailmail::Message;

/// The SMTP client dialog to relay one message: the commands to issue in order,
/// then the dot-stuffed `DATA` payload (already terminated by the lone `.` line).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayScript {
    /// Commands to send in sequence (each awaiting a positive reply).
    pub commands: Vec<String>,
    /// The `DATA` payload: dot-stuffed message bytes + the `.\r\n` terminator.
    pub data: Vec<u8>,
}

/// Build the relay script for `message`, announcing ourselves as `helo_domain`.
#[must_use]
pub fn relay_script(helo_domain: &str, message: &Message) -> RelayScript {
    let from = message
        .envelope
        .sender
        .as_ref()
        .map(ToString::to_string)
        .unwrap_or_default();
    let mut commands = vec![format!("EHLO {helo_domain}"), format!("MAIL FROM:<{from}>")];
    for rcpt in &message.envelope.recipients {
        commands.push(format!("RCPT TO:<{rcpt}>"));
    }
    commands.push("DATA".to_string());
    RelayScript {
        commands,
        data: dot_stuff(&message.to_bytes()),
    }
}

/// Apply RFC 5321 dot-stuffing (double a leading `.` on each line) to `body` and
/// append the `.\r\n` end-of-data line. Operates on raw bytes, **preserving the
/// message verbatim** (no lossy UTF-8 round-trip), so 8-bit/binary content and
/// DKIM signatures survive the relay. Shared by the outbound relay and the POP3
/// `RETR` multi-line response, which use identical framing.
#[must_use]
pub fn dot_stuff(body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(body.len() + 8);
    for line in split_on_crlf(body) {
        if line.first() == Some(&b'.') {
            out.push(b'.');
        }
        out.extend_from_slice(line);
        out.extend_from_slice(b"\r\n");
    }
    out.extend_from_slice(b".\r\n");
    out
}

/// Split `body` on `\r\n` boundaries, mirroring `str::split("\r\n")` (a trailing
/// `\r\n` yields a final empty segment), but over raw bytes.
fn split_on_crlf(body: &[u8]) -> Vec<&[u8]> {
    let mut segments = Vec::new();
    let (mut start, mut i) = (0usize, 0usize);
    while i + 1 < body.len() {
        if body[i] == b'\r' && body[i + 1] == b'\n' {
            segments.push(&body[start..i]);
            i += 2;
            start = i;
        } else {
            i += 1;
        }
    }
    segments.push(&body[start..]);
    segments
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::snailmail::{Envelope, Mailbox, Message};

    fn message() -> Message {
        Message::parse(
            Envelope::new(
                Some(Mailbox::parse("a@x.com").unwrap()),
                vec![
                    Mailbox::parse("b@y.com").unwrap(),
                    Mailbox::parse("c@z.com").unwrap(),
                ],
            ),
            b"Subject: hi\r\n\r\nbody",
        )
        .unwrap()
    }

    #[test]
    fn builds_command_sequence() {
        let script = relay_script("relay.example.com", &message());
        assert_eq!(script.commands[0], "EHLO relay.example.com");
        assert_eq!(script.commands[1], "MAIL FROM:<a@x.com>");
        assert_eq!(script.commands[2], "RCPT TO:<b@y.com>");
        assert_eq!(script.commands[3], "RCPT TO:<c@z.com>");
        assert_eq!(script.commands[4], "DATA");
    }

    #[test]
    fn data_is_dot_stuffed_and_terminated() {
        let msg = Message::parse(
            Envelope::new(None, vec![Mailbox::parse("b@y.com").unwrap()]),
            b"Subject: x\r\n\r\n.leading dot line",
        )
        .unwrap();
        let script = relay_script("h", &msg);
        let payload = String::from_utf8(script.data).unwrap();
        assert!(payload.contains("..leading dot line")); // stuffed
        assert!(payload.ends_with(".\r\n")); // terminator
    }

    #[test]
    fn relay_payload_preserves_non_utf8_bytes_verbatim() {
        // The #4 regression for relay: the DATA payload must carry the original
        // 8-bit bytes (so DKIM survives), only dot-stuffing and the terminator
        // added — never a lossy UTF-8 substitution (U+FFFD == EF BF BD).
        let raw: &[u8] = b"Subject: caf\xe9\r\n\r\nbody \xff\xfe end\r\n";
        let msg = Message::parse(
            Envelope::new(None, vec![Mailbox::parse("b@y.com").unwrap()]),
            raw,
        )
        .unwrap();
        let script = relay_script("h", &msg);
        // No lossy replacement characters, the verbatim 8-bit subsequences survive,
        // and the payload is terminated.
        assert!(
            !script.data.windows(3).any(|w| w == [0xEF, 0xBF, 0xBD]),
            "no U+FFFD replacement bytes may appear"
        );
        assert!(script.data.windows(4).any(|w| w == b"caf\xe9"));
        assert!(script.data.windows(3).any(|w| w == b" \xff\xfe"));
        assert!(script.data.ends_with(b".\r\n"));
    }

    #[test]
    fn dot_stuff_doubles_leading_dots_and_terminates() {
        // Each CRLF-delimited line is re-emitted with CRLF (a trailing CRLF yields a
        // final empty line, matching str::split("\r\n") semantics), then `.\r\n`.
        assert_eq!(dot_stuff(b"hi\r\n.dot\r\n"), b"hi\r\n..dot\r\n\r\n.\r\n");
        assert_eq!(dot_stuff(b""), b"\r\n.\r\n");
        // Raw bytes pass through untouched (no lossy conversion).
        assert_eq!(dot_stuff(b"\xff\xfe"), b"\xff\xfe\r\n.\r\n");
    }
}
