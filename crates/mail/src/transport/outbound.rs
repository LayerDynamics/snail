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
        data: dot_stuffed(&message.to_bytes()),
    }
}

/// Apply RFC 5321 dot-stuffing (double a leading `.`) and append the `.\r\n`
/// terminator line.
fn dot_stuffed(body: &[u8]) -> Vec<u8> {
    let text = String::from_utf8_lossy(body);
    let mut out = String::new();
    for line in text.split("\r\n") {
        if line.starts_with('.') {
            out.push('.');
        }
        out.push_str(line);
        out.push_str("\r\n");
    }
    out.push_str(".\r\n");
    out.into_bytes()
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
}
