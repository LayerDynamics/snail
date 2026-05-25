//! Inbound reception: collect an SMTP `DATA` body (with RFC 5321 dot-unstuffing)
//! and assemble a deliverable [`Message`].

use crate::error::Result;
use crate::snailmail::{Envelope, Message};

/// Accumulates the `DATA` body lines of an inbound SMTP transaction.
#[derive(Debug, Default)]
pub struct InboundCollector {
    body: Vec<u8>,
    finished: bool,
}

impl InboundCollector {
    /// A new, empty collector.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Feed one `DATA` line (trailing CRLF optional). Returns `true` when the
    /// terminating lone `.` is seen. Applies dot-unstuffing: a line beginning
    /// with `.` has one leading dot removed.
    pub fn push_line(&mut self, line: &str) -> bool {
        let line = line.strip_suffix('\n').unwrap_or(line);
        let line = line.strip_suffix('\r').unwrap_or(line);
        if line == "." {
            self.finished = true;
            return true;
        }
        let unstuffed = line.strip_prefix('.').unwrap_or(line);
        self.body.extend_from_slice(unstuffed.as_bytes());
        self.body.extend_from_slice(b"\r\n");
        false
    }

    /// Whether the terminating `.` has been received.
    #[must_use]
    pub fn is_finished(&self) -> bool {
        self.finished
    }

    /// Assemble the collected body and `envelope` into a [`Message`].
    ///
    /// # Errors
    /// Propagates [`crate::error::MailError::Malformed`] from message parsing.
    pub fn into_message(self, envelope: Envelope) -> Result<Message> {
        Message::parse(envelope, &self.body)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::snailmail::Mailbox;

    fn envelope() -> Envelope {
        Envelope::new(None, vec![Mailbox::parse("b@y.com").unwrap()])
    }

    #[test]
    fn collects_body_until_dot_then_parses() {
        let mut c = InboundCollector::new();
        assert!(!c.push_line("Subject: Hi"));
        assert!(!c.push_line(""));
        assert!(!c.push_line("hello world"));
        assert!(c.push_line(".")); // terminator
        assert!(c.is_finished());
        let msg = c.into_message(envelope()).unwrap();
        assert_eq!(msg.subject(), Some("Hi"));
        assert_eq!(msg.body, b"hello world\r\n");
    }

    #[test]
    fn dot_unstuffs_leading_dots() {
        let mut c = InboundCollector::new();
        c.push_line("Subject: x");
        c.push_line("");
        c.push_line("..hidden"); // sender stuffed ".hidden" -> "..hidden"
        c.push_line(".");
        let msg = c.into_message(envelope()).unwrap();
        assert_eq!(msg.body, b".hidden\r\n");
    }
}
