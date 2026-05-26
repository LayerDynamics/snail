//! Inbound reception: collect an SMTP `DATA` body (with RFC 5321 dot-unstuffing)
//! and assemble a deliverable [`Message`].

use crate::error::Result;
use crate::snailmail::{Envelope, Message};

/// Accumulates the `DATA` body lines of an inbound SMTP transaction.
#[derive(Debug)]
pub struct InboundCollector {
    body: Vec<u8>,
    finished: bool,
    /// Whether the previously pushed line ended with CRLF. Initialised `true` to
    /// stand in for the CRLF that terminates the `DATA` command itself, so an
    /// immediate `.\r\n` (an empty message) is still a valid terminator.
    prev_crlf: bool,
}

impl Default for InboundCollector {
    fn default() -> Self {
        Self {
            body: Vec::new(),
            finished: false,
            prev_crlf: true,
        }
    }
}

impl InboundCollector {
    /// A new, empty collector.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Feed one raw `DATA` line **including its line terminator** as read off the
    /// wire. Returns `true` only when the genuine end-of-data marker
    /// `<CRLF>.<CRLF>` is seen.
    ///
    /// The terminator check deliberately requires real CRLF framing on *both*
    /// sides of the lone `.`: a bare-LF (or bare-CR) `.` line is treated as
    /// ordinary body, never as end-of-data. Honouring a bare-LF `<LF>.<LF>` (or
    /// `<LF>.<CRLF>`, `<CRLF>.<LF>`) as a terminator is the SMTP-smuggling vector
    /// (the 2023–2024 CVE class): a strict downstream MTA disagrees about where
    /// the message ends, letting a sender inject a second, spoofed message.
    ///
    /// Every body line is re-emitted with canonical CRLF, so ambiguous bare
    /// newlines are normalised away and can never be relayed onward as a
    /// smuggling payload. Dot-unstuffing (a leading `.` removed) is applied to
    /// every body line.
    pub fn push_line(&mut self, line: &str) -> bool {
        let this_crlf = line.ends_with("\r\n");
        let content = line
            .strip_suffix("\r\n")
            .or_else(|| line.strip_suffix('\n'))
            .or_else(|| line.strip_suffix('\r'))
            .unwrap_or(line);

        // End-of-data only on a genuine <CRLF>.<CRLF>: the prior line and this
        // one must both be CRLF-framed, and this line must be the lone dot.
        if self.prev_crlf && this_crlf && content == "." {
            self.finished = true;
            return true;
        }

        let unstuffed = content.strip_prefix('.').unwrap_or(content);
        self.body.extend_from_slice(unstuffed.as_bytes());
        self.body.extend_from_slice(b"\r\n");
        self.prev_crlf = this_crlf;
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
        assert!(!c.push_line("Subject: Hi\r\n"));
        assert!(!c.push_line("\r\n"));
        assert!(!c.push_line("hello world\r\n"));
        assert!(c.push_line(".\r\n")); // genuine <CRLF>.<CRLF> terminator
        assert!(c.is_finished());
        let msg = c.into_message(envelope()).unwrap();
        assert_eq!(msg.subject(), Some("Hi"));
        assert_eq!(msg.body, b"hello world\r\n");
    }

    #[test]
    fn dot_unstuffs_leading_dots() {
        let mut c = InboundCollector::new();
        c.push_line("Subject: x\r\n");
        c.push_line("\r\n");
        c.push_line("..hidden\r\n"); // sender stuffed ".hidden" -> "..hidden"
        c.push_line(".\r\n");
        let msg = c.into_message(envelope()).unwrap();
        assert_eq!(msg.body, b".hidden\r\n");
    }

    #[test]
    fn empty_message_terminates_immediately() {
        // A lone ".\r\n" right after DATA (prev_crlf seeded true) ends the empty
        // message.
        let mut c = InboundCollector::new();
        assert!(c.push_line(".\r\n"));
        assert!(c.is_finished());
    }

    #[test]
    fn bare_lf_dot_is_not_a_terminator() {
        // <LF>.<LF>: a "." that arrived without CRLF framing is body, not the end
        // of data (SMTP-smuggling defence).
        let mut c = InboundCollector::new();
        assert!(!c.push_line("first\r\n"));
        assert!(!c.push_line(".\n")); // bare-LF dot — NOT a terminator
        assert!(!c.push_line("still body\r\n"));
        assert!(c.push_line(".\r\n")); // only the genuine CRLF dot ends it
        assert!(c.is_finished());
    }

    #[test]
    fn lf_dot_crlf_is_not_a_terminator() {
        // <LF>.<CRLF>: the dot line is CRLF-framed, but the *preceding* line ended
        // with a bare LF, so this is not a genuine <CRLF>.<CRLF>.
        let mut c = InboundCollector::new();
        assert!(!c.push_line("first\n")); // bare-LF line → prev_crlf := false
        assert!(!c.push_line(".\r\n")); // preceding line was not CRLF → not the end
        assert!(c.push_line(".\r\n")); // now the preceding (".") line was CRLF → ends
        assert!(c.is_finished());
    }

    #[test]
    fn crlf_dot_lf_is_not_a_terminator() {
        // <CRLF>.<LF>: the dot line ends with a bare LF → not end-of-data.
        let mut c = InboundCollector::new();
        assert!(!c.push_line("first\r\n"));
        assert!(!c.push_line(".\n")); // <CRLF>.<LF> — not a terminator
        assert!(!c.push_line("more\r\n")); // resets prev_crlf to true
        assert!(c.push_line(".\r\n")); // genuine terminator
        assert!(c.is_finished());
    }

    #[test]
    fn smuggled_commands_stay_in_the_body() {
        // The classic payload: a bare-LF "." followed by injected SMTP commands.
        // With the genuine-CRLF terminator none of it ends the message — it all
        // lands inside the single message body.
        let mut c = InboundCollector::new();
        c.push_line("Subject: legit\r\n");
        c.push_line("\r\n"); // end of headers
        c.push_line("body start\r\n");
        c.push_line(".\n"); // smuggling attempt
        c.push_line("MAIL FROM:<spoofed@example.com>\r\n");
        c.push_line("RCPT TO:<victim@example.com>\r\n");
        c.push_line("Injected\r\n");
        assert!(c.push_line(".\r\n")); // the genuine terminator
        let msg = c.into_message(envelope()).unwrap();
        let body = String::from_utf8_lossy(&msg.body);
        assert!(body.contains("MAIL FROM:<spoofed@example.com>"), "{body}");
        assert!(body.contains("Injected"), "{body}");
    }
}
