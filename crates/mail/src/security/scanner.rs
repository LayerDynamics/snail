//! Content scanning: a configurable [`MessageFilter`] that rejects oversized
//! messages and flags messages whose subject matches configured substrings.

use crate::snailmail::{FilterVerdict, Message, MessageFilter};

/// A configurable content scanner. Implements m12's [`MessageFilter`] so it can
/// be injected into the delivery pipeline (MDA) at the composition root.
#[derive(Debug, Clone)]
pub struct ContentScanner {
    /// Reject messages whose body exceeds this many bytes. `None` = no limit.
    pub max_body_bytes: Option<usize>,
    /// Subject substrings (matched case-insensitively) that cause a `Flag`.
    pub flag_subject_substrings: Vec<String>,
}

impl Default for ContentScanner {
    fn default() -> Self {
        Self {
            // 25 MiB — a common default message-size ceiling.
            max_body_bytes: Some(25 * 1024 * 1024),
            flag_subject_substrings: Vec::new(),
        }
    }
}

impl ContentScanner {
    /// A scanner with default limits and no flagged subjects.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a subject substring that, if present, flags the message.
    #[must_use]
    pub fn flagging(mut self, substring: impl Into<String>) -> Self {
        self.flag_subject_substrings.push(substring.into());
        self
    }
}

impl MessageFilter for ContentScanner {
    fn scan(&self, message: &Message) -> FilterVerdict {
        if let Some(max) = self.max_body_bytes
            && message.body.len() > max
        {
            return FilterVerdict::Reject;
        }
        if let Some(subject) = message.subject() {
            let lower = subject.to_ascii_lowercase();
            if self
                .flag_subject_substrings
                .iter()
                .any(|s| lower.contains(&s.to_ascii_lowercase()))
            {
                return FilterVerdict::Flag;
            }
        }
        FilterVerdict::Accept
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::snailmail::{Envelope, Message};

    fn message(headers_and_body: &[u8]) -> Message {
        Message::parse(Envelope::new(None, vec![]), headers_and_body).unwrap()
    }

    #[test]
    fn accepts_normal_message() {
        let scanner = ContentScanner::new();
        assert_eq!(
            scanner.scan(&message(b"Subject: hi\r\n\r\nbody")),
            FilterVerdict::Accept
        );
    }

    #[test]
    fn rejects_oversized_body() {
        let scanner = ContentScanner {
            max_body_bytes: Some(4),
            flag_subject_substrings: Vec::new(),
        };
        assert_eq!(
            scanner.scan(&message(b"Subject: x\r\n\r\ntoo long body")),
            FilterVerdict::Reject
        );
    }

    #[test]
    fn flags_banned_subject_substring() {
        let scanner = ContentScanner::new().flagging("WIN A PRIZE");
        assert_eq!(
            scanner.scan(&message(b"Subject: You can win a prize today\r\n\r\nx")),
            FilterVerdict::Flag
        );
    }
}
