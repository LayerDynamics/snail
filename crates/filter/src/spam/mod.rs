//! Content-based spam scoring: weighted phrase rules over a message's subject
//! and body, mapped to a [`mail::FilterVerdict`].

use mail::{FilterVerdict, Message, MessageFilter};

/// A single scoring rule: a substring (matched case-insensitively against the
/// subject and body) and the score it contributes per match.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpamRule {
    /// The substring to look for.
    pub phrase: String,
    /// Score added when the phrase is present.
    pub weight: u32,
}

impl SpamRule {
    /// Build a rule.
    pub fn new(phrase: impl Into<String>, weight: u32) -> Self {
        Self {
            phrase: phrase.into(),
            weight,
        }
    }
}

/// A configurable content spam filter. Sums the weights of matching rules and
/// maps the total to Accept / Flag / Reject by threshold.
#[derive(Debug, Clone)]
pub struct SpamFilter {
    rules: Vec<SpamRule>,
    flag_threshold: u32,
    reject_threshold: u32,
}

impl Default for SpamFilter {
    fn default() -> Self {
        Self {
            rules: vec![
                SpamRule::new("viagra", 5),
                SpamRule::new("you have won", 5),
                SpamRule::new("free money", 5),
                SpamRule::new("click here now", 3),
                SpamRule::new("act now", 2),
                SpamRule::new("wire transfer", 3),
            ],
            flag_threshold: 5,
            reject_threshold: 10,
        }
    }
}

impl SpamFilter {
    /// A filter with the default rule set.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Build a filter from explicit rules and thresholds.
    #[must_use]
    pub fn with_rules(rules: Vec<SpamRule>, flag_threshold: u32, reject_threshold: u32) -> Self {
        Self {
            rules,
            flag_threshold,
            reject_threshold,
        }
    }

    /// The spam score for `message`: the sum of the weights of every rule whose
    /// phrase appears in the subject or body (case-insensitive).
    #[must_use]
    pub fn score(&self, message: &Message) -> u32 {
        let mut haystack = message.subject().unwrap_or_default().to_ascii_lowercase();
        haystack.push('\n');
        haystack.push_str(&String::from_utf8_lossy(&message.body).to_ascii_lowercase());
        self.rules
            .iter()
            .filter(|rule| haystack.contains(&rule.phrase.to_ascii_lowercase()))
            .map(|rule| rule.weight)
            .sum()
    }
}

impl MessageFilter for SpamFilter {
    fn scan(&self, message: &Message) -> FilterVerdict {
        let score = self.score(message);
        if score >= self.reject_threshold {
            FilterVerdict::Reject
        } else if score >= self.flag_threshold {
            FilterVerdict::Flag
        } else {
            FilterVerdict::Accept
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mail::{Envelope, Message};

    fn message(subject: &str, body: &str) -> Message {
        Message::parse(
            Envelope::new(None, vec![]),
            format!("Subject: {subject}\r\n\r\n{body}").as_bytes(),
        )
        .unwrap()
    }

    #[test]
    fn clean_message_is_accepted() {
        let f = SpamFilter::new();
        assert_eq!(
            f.scan(&message("Lunch tomorrow?", "Are you free at noon?")),
            FilterVerdict::Accept
        );
    }

    #[test]
    fn single_hit_flags() {
        let f = SpamFilter::new();
        // "free money" = weight 5 == flag_threshold.
        let m = message("Re: offer", "get free money fast");
        assert_eq!(f.score(&m), 5);
        assert_eq!(f.scan(&m), FilterVerdict::Flag);
    }

    #[test]
    fn multiple_hits_reject() {
        let f = SpamFilter::new();
        // "you have won" (5) + "viagra" (5) = 10 == reject_threshold.
        let m = message("You have WON", "cheap VIAGRA here");
        assert_eq!(f.score(&m), 10);
        assert_eq!(f.scan(&m), FilterVerdict::Reject);
    }

    #[test]
    fn custom_rules_apply() {
        let f = SpamFilter::with_rules(vec![SpamRule::new("forbidden", 100)], 50, 100);
        assert_eq!(
            f.scan(&message("x", "this is FORBIDDEN content")),
            FilterVerdict::Reject
        );
    }
}
