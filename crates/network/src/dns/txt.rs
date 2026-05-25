//! TXT record value + the `tag=value; …` parser shared by DKIM/DMARC.

use std::collections::BTreeMap;

/// A raw TXT record (one or more concatenated character-strings).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TxtRecord(pub String);

/// Parse a `tag=value; tag=value` string into an ordered map (keys and values
/// trimmed; empty keys dropped).
#[must_use]
pub fn parse_tag_map(raw: &str) -> BTreeMap<String, String> {
    raw.split(';')
        .filter_map(|kv| kv.split_once('='))
        .map(|(k, v)| (k.trim().to_string(), v.trim().to_string()))
        .filter(|(k, _)| !k.is_empty())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_trimmed_tag_value_pairs() {
        let m = parse_tag_map("v=DKIM1; k=rsa ;  p=abc ");
        assert_eq!(m.get("v").map(String::as_str), Some("DKIM1"));
        assert_eq!(m.get("k").map(String::as_str), Some("rsa"));
        assert_eq!(m.get("p").map(String::as_str), Some("abc"));
    }

    #[test]
    fn ignores_fragments_without_equals() {
        let m = parse_tag_map("v=DMARC1; garbage; p=none");
        assert_eq!(m.len(), 2);
        assert_eq!(m.get("p").map(String::as_str), Some("none"));
    }
}
