//! Dovecot interop: Maildir++ folder-name mapping.
//!
//! Maps logical mailbox names to the Maildir++ on-disk folder names Dovecot
//! uses — `INBOX` is the maildir root, sub-folders are `.Name`, and hierarchy is
//! separated by `.` — so a Dovecot frontend could serve mail stored by Snail.
//! (Deeper Dovecot integration, e.g. its auth socket protocol, is out of scope.)

/// Convert a logical mailbox path (e.g. `Sent`, `Work/2024`) to a Maildir++
/// folder name. `INBOX` maps to the maildir root `.`.
#[must_use]
pub fn to_maildir(mailbox: &str) -> String {
    if mailbox.eq_ignore_ascii_case("INBOX") {
        ".".to_string()
    } else {
        format!(".{}", mailbox.replace('/', "."))
    }
}

/// Convert a Maildir++ folder name back to a logical mailbox path. The root `.`
/// (or empty) maps back to `INBOX`.
#[must_use]
pub fn from_maildir(folder: &str) -> String {
    if folder == "." || folder.is_empty() {
        "INBOX".to_string()
    } else {
        folder.trim_start_matches('.').replace('.', "/")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inbox_maps_to_root() {
        assert_eq!(to_maildir("INBOX"), ".");
        assert_eq!(to_maildir("inbox"), ".");
        assert_eq!(from_maildir("."), "INBOX");
        assert_eq!(from_maildir(""), "INBOX");
    }

    #[test]
    fn subfolders_round_trip() {
        assert_eq!(to_maildir("Sent"), ".Sent");
        assert_eq!(to_maildir("Work/2024"), ".Work.2024");
        assert_eq!(from_maildir(".Work.2024"), "Work/2024");
        assert_eq!(from_maildir(&to_maildir("Lists/rust")), "Lists/rust");
    }
}
