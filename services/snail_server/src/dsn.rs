//! Delivery Status Notification (RFC 3464) bounce generation.
//!
//! When an outbound message permanently fails (or exhausts its retries), the
//! sender must be told — otherwise mail vanishes silently. This builds a
//! `multipart/report; report-type=delivery-status` bounce addressed to the
//! original sender, with the **null envelope sender** (`MAIL FROM:<>`), per RFC
//! 3464 §3: a DSN is itself sent with an empty reverse-path so it can never
//! trigger a further DSN (the worker also refuses to bounce a null-sender
//! message, closing the loop on both sides).

use std::time::SystemTime;

use mail::{Envelope, Mailbox, Message};

use crate::received::rfc5322_date;

/// Build a failure DSN to `original_sender` reporting that delivery to
/// `failed_recipients` failed with `reason`. `host` is this MTA's name (used in
/// the daemon address and `Reporting-MTA`). `original_headers` are embedded as a
/// `text/rfc822-headers` part so the sender can identify the bounced message.
///
/// The returned [`Message`] carries the **null envelope sender** (`None`) and a
/// single recipient (the original sender), ready to route via
/// `Server::accept_inbound`.
#[must_use]
pub fn build_failure_dsn(
    host: &str,
    original_sender: &Mailbox,
    failed_recipients: &[Mailbox],
    reason: &str,
    original_headers: &[u8],
    at: SystemTime,
) -> Message {
    let host = sanitize_line(host);
    let date = rfc5322_date(at);
    let reason = sanitize_line(reason);
    // A boundary that cannot occur in the parts (header bytes can't contain it).
    let boundary = format!("=_snail_dsn_{}", boundary_nonce(at));

    let mut raw = Vec::new();
    // --- Outer headers ---
    push(
        &mut raw,
        &format!("From: Mail Delivery System <MAILER-DAEMON@{host}>"),
    );
    push(&mut raw, &format!("To: <{original_sender}>"));
    push(&mut raw, "Subject: Undelivered Mail Returned to Sender");
    push(&mut raw, &format!("Date: {date}"));
    push(&mut raw, "Auto-Submitted: auto-replied");
    push(&mut raw, "MIME-Version: 1.0");
    push(
        &mut raw,
        &format!(
            "Content-Type: multipart/report; report-type=delivery-status; boundary=\"{boundary}\""
        ),
    );
    push(&mut raw, ""); // end of headers

    // --- Part 1: human-readable explanation ---
    push(&mut raw, &format!("--{boundary}"));
    push(&mut raw, "Content-Type: text/plain; charset=us-ascii");
    push(&mut raw, "");
    push(
        &mut raw,
        &format!("This is the mail system at host {host}."),
    );
    push(&mut raw, "");
    push(
        &mut raw,
        "Your message could not be delivered to one or more recipients.",
    );
    push(&mut raw, "The error reported was:");
    push(&mut raw, "");
    push(&mut raw, &format!("    {reason}"));
    push(&mut raw, "");
    for rcpt in failed_recipients {
        push(&mut raw, &format!("    <{rcpt}>: delivery failed"));
    }
    push(&mut raw, "");

    // --- Part 2: machine-readable delivery-status (RFC 3464) ---
    push(&mut raw, &format!("--{boundary}"));
    push(&mut raw, "Content-Type: message/delivery-status");
    push(&mut raw, "");
    push(&mut raw, &format!("Reporting-MTA: dns; {host}"));
    push(&mut raw, &format!("Arrival-Date: {date}"));
    for rcpt in failed_recipients {
        push(&mut raw, "");
        push(&mut raw, &format!("Final-Recipient: rfc822; {rcpt}"));
        push(&mut raw, "Action: failed");
        push(&mut raw, "Status: 5.0.0");
        push(&mut raw, &format!("Diagnostic-Code: smtp; {reason}"));
    }
    push(&mut raw, "");

    // --- Part 3: the original message's headers (text/rfc822-headers) ---
    push(&mut raw, &format!("--{boundary}"));
    push(&mut raw, "Content-Type: text/rfc822-headers");
    push(&mut raw, "");
    // Embedded verbatim; these are the bytes the sender sent us.
    raw.extend_from_slice(original_headers);
    if !original_headers.ends_with(b"\r\n") {
        raw.extend_from_slice(b"\r\n");
    }

    // --- Closing boundary ---
    push(&mut raw, &format!("--{boundary}--"));

    // Parse back into a Message with the null-sender envelope. Parsing our own
    // well-formed bytes cannot fail, but fall back to a trivial body if it does.
    let envelope = Envelope::new(None, vec![original_sender.clone()]);
    Message::parse(envelope.clone(), &raw).unwrap_or_else(|_| {
        Message::parse(
            envelope,
            b"Subject: Undelivered Mail Returned to Sender\r\n\r\nDelivery failed.\r\n",
        )
        .expect("the trivial fallback DSN is always well-formed")
    })
}

/// Append `line` followed by CRLF.
fn push(out: &mut Vec<u8>, line: &str) {
    out.extend_from_slice(line.as_bytes());
    out.extend_from_slice(b"\r\n");
}

/// Strip CR/LF so an attacker-influenced `reason`/`host` cannot inject headers
/// or extra MIME parts into the DSN.
fn sanitize_line(s: &str) -> String {
    s.replace(['\r', '\n'], " ")
}

/// A short nonce for the MIME boundary, derived from the timestamp.
fn boundary_nonce(at: SystemTime) -> u128 {
    at.duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, UNIX_EPOCH};

    fn mb(s: &str) -> Mailbox {
        Mailbox::parse(s).unwrap()
    }

    #[test]
    fn dsn_has_null_envelope_sender_and_targets_original_sender() {
        let dsn = build_failure_dsn(
            "snail.example",
            &mb("alice@remote.test"),
            &[mb("bob@example.com")],
            "550 no such user",
            b"Subject: hi\r\nFrom: alice@remote.test\r\n\r\n",
            UNIX_EPOCH + Duration::from_secs(1_234_567_890),
        );
        // RFC 3464 §3: a DSN uses the null reverse-path so it can never re-bounce.
        assert!(dsn.envelope.sender.is_none());
        assert_eq!(dsn.envelope.recipients, vec![mb("alice@remote.test")]);
    }

    #[test]
    fn dsn_is_a_multipart_report_naming_the_failure() {
        let dsn = build_failure_dsn(
            "snail.example",
            &mb("alice@remote.test"),
            &[mb("bob@example.com")],
            "550 mailbox unavailable",
            b"Subject: hi\r\n\r\n",
            UNIX_EPOCH + Duration::from_secs(1_234_567_890),
        );
        let bytes = dsn.to_bytes();
        let text = String::from_utf8_lossy(&bytes);
        assert!(text.contains("multipart/report; report-type=delivery-status"));
        assert!(text.contains("message/delivery-status"));
        assert!(text.contains("Final-Recipient: rfc822; bob@example.com"));
        assert!(text.contains("Action: failed"));
        assert!(text.contains("550 mailbox unavailable"));
        assert!(text.contains("MAILER-DAEMON@snail.example"));
        assert!(text.contains("To: <alice@remote.test>"));
    }

    #[test]
    fn dsn_reason_cannot_inject_headers() {
        let dsn = build_failure_dsn(
            "snail.example",
            &mb("alice@remote.test"),
            &[mb("bob@example.com")],
            "evil\r\nBcc: victim@example.com",
            b"Subject: hi\r\n\r\n",
            UNIX_EPOCH,
        );
        let text = String::from_utf8_lossy(&dsn.to_bytes()).into_owned();
        // The injected CRLF is flattened, so no rogue Bcc header line appears.
        assert!(!text.contains("\nBcc: victim@example.com"));
    }
}
