//! `Received:` trace headers and the RFC 5321 §6.3 hop-count loop breaker.
//!
//! Every accepted message gets a `Received:` header prepended at reception, both
//! to record the trace hop (RFC 5321 §4.4) and to give downstream MTAs — and us,
//! on a later hop — a way to count hops and break forwarding loops. A message
//! that arrives already carrying [`MAX_RECEIVED_HOPS`] `Received:` headers is
//! refused rather than delivered/relayed, so a loop cannot be relayed forever.
//!
//! The RFC 5322 date is formatted without a date/time dependency (the workspace
//! has none) via the civil-from-days algorithm, in UTC (`+0000`).

use std::time::{SystemTime, UNIX_EPOCH};

/// Maximum `Received:` headers a message may already carry before it is treated
/// as a mail loop and refused (RFC 5321 §6.3 suggests a limit of at least 100).
pub const MAX_RECEIVED_HOPS: usize = 100;

/// Build a `Received:` header line (no trailing CRLF) recording this hop:
/// `Received: from <helo> by <host> with <proto>; <rfc5322-date>`.
///
/// `helo` and `host` are sanitised of CR/LF so a hostile HELO argument cannot
/// inject extra header lines.
#[must_use]
pub fn received_header(helo: &str, host: &str, proto: &str, at: SystemTime) -> Vec<u8> {
    format!(
        "Received: from {} by {} with {proto}; {}",
        sanitize(helo),
        sanitize(host),
        rfc5322_date(at),
    )
    .into_bytes()
}

/// Strip CR/LF (header-injection defence) from an untrusted token.
fn sanitize(s: &str) -> String {
    s.replace(['\r', '\n'], "")
}

/// Format `at` as an RFC 5322 date-time in UTC, e.g. `Thu, 01 Jan 1970 00:00:00 +0000`.
#[must_use]
pub fn rfc5322_date(at: SystemTime) -> String {
    let secs = at
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let days = secs.div_euclid(86_400);
    let tod = secs.rem_euclid(86_400);
    let (hour, min, sec) = (tod / 3600, (tod % 3600) / 60, tod % 60);
    // 1970-01-01 was a Thursday; index 0 = Sun.
    let dow = (days.rem_euclid(7) + 4).rem_euclid(7) as usize;
    let (year, month, day) = civil_from_days(days);

    const WD: [&str; 7] = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
    const MON: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    format!(
        "{}, {day:02} {} {year} {hour:02}:{min:02}:{sec:02} +0000",
        WD[dow],
        MON[(month - 1) as usize],
    )
}

/// Civil (year, month, day) from a count of days since 1970-01-01 (Howard
/// Hinnant's algorithm; valid across the full proleptic Gregorian range).
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = (if z >= 0 { z } else { z - 146_096 }) / 146_097;
    let doe = z - era * 146_097; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365; // [0, 399]
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32; // [1, 31]
    let m = (if mp < 10 { mp + 3 } else { mp - 9 }) as u32; // [1, 12]
    (if m <= 2 { y + 1 } else { y }, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn rfc5322_date_at_epoch_is_the_unix_birthday() {
        assert_eq!(rfc5322_date(UNIX_EPOCH), "Thu, 01 Jan 1970 00:00:00 +0000");
    }

    #[test]
    fn rfc5322_date_of_a_known_instant() {
        // 1234567890 = Fri, 13 Feb 2009 23:31:30 UTC (a well-known epoch milestone).
        let at = UNIX_EPOCH + Duration::from_secs(1_234_567_890);
        assert_eq!(rfc5322_date(at), "Fri, 13 Feb 2009 23:31:30 +0000");
    }

    #[test]
    fn received_header_is_well_formed_and_injection_safe() {
        let at = UNIX_EPOCH + Duration::from_secs(1_234_567_890);
        // A hostile HELO with embedded CRLF must not inject a second header line.
        let h = received_header("evil\r\nX-Inject: yes", "snail.example", "ESMTP", at);
        let s = String::from_utf8(h).unwrap();
        assert_eq!(
            s,
            "Received: from evilX-Inject: yes by snail.example with ESMTP; \
             Fri, 13 Feb 2009 23:31:30 +0000"
        );
        assert!(!s.contains('\n') && !s.contains('\r'));
    }
}
