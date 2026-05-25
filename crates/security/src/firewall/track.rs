//! Per-IP connection/attempt tracking.

use std::collections::HashMap;
use std::net::IpAddr;
use std::time::Instant;

/// A single IP's running attempt count and most-recent sighting.
#[derive(Debug, Clone, Copy)]
pub struct AttemptRecord {
    /// Number of attempts recorded.
    pub attempts: u64,
    /// When the most recent attempt was recorded.
    pub last_seen: Instant,
}

/// Tracks how often each IP has been seen and when.
#[derive(Debug, Default)]
pub struct ConnectionTracker {
    records: HashMap<IpAddr, AttemptRecord>,
}

impl ConnectionTracker {
    /// Create an empty tracker.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record an attempt from `ip`, returning its running total.
    pub fn record(&mut self, ip: IpAddr) -> u64 {
        let now = Instant::now();
        let rec = self.records.entry(ip).or_insert(AttemptRecord {
            attempts: 0,
            last_seen: now,
        });
        rec.attempts += 1;
        rec.last_seen = now;
        rec.attempts
    }

    /// Attempts recorded for `ip` (0 if never seen).
    #[must_use]
    pub fn attempts(&self, ip: &IpAddr) -> u64 {
        self.records.get(ip).map_or(0, |r| r.attempts)
    }

    /// Number of distinct IPs tracked.
    #[must_use]
    pub fn tracked_ips(&self) -> usize {
        self.records.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn record_increments_per_ip() {
        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let mut t = ConnectionTracker::new();
        assert_eq!(t.record(ip), 1);
        assert_eq!(t.record(ip), 2);
        assert_eq!(t.attempts(&ip), 2);
        assert_eq!(t.attempts(&IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2))), 0);
    }
}
