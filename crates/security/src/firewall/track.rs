//! Per-IP connection/attempt tracking — bounded so a distinct-IP flood cannot
//! grow it without limit (memory-exhaustion DoS).

use std::collections::HashMap;
use std::net::IpAddr;
use std::time::{Duration, Instant};

/// Run an idle-eviction sweep once every this many `record` calls (amortised, so
/// the per-call cost stays O(1) while the sweep is O(tracked)).
const PRUNE_INTERVAL: u32 = 1024;

/// A single IP's running attempt count and most-recent sighting.
#[derive(Debug, Clone, Copy)]
pub struct AttemptRecord {
    /// Number of attempts recorded.
    pub attempts: u64,
    /// When the most recent attempt was recorded.
    pub last_seen: Instant,
}

/// Tracks how often each IP has been seen and when. This counter is
/// observational — it does not gate the [`crate::firewall::Firewall`] decision
/// (the rate limiter and allow/block lists do) — so under a flood it may stop
/// recording new IPs once at capacity rather than grow without bound.
#[derive(Debug)]
pub struct ConnectionTracker {
    records: HashMap<IpAddr, AttemptRecord>,
    /// Entries idle longer than this are evicted on the next sweep.
    idle_ttl: Duration,
    /// Hard cap on retained IPs.
    max_tracked: usize,
    /// `record` calls since the last sweep.
    since_prune: u32,
}

impl Default for ConnectionTracker {
    fn default() -> Self {
        Self::with_limits(Duration::from_secs(600), 100_000)
    }
}

impl ConnectionTracker {
    /// Create an empty tracker with default limits (10-minute idle TTL, 100k IPs).
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Create an empty tracker with explicit eviction limits.
    #[must_use]
    pub fn with_limits(idle_ttl: Duration, max_tracked: usize) -> Self {
        Self {
            records: HashMap::new(),
            idle_ttl,
            max_tracked,
            since_prune: 0,
        }
    }

    /// Record an attempt from `ip`, returning its running total.
    pub fn record(&mut self, ip: IpAddr) -> u64 {
        self.record_at(ip, Instant::now())
    }

    /// [`Self::record`] with an injected clock — the deterministic test seam.
    fn record_at(&mut self, ip: IpAddr, now: Instant) -> u64 {
        self.since_prune = self.since_prune.saturating_add(1);
        if self.since_prune >= PRUNE_INTERVAL {
            self.prune(now);
        }
        if let Some(rec) = self.records.get_mut(&ip) {
            rec.attempts += 1;
            rec.last_seen = now;
            return rec.attempts;
        }
        // A new IP. Enforce the hard cap: between sweeps, once full, stop growing
        // (this counter is observational, so dropping the entry is safe and keeps
        // the map bounded at O(1) per call — no per-insert scan to amplify a flood).
        if self.records.len() >= self.max_tracked {
            return 1;
        }
        self.records.insert(
            ip,
            AttemptRecord {
                attempts: 1,
                last_seen: now,
            },
        );
        1
    }

    /// Evict entries idle longer than the TTL and release freed capacity.
    fn prune(&mut self, now: Instant) {
        self.records
            .retain(|_, r| now.saturating_duration_since(r.last_seen) < self.idle_ttl);
        self.records.shrink_to_fit();
        self.since_prune = 0;
    }

    /// Attempts recorded for `ip` (0 if never seen, or if it went untracked
    /// because the tracker was at capacity during a flood).
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

    fn ip(n: u32) -> IpAddr {
        IpAddr::V4(Ipv4Addr::from(n))
    }

    #[test]
    fn record_increments_per_ip() {
        let one = ip(1);
        let mut t = ConnectionTracker::new();
        assert_eq!(t.record(one), 1);
        assert_eq!(t.record(one), 2);
        assert_eq!(t.attempts(&one), 2);
        assert_eq!(t.attempts(&ip(2)), 0);
    }

    #[test]
    fn hard_cap_bounds_distinct_ips() {
        let mut t = ConnectionTracker::with_limits(Duration::from_secs(600), 100);
        let now = Instant::now();
        for n in 0..5000 {
            t.record_at(ip(n), now);
        }
        assert!(
            t.tracked_ips() <= 100,
            "tracker must stay within the cap, got {}",
            t.tracked_ips()
        );
    }

    #[test]
    fn idle_entries_are_evicted_on_sweep() {
        let ttl = Duration::from_secs(600);
        let mut t = ConnectionTracker::with_limits(ttl, 100_000);
        let start = Instant::now();
        // Seed one IP, then drive PRUNE_INTERVAL records from fresh IPs far in the
        // future so the seeded entry is now idle past its TTL and gets swept.
        t.record_at(ip(1), start);
        let later = start + ttl + Duration::from_secs(1);
        for n in 0..PRUNE_INTERVAL {
            t.record_at(ip(10_000 + n), later);
        }
        assert_eq!(t.attempts(&ip(1)), 0, "the idle entry should be evicted");
    }
}
