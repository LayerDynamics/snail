//! Firewall configuration.

use std::net::IpAddr;
use std::num::NonZeroU32;
use std::time::Duration;

use governor::Quota;

/// Configuration for a [`crate::firewall::Firewall`].
#[derive(Debug, Clone)]
pub struct FirewallConfig {
    /// Per-IP request quota (rate limit + burst).
    pub quota: Quota,
    /// IPs always permitted (bypass the rate limit).
    pub allow: Vec<IpAddr>,
    /// IPs always denied.
    pub block: Vec<IpAddr>,
    /// Capacity of the recent-decision trace ring.
    pub trace_capacity: usize,
    /// Hard cap on the number of distinct IPs the connection tracker retains.
    /// Once reached, new IPs go uncounted until idle ones are evicted — a
    /// backstop so a distinct-IP flood cannot exhaust memory. Tighten under
    /// memory pressure.
    pub max_tracked_ips: usize,
    /// How long an IP's tracker entry survives without being seen before it is
    /// eligible for eviction.
    pub idle_ttl: Duration,
}

impl Default for FirewallConfig {
    fn default() -> Self {
        Self {
            // 30 connections/minute/IP, bursting up to 30.
            quota: Quota::per_minute(NonZeroU32::new(30).expect("30 is non-zero")),
            allow: Vec::new(),
            block: Vec::new(),
            trace_capacity: 256,
            max_tracked_ips: 100_000,
            idle_ttl: Duration::from_secs(600),
        }
    }
}
