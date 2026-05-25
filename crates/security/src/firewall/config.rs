//! Firewall configuration.

use std::net::IpAddr;
use std::num::NonZeroU32;

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
}

impl Default for FirewallConfig {
    fn default() -> Self {
        Self {
            // 30 connections/minute/IP, bursting up to 30.
            quota: Quota::per_minute(NonZeroU32::new(30).expect("30 is non-zero")),
            allow: Vec::new(),
            block: Vec::new(),
            trace_capacity: 256,
        }
    }
}
