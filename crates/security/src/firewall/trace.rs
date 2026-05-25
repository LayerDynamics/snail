//! Bounded ring of recent firewall decisions, for forensics / observability.

use std::collections::VecDeque;
use std::net::IpAddr;

use crate::firewall::firewall::Decision;

/// A capacity-bounded record of the most recent `(Ip, Decision)` pairs. Oldest
/// entries are dropped once capacity is reached.
#[derive(Debug)]
pub struct DecisionTrace {
    capacity: usize,
    entries: VecDeque<(IpAddr, Decision)>,
}

impl DecisionTrace {
    /// Create a trace holding up to `capacity` entries (minimum 1).
    #[must_use]
    pub fn new(capacity: usize) -> Self {
        Self {
            capacity: capacity.max(1),
            entries: VecDeque::new(),
        }
    }

    /// Record a decision, evicting the oldest entry if at capacity.
    pub fn record(&mut self, ip: IpAddr, decision: Decision) {
        if self.entries.len() == self.capacity {
            self.entries.pop_front();
        }
        self.entries.push_back((ip, decision));
    }

    /// Iterate the retained decisions, oldest first.
    pub fn recent(&self) -> impl Iterator<Item = &(IpAddr, Decision)> {
        self.entries.iter()
    }

    /// Number of decisions currently retained.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the trace is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::firewall::firewall::DenyReason;
    use std::net::Ipv4Addr;

    fn ip(n: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, n))
    }

    #[test]
    fn ring_is_bounded_and_evicts_oldest() {
        let mut t = DecisionTrace::new(2);
        t.record(ip(1), Decision::Allow);
        t.record(ip(2), Decision::Deny(DenyReason::RateLimited));
        t.record(ip(3), Decision::Allow);
        assert_eq!(t.len(), 2);
        // ip(1) was evicted; oldest retained is ip(2).
        assert_eq!(t.recent().next().unwrap().0, ip(2));
    }

    #[test]
    fn zero_capacity_is_clamped_to_one() {
        let mut t = DecisionTrace::new(0);
        t.record(ip(1), Decision::Allow);
        assert_eq!(t.len(), 1);
    }
}
