//! Blocklist: IP addresses that are always denied by the firewall.

use std::collections::HashSet;
use std::net::IpAddr;

/// A set of IP addresses that are always denied.
#[derive(Debug, Default, Clone)]
pub struct BlockList {
    ips: HashSet<IpAddr>,
}

impl BlockList {
    /// Create an empty blocklist.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add an IP. Returns `true` if it was newly inserted.
    pub fn insert(&mut self, ip: IpAddr) -> bool {
        self.ips.insert(ip)
    }

    /// Remove an IP. Returns `true` if it was present.
    pub fn remove(&mut self, ip: &IpAddr) -> bool {
        self.ips.remove(ip)
    }

    /// Whether `ip` is blocklisted.
    #[must_use]
    pub fn contains(&self, ip: &IpAddr) -> bool {
        self.ips.contains(ip)
    }

    /// Number of blocklisted IPs.
    #[must_use]
    pub fn len(&self) -> usize {
        self.ips.len()
    }

    /// Whether the blocklist is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.ips.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn insert_contains_remove() {
        let ip = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7));
        let mut list = BlockList::new();
        assert!(list.insert(ip));
        assert!(list.contains(&ip));
        assert!(list.remove(&ip));
        assert!(!list.contains(&ip));
    }
}
