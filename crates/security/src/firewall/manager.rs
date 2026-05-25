//! `FirewallManager`: owns a [`Firewall`] built from configuration and supports
//! reloading that configuration at runtime.

use governor::clock::DefaultClock;

use crate::firewall::config::FirewallConfig;
use crate::firewall::firewall::Firewall;

/// Owns the live [`Firewall`] and the configuration it was built from, so the
/// composition root can hold one handle and reload policy without re-plumbing.
pub struct FirewallManager {
    firewall: Firewall<DefaultClock>,
    config: FirewallConfig,
}

impl FirewallManager {
    /// Build a manager (and its firewall) from `config`.
    #[must_use]
    pub fn new(config: FirewallConfig) -> Self {
        let firewall = Firewall::new(&config);
        Self { firewall, config }
    }

    /// The live firewall.
    #[must_use]
    pub fn firewall(&self) -> &Firewall<DefaultClock> {
        &self.firewall
    }

    /// The configuration the current firewall was built from.
    #[must_use]
    pub fn config(&self) -> &FirewallConfig {
        &self.config
    }

    /// Replace the firewall with one built from `config` (policy reload).
    pub fn reload(&mut self, config: FirewallConfig) {
        self.firewall = Firewall::new(&config);
        self.config = config;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::firewall::firewall::{Decision, DenyReason};
    use std::net::{IpAddr, Ipv4Addr};

    fn ip(n: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, n))
    }

    #[test]
    fn reload_applies_new_policy() {
        let mut mgr = FirewallManager::new(FirewallConfig::default());
        assert_eq!(mgr.firewall().check(ip(5)), Decision::Allow);

        mgr.reload(FirewallConfig {
            block: vec![ip(5)],
            ..FirewallConfig::default()
        });
        assert_eq!(
            mgr.firewall().check(ip(5)),
            Decision::Deny(DenyReason::Blocklisted)
        );
    }
}
