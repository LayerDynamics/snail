//! The `Firewall`: composes the allow/block lists, a governor rate limiter,
//! connection tracking, a decision trace, and a pause switch into one gate.

use std::net::IpAddr;
use std::sync::{Mutex, PoisonError, RwLock};

use governor::RateLimiter;
use governor::clock::{Clock, DefaultClock};
use governor::middleware::NoOpMiddleware;
use governor::state::keyed::DefaultKeyedStateStore;

use crate::firewall::allow::AllowList;
use crate::firewall::block::BlockList;
use crate::firewall::config::FirewallConfig;
use crate::firewall::pause::PauseSwitch;
use crate::firewall::trace::DecisionTrace;
use crate::firewall::track::ConnectionTracker;

/// Why the firewall denied a connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DenyReason {
    /// The source IP is on the blocklist.
    Blocklisted,
    /// The source IP exceeded its rate-limit quota.
    RateLimited,
}

/// The outcome of a firewall check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    /// The connection is permitted.
    Allow,
    /// The connection is denied for the given reason.
    Deny(DenyReason),
}

type KeyedLimiter<C> =
    RateLimiter<IpAddr, DefaultKeyedStateStore<IpAddr>, C, NoOpMiddleware<<C as Clock>::Instant>>;

/// Connection-policy gate for the public-facing server. Generic over the clock
/// `C` so tests can drive a deterministic `FakeRelativeClock`.
pub struct Firewall<C: Clock = DefaultClock> {
    limiter: KeyedLimiter<C>,
    allow: RwLock<AllowList>,
    block: RwLock<BlockList>,
    tracker: Mutex<ConnectionTracker>,
    trace: Mutex<DecisionTrace>,
    pause: PauseSwitch,
}

impl Firewall<DefaultClock> {
    /// Build a firewall from `config` using the real system clock.
    #[must_use]
    pub fn new(config: &FirewallConfig) -> Self {
        Self::build(config, RateLimiter::keyed(config.quota))
    }
}

impl<C: Clock> Firewall<C> {
    /// Build a firewall from `config` using an explicit clock (e.g. a fake clock in tests).
    #[must_use]
    pub fn with_clock(config: &FirewallConfig, clock: C) -> Self {
        let limiter = RateLimiter::new(config.quota, DefaultKeyedStateStore::default(), &clock);
        Self::build(config, limiter)
    }

    fn build(config: &FirewallConfig, limiter: KeyedLimiter<C>) -> Self {
        let mut allow = AllowList::new();
        for ip in &config.allow {
            allow.insert(*ip);
        }
        let mut block = BlockList::new();
        for ip in &config.block {
            block.insert(*ip);
        }
        Self {
            limiter,
            allow: RwLock::new(allow),
            block: RwLock::new(block),
            tracker: Mutex::new(ConnectionTracker::new()),
            trace: Mutex::new(DecisionTrace::new(config.trace_capacity)),
            pause: PauseSwitch::new(),
        }
    }

    /// Decide whether a connection from `ip` is permitted.
    ///
    /// Evaluation order: paused (→ allow) → allowlist (→ allow) → blocklist
    /// (→ deny) → rate limit. Every call is tracked and traced.
    pub fn check(&self, ip: IpAddr) -> Decision {
        self.tracker
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .record(ip);

        let decision = if self.pause.is_paused()
            || self
                .allow
                .read()
                .unwrap_or_else(PoisonError::into_inner)
                .contains(&ip)
        {
            Decision::Allow
        } else if self
            .block
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .contains(&ip)
        {
            Decision::Deny(DenyReason::Blocklisted)
        } else if self.limiter.check_key(&ip).is_err() {
            Decision::Deny(DenyReason::RateLimited)
        } else {
            Decision::Allow
        };

        self.trace
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .record(ip, decision);
        decision
    }

    /// Add `ip` to the runtime allowlist.
    pub fn allow_ip(&self, ip: IpAddr) {
        self.allow
            .write()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(ip);
    }

    /// Add `ip` to the runtime blocklist.
    pub fn block_ip(&self, ip: IpAddr) {
        self.block
            .write()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(ip);
    }

    /// Pause enforcement (permit everything).
    pub fn pause(&self) {
        self.pause.pause();
    }

    /// Resume enforcement.
    pub fn resume(&self) {
        self.pause.resume();
    }

    /// Attempts recorded for `ip` so far.
    #[must_use]
    pub fn attempts(&self, ip: &IpAddr) -> u64 {
        self.tracker
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .attempts(ip)
    }

    /// Number of decisions currently retained in the trace ring.
    #[must_use]
    pub fn trace_len(&self) -> usize {
        self.trace
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use governor::Quota;
    use governor::clock::FakeRelativeClock;
    use std::net::Ipv4Addr;
    use std::num::NonZeroU32;
    use std::time::Duration;

    fn ip(n: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, n))
    }

    fn quota(per_sec: u32) -> Quota {
        Quota::per_second(NonZeroU32::new(per_sec).unwrap())
    }

    #[test]
    fn blocklisted_ip_is_denied() {
        let cfg = FirewallConfig {
            block: vec![ip(9)],
            ..FirewallConfig::default()
        };
        let fw = Firewall::new(&cfg);
        assert_eq!(fw.check(ip(9)), Decision::Deny(DenyReason::Blocklisted));
    }

    #[test]
    fn allowlisted_ip_bypasses_blocklist_and_rate_limit() {
        let cfg = FirewallConfig {
            allow: vec![ip(1)],
            block: vec![ip(1)],
            quota: quota(1),
            ..FirewallConfig::default()
        };
        let fw = Firewall::new(&cfg);
        // Allowlist is checked before blocklist and rate limit.
        for _ in 0..5 {
            assert_eq!(fw.check(ip(1)), Decision::Allow);
        }
    }

    #[test]
    fn rate_limit_denies_after_burst_then_recovers_with_clock() {
        let clock = FakeRelativeClock::default();
        let cfg = FirewallConfig {
            quota: quota(2), // burst 2, replenish 1 per 500ms
            ..FirewallConfig::default()
        };
        let fw = Firewall::with_clock(&cfg, clock.clone());

        assert_eq!(fw.check(ip(2)), Decision::Allow);
        assert_eq!(fw.check(ip(2)), Decision::Allow);
        assert_eq!(fw.check(ip(2)), Decision::Deny(DenyReason::RateLimited));

        clock.advance(Duration::from_secs(1)); // replenishes the burst
        assert_eq!(fw.check(ip(2)), Decision::Allow);
    }

    #[test]
    fn pause_permits_even_blocklisted_then_resume_restores() {
        let cfg = FirewallConfig {
            block: vec![ip(9)],
            ..FirewallConfig::default()
        };
        let fw = Firewall::new(&cfg);
        fw.pause();
        assert_eq!(fw.check(ip(9)), Decision::Allow);
        fw.resume();
        assert_eq!(fw.check(ip(9)), Decision::Deny(DenyReason::Blocklisted));
    }

    #[test]
    fn checks_are_tracked_and_traced() {
        let fw = Firewall::new(&FirewallConfig::default());
        fw.check(ip(3));
        fw.check(ip(3));
        assert_eq!(fw.attempts(&ip(3)), 2);
        assert_eq!(fw.trace_len(), 2);
    }
}
