//! Greylisting (RFC 6647 §2.5): temporarily defer the first delivery attempt for
//! an unseen `(network, sender, recipient)` triplet, then accept it once the
//! sender retries after a short delay. Spam bots rarely retry; legitimate MTAs
//! do. State is per-triplet and bounded.
//!
//! The source is keyed by network (IPv4 `/24`, IPv6 `/64`) rather than exact IP,
//! so a sender whose retries come from a different host in the same provider pool
//! is still recognised — a common cause of greylisting breakage otherwise.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::{Mutex, PoisonError};
use std::time::{Duration, SystemTime};

/// Greylisting policy.
#[derive(Debug, Clone, Copy)]
pub struct GreylistConfig {
    /// Minimum wait before a retried triplet is accepted.
    pub delay: Duration,
    /// How long a still-pending (deferred, not-yet-retried) triplet is remembered;
    /// after this it is forgotten and a fresh attempt starts the delay over.
    pub pending_ttl: Duration,
    /// How long a passed triplet is whitelisted (later mail skips the delay).
    pub pass_ttl: Duration,
    /// Hard cap on tracked triplets (memory bound). At capacity, unseen triplets
    /// are allowed (fail-open) so a flood cannot block all mail.
    pub max_entries: usize,
}

impl Default for GreylistConfig {
    fn default() -> Self {
        Self {
            delay: Duration::from_secs(60),
            pending_ttl: Duration::from_secs(6 * 60 * 60),
            pass_ttl: Duration::from_secs(30 * 24 * 60 * 60),
            max_entries: 100_000,
        }
    }
}

/// The greylisting decision for one delivery attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GreyDecision {
    /// Accept the recipient.
    Allow,
    /// Temporarily refuse (`4xx`); the sender should retry after the delay.
    Defer,
}

type Triplet = (IpAddr, String, String);

#[derive(Debug)]
struct Entry {
    first_seen: SystemTime,
    last_seen: SystemTime,
    passed: bool,
}

/// A per-triplet greylist. Cheap to share via `Arc`; all state is behind one mutex.
#[derive(Debug)]
pub struct Greylist {
    config: GreylistConfig,
    entries: Mutex<HashMap<Triplet, Entry>>,
}

impl Greylist {
    /// Build a greylist with the given policy.
    #[must_use]
    pub fn new(config: GreylistConfig) -> Self {
        Self {
            config,
            entries: Mutex::new(HashMap::new()),
        }
    }

    /// Decide whether to accept a `(source IP, sender, recipient)` delivery now.
    #[must_use]
    pub fn check(&self, ip: IpAddr, sender: &str, recipient: &str) -> GreyDecision {
        self.check_at(ip, sender, recipient, SystemTime::now())
    }

    /// [`Self::check`] with an injected clock — the deterministic test seam.
    fn check_at(&self, ip: IpAddr, sender: &str, recipient: &str, now: SystemTime) -> GreyDecision {
        let key = (
            mask_ip(ip),
            sender.to_ascii_lowercase(),
            recipient.to_ascii_lowercase(),
        );
        let mut entries = self.entries.lock().unwrap_or_else(PoisonError::into_inner);
        prune(&mut entries, now, &self.config);

        if let Some(entry) = entries.get_mut(&key) {
            entry.last_seen = now;
            if entry.passed {
                return GreyDecision::Allow;
            }
            // Accept once the sender has waited at least `delay` before retrying.
            if now
                .duration_since(entry.first_seen)
                .is_ok_and(|waited| waited >= self.config.delay)
            {
                entry.passed = true;
                return GreyDecision::Allow;
            }
            return GreyDecision::Defer;
        }

        // Unseen triplet. Under a flood at capacity, fail open rather than block.
        if entries.len() >= self.config.max_entries {
            return GreyDecision::Allow;
        }
        entries.insert(
            key,
            Entry {
                first_seen: now,
                last_seen: now,
                passed: false,
            },
        );
        GreyDecision::Defer
    }

    /// Number of triplets currently tracked (for tests/metrics).
    #[must_use]
    pub fn tracked(&self) -> usize {
        self.entries
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .len()
    }
}

/// Mask an IP to its greylisting network: IPv4 `/24`, IPv6 `/64`.
fn mask_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            IpAddr::V4(Ipv4Addr::new(o[0], o[1], o[2], 0))
        }
        IpAddr::V6(v6) => {
            let s = v6.segments();
            IpAddr::V6(Ipv6Addr::new(s[0], s[1], s[2], s[3], 0, 0, 0, 0))
        }
    }
}

/// Forget passed triplets past `pass_ttl` and pending triplets past `pending_ttl`,
/// bounding memory under a flood of distinct triplets.
fn prune(entries: &mut HashMap<Triplet, Entry>, now: SystemTime, config: &GreylistConfig) {
    entries.retain(|_, entry| {
        let ttl = if entry.passed {
            config.pass_ttl
        } else {
            config.pending_ttl
        };
        entry
            .last_seen
            .checked_add(ttl)
            .is_some_and(|deadline| deadline > now)
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> GreylistConfig {
        GreylistConfig {
            delay: Duration::from_secs(60),
            pending_ttl: Duration::from_secs(3600),
            pass_ttl: Duration::from_secs(86_400),
            max_entries: 100,
        }
    }

    fn ip(last: u8) -> IpAddr {
        IpAddr::from([203, 0, 113, last])
    }

    fn at(secs: u64) -> SystemTime {
        SystemTime::UNIX_EPOCH + Duration::from_secs(secs)
    }

    #[test]
    fn first_attempt_defers_then_retry_after_delay_passes() {
        let g = Greylist::new(cfg());
        // First sight → defer.
        assert_eq!(
            g.check_at(ip(1), "a@x.test", "b@y.test", at(1000)),
            GreyDecision::Defer
        );
        // Retry too soon → still deferred.
        assert_eq!(
            g.check_at(ip(1), "a@x.test", "b@y.test", at(1030)),
            GreyDecision::Defer
        );
        // Retry after the delay → accepted.
        assert_eq!(
            g.check_at(ip(1), "a@x.test", "b@y.test", at(1061)),
            GreyDecision::Allow
        );
        // Subsequently whitelisted (passed) → immediate accept.
        assert_eq!(
            g.check_at(ip(1), "a@x.test", "b@y.test", at(1062)),
            GreyDecision::Allow
        );
    }

    #[test]
    fn triplet_is_specific_to_ip_sender_recipient() {
        let g = Greylist::new(cfg());
        g.check_at(ip(1), "a@x.test", "b@y.test", at(1000)); // defer + record
        // Different recipient → a new triplet, also deferred.
        assert_eq!(
            g.check_at(ip(1), "a@x.test", "c@y.test", at(1000)),
            GreyDecision::Defer
        );
        // Different sender → new triplet.
        assert_eq!(
            g.check_at(ip(1), "z@x.test", "b@y.test", at(1000)),
            GreyDecision::Defer
        );
    }

    #[test]
    fn same_network_is_treated_as_one_source() {
        let g = Greylist::new(cfg());
        // First attempt from .1, retry from .2 in the same /24 → recognised.
        assert_eq!(
            g.check_at(ip(1), "a@x.test", "b@y.test", at(1000)),
            GreyDecision::Defer
        );
        assert_eq!(
            g.check_at(ip(2), "a@x.test", "b@y.test", at(1061)),
            GreyDecision::Allow,
            "a /24 neighbour's retry after the delay is accepted"
        );
    }

    #[test]
    fn pending_triplets_expire() {
        let g = Greylist::new(cfg());
        g.check_at(ip(1), "a@x.test", "b@y.test", at(1000));
        assert_eq!(g.tracked(), 1);
        // Past pending_ttl with no retry → pruned on the next check.
        let _ = g.check_at(ip(9), "q@x.test", "r@y.test", at(1000 + 3601));
        assert!(
            g.tracked() <= 1,
            "the stale pending triplet was pruned, got {}",
            g.tracked()
        );
    }

    #[test]
    fn fail_open_at_capacity() {
        let g = Greylist::new(GreylistConfig {
            max_entries: 1,
            ..cfg()
        });
        assert_eq!(
            g.check_at(ip(1), "a@x.test", "b@y.test", at(1000)),
            GreyDecision::Defer
        );
        // At capacity, an unseen triplet is allowed rather than blocking mail.
        assert_eq!(
            g.check_at(ip(2), "c@x.test", "d@y.test", at(1000)),
            GreyDecision::Allow
        );
    }
}
