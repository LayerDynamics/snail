//! Brute-force authentication throttle: a per-IP failed-attempt counter with a
//! hard lockout, shared across connections so reconnecting does not reset the
//! budget. Consulted by the client-facing protocol loops (IMAP/POP3/submission)
//! on each credential check; distinct from the connection-rate [`crate::Firewall`].

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Mutex, PoisonError};
use std::time::{Duration, SystemTime};

/// Throttle policy: how many failed attempts an IP may make before it is locked
/// out, and for how long.
#[derive(Debug, Clone, Copy)]
pub struct ThrottleConfig {
    /// Failed attempts from one IP that trigger a lockout.
    pub max_failures: u32,
    /// How long an IP stays locked out once the threshold is reached.
    pub lockout: Duration,
}

impl Default for ThrottleConfig {
    fn default() -> Self {
        Self {
            max_failures: 5,
            lockout: Duration::from_secs(15 * 60),
        }
    }
}

/// One IP's failed-attempt record.
#[derive(Debug)]
struct Attempt {
    failures: u32,
    locked_until: Option<SystemTime>,
    last_seen: SystemTime,
}

/// A per-IP authentication throttle. Cheap to clone the `Arc` around it; all
/// state lives behind one mutex (the contended path is a brief map update).
#[derive(Debug)]
pub struct AuthThrottle {
    config: ThrottleConfig,
    records: Mutex<HashMap<IpAddr, Attempt>>,
}

impl AuthThrottle {
    /// Build a throttle with the given policy.
    #[must_use]
    pub fn new(config: ThrottleConfig) -> Self {
        Self {
            config,
            records: Mutex::new(HashMap::new()),
        }
    }

    /// Whether `ip` may currently attempt authentication (`false` while locked out).
    #[must_use]
    pub fn check(&self, ip: IpAddr) -> bool {
        self.check_at(ip, SystemTime::now())
    }

    /// Record a failed authentication attempt from `ip`, locking it out once the
    /// configured threshold is reached.
    pub fn record_failure(&self, ip: IpAddr) {
        self.record_failure_at(ip, SystemTime::now());
    }

    /// Clear `ip`'s failure history after a successful authentication.
    pub fn record_success(&self, ip: IpAddr) {
        self.guard().remove(&ip);
    }

    fn guard(&self) -> std::sync::MutexGuard<'_, HashMap<IpAddr, Attempt>> {
        self.records.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// [`Self::check`] with an injected clock — the deterministic test seam.
    fn check_at(&self, ip: IpAddr, now: SystemTime) -> bool {
        match self.guard().get(&ip) {
            // Allowed unless there is a lockout still in the future.
            Some(attempt) => attempt.locked_until.is_none_or(|until| until <= now),
            None => true,
        }
    }

    /// [`Self::record_failure`] with an injected clock — the deterministic test seam.
    fn record_failure_at(&self, ip: IpAddr, now: SystemTime) {
        let ThrottleConfig {
            max_failures,
            lockout,
        } = self.config;
        let mut records = self.guard();
        prune(&mut records, now, lockout);
        let attempt = records.entry(ip).or_insert(Attempt {
            failures: 0,
            locked_until: None,
            last_seen: now,
        });
        attempt.last_seen = now;
        // Already locked out: the failure changes nothing until the lock lifts.
        if attempt.locked_until.is_some_and(|until| until > now) {
            return;
        }
        // A prior lockout has elapsed: begin a fresh window.
        if attempt.locked_until.is_some() {
            attempt.failures = 0;
            attempt.locked_until = None;
        }
        attempt.failures += 1;
        if attempt.failures >= max_failures {
            attempt.locked_until = now.checked_add(lockout);
        }
    }
}

/// Drop records that are neither currently locked nor seen within the lockout
/// window, bounding memory under a flood of distinct source IPs.
fn prune(records: &mut HashMap<IpAddr, Attempt>, now: SystemTime, lockout: Duration) {
    records.retain(|_, attempt| {
        attempt.locked_until.is_some_and(|until| until > now)
            || attempt
                .last_seen
                .checked_add(lockout)
                .is_some_and(|deadline| deadline > now)
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(last: u8) -> IpAddr {
        IpAddr::from([127, 0, 0, last])
    }

    fn cfg() -> ThrottleConfig {
        ThrottleConfig {
            max_failures: 3,
            lockout: Duration::from_secs(900),
        }
    }

    fn at(secs: u64) -> SystemTime {
        SystemTime::UNIX_EPOCH + Duration::from_secs(secs)
    }

    #[test]
    fn allows_below_threshold_then_locks_at_threshold() {
        let t = AuthThrottle::new(cfg());
        let now = at(1000);
        assert!(t.check_at(ip(1), now));
        t.record_failure_at(ip(1), now);
        t.record_failure_at(ip(1), now);
        assert!(
            t.check_at(ip(1), now),
            "two failures is still under the limit"
        );
        t.record_failure_at(ip(1), now); // third trips the lockout
        assert!(
            !t.check_at(ip(1), now),
            "locked once the threshold is reached"
        );
    }

    #[test]
    fn success_clears_the_failure_history() {
        let t = AuthThrottle::new(cfg());
        let now = at(1000);
        for _ in 0..3 {
            t.record_failure_at(ip(1), now);
        }
        assert!(!t.check_at(ip(1), now));
        t.record_success(ip(1));
        assert!(t.check_at(ip(1), now), "a success unlocks the IP");
    }

    #[test]
    fn lockout_expires_after_the_window() {
        let t = AuthThrottle::new(cfg());
        let now = at(1000);
        for _ in 0..3 {
            t.record_failure_at(ip(1), now);
        }
        assert!(!t.check_at(ip(1), now));
        assert!(
            t.check_at(ip(1), now + Duration::from_secs(901)),
            "the lockout lifts after its window"
        );
    }

    #[test]
    fn lockout_is_per_ip() {
        let t = AuthThrottle::new(cfg());
        let now = at(1000);
        for _ in 0..3 {
            t.record_failure_at(ip(1), now);
        }
        assert!(!t.check_at(ip(1), now));
        assert!(t.check_at(ip(2), now), "a different IP is unaffected");
    }
}
