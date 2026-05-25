//! Security audit logging: a structured `tracing` event per occurrence plus a
//! capacity-bounded in-memory ring of the most recent events for inspection.

use std::collections::VecDeque;
use std::net::IpAddr;
use std::sync::{Mutex, PoisonError};

use tracing::{info, warn};

use crate::audit::config::AuditConfig;

/// A security-relevant event worth auditing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuditEvent {
    /// A user authenticated successfully.
    AuthSuccess {
        /// The authenticated username.
        user: String,
    },
    /// An authentication attempt failed.
    AuthFailure {
        /// The username that was attempted.
        user: String,
        /// The source address.
        ip: IpAddr,
    },
    /// A connection was blocked by the firewall.
    Blocked {
        /// The blocked source address.
        ip: IpAddr,
        /// Why it was blocked.
        reason: String,
    },
    /// A connection was rate-limited.
    RateLimited {
        /// The throttled source address.
        ip: IpAddr,
    },
}

/// Records [`AuditEvent`]s: emits a structured `tracing` event (so telemetry
/// captures it) and retains a capacity-bounded ring of the most recent events.
pub struct AuditLog {
    capacity: usize,
    recent: Mutex<VecDeque<AuditEvent>>,
}

impl AuditLog {
    /// Create an audit log from configuration.
    #[must_use]
    pub fn new(config: &AuditConfig) -> Self {
        Self {
            capacity: config.capacity.max(1),
            recent: Mutex::new(VecDeque::new()),
        }
    }

    /// Record an event: emit it via `tracing` and append it to the recent ring,
    /// evicting the oldest entry if at capacity.
    pub fn record(&self, event: AuditEvent) {
        match &event {
            AuditEvent::AuthSuccess { user } => {
                info!(target: "snail::audit", user = user.as_str(), "authentication succeeded");
            }
            AuditEvent::AuthFailure { user, ip } => {
                warn!(target: "snail::audit", user = user.as_str(), %ip, "authentication failed");
            }
            AuditEvent::Blocked { ip, reason } => {
                warn!(target: "snail::audit", %ip, reason = reason.as_str(), "connection blocked");
            }
            AuditEvent::RateLimited { ip } => {
                warn!(target: "snail::audit", %ip, "connection rate-limited");
            }
        }
        let mut ring = self.recent.lock().unwrap_or_else(PoisonError::into_inner);
        if ring.len() == self.capacity {
            ring.pop_front();
        }
        ring.push_back(event);
    }

    /// A snapshot of the retained events, oldest first.
    #[must_use]
    pub fn recent(&self) -> Vec<AuditEvent> {
        self.recent
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .iter()
            .cloned()
            .collect()
    }

    /// Number of events currently retained.
    #[must_use]
    pub fn len(&self) -> usize {
        self.recent
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .len()
    }

    /// Whether the recent ring is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.recent
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn ip(n: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, n))
    }

    #[test]
    fn records_events_in_order() {
        let log = AuditLog::new(&AuditConfig::default());
        log.record(AuditEvent::AuthSuccess {
            user: "alice".into(),
        });
        log.record(AuditEvent::RateLimited { ip: ip(1) });
        let recent = log.recent();
        assert_eq!(recent.len(), 2);
        assert_eq!(
            recent[0],
            AuditEvent::AuthSuccess {
                user: "alice".into()
            }
        );
        assert_eq!(recent[1], AuditEvent::RateLimited { ip: ip(1) });
    }

    #[test]
    fn ring_is_bounded_to_capacity() {
        let log = AuditLog::new(&AuditConfig { capacity: 2 });
        for n in 0..5 {
            log.record(AuditEvent::RateLimited { ip: ip(n) });
        }
        assert_eq!(log.len(), 2);
        // Oldest (ip 0..2) evicted; the two most recent remain.
        assert_eq!(log.recent()[0], AuditEvent::RateLimited { ip: ip(3) });
        assert_eq!(log.recent()[1], AuditEvent::RateLimited { ip: ip(4) });
    }
}
