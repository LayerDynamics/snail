//! Security audit logging: a structured `tracing` event per occurrence plus a
//! capacity-bounded in-memory ring of the most recent events for inspection.

use std::collections::VecDeque;
use std::net::IpAddr;
use std::sync::{Mutex, PoisonError};

use tracing::{error, info, warn};

use crate::audit::config::AuditConfig;
use crate::audit::sink::DurableAuditSink;

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
    /// Firewall enforcement was paused — every connection is now permitted,
    /// **including blocklisted IPs**. A high-impact administrative transition
    /// that must leave a trail (the pause itself is otherwise invisible).
    FirewallPaused,
    /// Firewall enforcement was resumed (normal policy is back in effect).
    FirewallResumed,
}

impl AuditEvent {
    /// A single-line, tab/newline-free encoding for the durable audit sink. There
    /// is no `serde` in the workspace, so this is hand-rolled; user/reason strings
    /// are sanitised of control characters so a record is always exactly one line
    /// and the sink's field framing is never broken.
    #[must_use]
    pub fn encode(&self) -> String {
        match self {
            AuditEvent::AuthSuccess { user } => {
                format!("auth_success user={}", sanitize(user))
            }
            AuditEvent::AuthFailure { user, ip } => {
                format!("auth_failure user={} ip={ip}", sanitize(user))
            }
            AuditEvent::Blocked { ip, reason } => {
                format!("blocked ip={ip} reason={}", sanitize(reason))
            }
            AuditEvent::RateLimited { ip } => format!("rate_limited ip={ip}"),
            AuditEvent::FirewallPaused => "firewall_paused".to_string(),
            AuditEvent::FirewallResumed => "firewall_resumed".to_string(),
        }
    }
}

/// Replace record/field separators so an encoded event stays a single, framed
/// line in the durable sink.
fn sanitize(s: &str) -> String {
    s.replace(['\t', '\n', '\r'], " ")
}

/// Records [`AuditEvent`]s: emits a structured `tracing` event (so telemetry
/// captures it), retains a capacity-bounded ring of the most recent events for
/// inspection, and — when a durable sink is configured — appends each event to an
/// append-only, hash-chained file that survives restarts and resists tampering.
pub struct AuditLog {
    capacity: usize,
    recent: Mutex<VecDeque<AuditEvent>>,
    sink: Option<DurableAuditSink>,
}

impl AuditLog {
    /// Create an audit log from configuration. If `config.sink_path` is set, the
    /// durable sink is opened; a failure to open it is logged loudly and the log
    /// degrades to RAM-only rather than aborting startup.
    #[must_use]
    pub fn new(config: &AuditConfig) -> Self {
        let sink = config
            .sink_path
            .as_ref()
            .and_then(|path| match DurableAuditSink::open(path) {
                Ok(sink) => Some(sink),
                Err(error) => {
                    error!(
                        target: "snail::audit",
                        %error,
                        path = %path.display(),
                        "failed to open durable audit sink; security events will NOT be persisted"
                    );
                    None
                }
            });
        Self {
            capacity: config.capacity.max(1),
            recent: Mutex::new(VecDeque::new()),
            sink,
        }
    }

    /// Record an event: emit it via `tracing`, persist it to the durable sink (if
    /// configured), and append it to the recent ring, evicting the oldest entry if
    /// at capacity.
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
            AuditEvent::FirewallPaused => {
                warn!(target: "snail::audit", "firewall enforcement paused — all connections permitted, including blocklisted IPs");
            }
            AuditEvent::FirewallResumed => {
                info!(target: "snail::audit", "firewall enforcement resumed");
            }
        }
        // Persist to the durable, tamper-evident chain before the volatile ring; a
        // sink write failure is logged but never drops the event from `tracing`/RAM.
        if let Some(sink) = &self.sink
            && let Err(error) = sink.append(&event)
        {
            error!(target: "snail::audit", %error, "failed to persist audit event to durable sink");
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
        let log = AuditLog::new(&AuditConfig {
            capacity: 2,
            sink_path: None,
        });
        for n in 0..5 {
            log.record(AuditEvent::RateLimited { ip: ip(n) });
        }
        assert_eq!(log.len(), 2);
        // Oldest (ip 0..2) evicted; the two most recent remain.
        assert_eq!(log.recent()[0], AuditEvent::RateLimited { ip: ip(3) });
        assert_eq!(log.recent()[1], AuditEvent::RateLimited { ip: ip(4) });
    }

    #[test]
    fn configured_sink_persists_events_durably_beyond_the_ring() {
        use crate::audit::DurableAuditSink;
        use std::time::{SystemTime, UNIX_EPOCH};

        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "snail-auditlog-{nanos}-{:?}.log",
            std::thread::current().id()
        ));

        // A ring capacity of 1 would normally lose all but the last event — but the
        // durable sink keeps every one, the property the finding requires.
        let log = AuditLog::new(&AuditConfig {
            capacity: 1,
            sink_path: Some(path.clone()),
        });
        log.record(AuditEvent::FirewallPaused);
        log.record(AuditEvent::RateLimited { ip: ip(1) });
        log.record(AuditEvent::FirewallResumed);
        // The RAM ring (capacity 1) retains only the last event...
        assert_eq!(log.len(), 1);
        drop(log);

        // ...but all three survive on disk as one verifiable, tamper-evident chain.
        assert_eq!(
            DurableAuditSink::verify(&path).unwrap(),
            crate::audit::ChainStatus::Valid { records: 3 },
            "every event must persist despite a capacity-1 ring"
        );
        let _ = std::fs::remove_file(path);
    }
}
