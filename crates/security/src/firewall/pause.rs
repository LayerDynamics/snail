//! Thread-safe firewall enforcement toggle.

use std::sync::atomic::{AtomicBool, Ordering};

/// A switch that enables/disables firewall enforcement at runtime. When paused,
/// the firewall permits everything (useful for maintenance / incident response).
#[derive(Debug)]
pub struct PauseSwitch {
    paused: AtomicBool,
}

impl Default for PauseSwitch {
    fn default() -> Self {
        Self {
            paused: AtomicBool::new(false),
        }
    }
}

impl PauseSwitch {
    /// Create a switch in the enforcing (not paused) state.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Pause enforcement (everything will be allowed).
    pub fn pause(&self) {
        self.paused.store(true, Ordering::SeqCst);
    }

    /// Resume enforcement.
    pub fn resume(&self) {
        self.paused.store(false, Ordering::SeqCst);
    }

    /// Whether enforcement is currently paused.
    #[must_use]
    pub fn is_paused(&self) -> bool {
        self.paused.load(Ordering::SeqCst)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn toggles_between_enforcing_and_paused() {
        let s = PauseSwitch::new();
        assert!(!s.is_paused());
        s.pause();
        assert!(s.is_paused());
        s.resume();
        assert!(!s.is_paused());
    }
}
