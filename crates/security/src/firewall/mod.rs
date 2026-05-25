//! Connection policy: governor rate limiting, IP allow/block lists, per-IP
//! connection tracking, a bounded decision trace, and a runtime pause switch.

pub mod allow;
pub mod block;
pub mod config;
// The scaffold names this file `firewall.rs` inside the `firewall/` module; that
// is intentional structure, so silence clippy's module-inception style lint here.
#[allow(clippy::module_inception)]
pub mod firewall;
pub mod manager;
pub mod pause;
pub mod trace;
pub mod track;

pub use allow::AllowList;
pub use block::BlockList;
pub use config::FirewallConfig;
pub use firewall::{Decision, DenyReason, Firewall};
pub use manager::FirewallManager;
pub use pause::PauseSwitch;
pub use trace::DecisionTrace;
pub use track::ConnectionTracker;
