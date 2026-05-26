//! Server configuration.

use utilities::Config;

/// Configuration for the composed Snail server.
#[derive(Debug, Clone)]
pub struct ServerConfig {
    /// Process configuration (data dir, log level) from `utilities`.
    pub base: Config,
    /// Domains this server hosts (mail to these is delivered locally).
    pub local_domains: Vec<String>,
}

impl ServerConfig {
    /// Build a config for the given local domains, using the default base config.
    #[must_use]
    pub fn new(local_domains: impl IntoIterator<Item = String>) -> Self {
        Self {
            base: Config::default(),
            local_domains: local_domains.into_iter().collect(),
        }
    }
}
