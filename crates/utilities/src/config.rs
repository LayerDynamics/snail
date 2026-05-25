//! Process-wide configuration shared across Snail services.

use std::path::PathBuf;

use crate::error::{Result, UtilError};

/// Configuration shared across Snail services.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    /// Directory under which mail and state are stored.
    pub data_dir: PathBuf,
    /// `tracing` env-filter directive (e.g. `info`, `snail=debug`).
    pub log_level: String,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            data_dir: PathBuf::from("/var/lib/snail"),
            log_level: "info".to_string(),
        }
    }
}

impl Config {
    /// Build configuration from the process environment, falling back to [`Default`].
    ///
    /// Recognised variables: `SNAIL_DATA_DIR`, `SNAIL_LOG`.
    ///
    /// # Errors
    /// Returns [`UtilError::Env`] if a recognised variable is present but blank.
    pub fn from_env() -> Result<Self> {
        Self::from_source(|k| std::env::var(k).ok())
    }

    /// Build configuration from an arbitrary variable source. Pure and testable.
    ///
    /// # Errors
    /// Returns [`UtilError::Env`] if a recognised variable is present but blank.
    pub fn from_source(get: impl Fn(&str) -> Option<String>) -> Result<Self> {
        let mut cfg = Self::default();

        if let Some(dir) = get("SNAIL_DATA_DIR") {
            if dir.trim().is_empty() {
                return Err(UtilError::Env {
                    name: "SNAIL_DATA_DIR".into(),
                    reason: "must not be empty".into(),
                });
            }
            cfg.data_dir = PathBuf::from(dir);
        }

        if let Some(level) = get("SNAIL_LOG") {
            if level.trim().is_empty() {
                return Err(UtilError::Env {
                    name: "SNAIL_LOG".into(),
                    reason: "must not be empty".into(),
                });
            }
            cfg.log_level = level;
        }

        Ok(cfg)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn default_has_sensible_values() {
        let c = Config::default();
        assert_eq!(c.data_dir, PathBuf::from("/var/lib/snail"));
        assert_eq!(c.log_level, "info");
    }

    #[test]
    fn from_source_overrides_set_vars() {
        let c = Config::from_source(|k| match k {
            "SNAIL_DATA_DIR" => Some("/data/snail".to_string()),
            "SNAIL_LOG" => Some("snail=debug".to_string()),
            _ => None,
        })
        .unwrap();
        assert_eq!(c.data_dir, PathBuf::from("/data/snail"));
        assert_eq!(c.log_level, "snail=debug");
    }

    #[test]
    fn from_source_rejects_empty_var() {
        let err = Config::from_source(|k| match k {
            "SNAIL_DATA_DIR" => Some("   ".to_string()),
            _ => None,
        })
        .unwrap_err();
        assert!(matches!(err, UtilError::Env { .. }));
    }
}
