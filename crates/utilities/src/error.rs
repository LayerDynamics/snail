//! Error types shared across Snail.

use thiserror::Error;

/// Errors produced by the shared utilities layer.
#[derive(Debug, Error)]
pub enum UtilError {
    /// A configuration value was missing or invalid.
    #[error("invalid configuration: {0}")]
    Config(String),

    /// An underlying I/O operation failed.
    #[error("i/o error: {0}")]
    Io(#[from] std::io::Error),

    /// An environment variable held a value that could not be used.
    #[error("environment variable `{name}` is invalid: {reason}")]
    Env {
        /// The offending variable name.
        name: String,
        /// Why it was rejected.
        reason: String,
    },
}

/// Convenience alias for results that fail with [`UtilError`].
pub type Result<T> = std::result::Result<T, UtilError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_error_displays_message() {
        let e = UtilError::Config("missing data_dir".into());
        assert_eq!(e.to_string(), "invalid configuration: missing data_dir");
    }

    #[test]
    fn io_error_converts_via_from() {
        let io = std::io::Error::new(std::io::ErrorKind::NotFound, "nope");
        let e: UtilError = io.into();
        assert!(matches!(e, UtilError::Io(_)));
        assert!(e.to_string().starts_with("i/o error:"));
    }

    #[test]
    fn env_error_formats_named_fields() {
        let e = UtilError::Env {
            name: "SNAIL_LOG".into(),
            reason: "not a level".into(),
        };
        assert_eq!(
            e.to_string(),
            "environment variable `SNAIL_LOG` is invalid: not a level"
        );
    }
}
