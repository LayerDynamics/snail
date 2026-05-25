//! Shared primitives for the Snail email server.
//!
//! `utilities` is the dependency-free foundation that every other Snail crate
//! builds on: a typed error type (`error::UtilError`) and process configuration
//! (`config::Config`).

pub mod config;
pub mod error;

// pub use config::Config;             // enabled in m3
pub use error::{Result, UtilError};
