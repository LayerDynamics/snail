//! DKIM signature verification (RFC 6376 + RFC 8463 Ed25519).
//!
//! - [`canonicalize`] implements the `simple`/`relaxed` header & body algorithms.
//! - [`signature`] parses a `DKIM-Signature` header field into its tags.
//! - [`verify`] orchestrates verification: locate the signature(s), fetch the
//!   public key via DNS, check the body hash, and verify the signature with RSA
//!   (RFC 6376) or Ed25519 (RFC 8463).
//!
//! Verification runs on the verbatim message bytes (preserved end-to-end by the
//! mail engine), so canonicalization sees exactly what the signer signed.

pub mod canonicalize;
pub mod signature;
pub mod verify;

pub use signature::{Algorithm, DkimSignature};
pub use verify::{DkimOutcome, DkimResult, verify};
