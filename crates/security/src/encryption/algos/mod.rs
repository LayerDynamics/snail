//! Algorithm registry: the configured password-hashing and AEAD primitives the
//! rest of `encryption` is built on. Selecting an algorithm here yields its real
//! configured parameters — not a no-op enum.

use argon2::{Algorithm, Argon2, Params, Version};

/// Password-hashing algorithms supported by the security layer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PasswordAlgo {
    /// Argon2id — memory-hard, OWASP-recommended; the project default.
    Argon2id,
}

impl PasswordAlgo {
    /// The configured [`Argon2`] hasher for this algorithm.
    #[must_use]
    pub fn hasher(self) -> Argon2<'static> {
        match self {
            Self::Argon2id => Argon2::new(Algorithm::Argon2id, Version::V0x13, Params::default()),
        }
    }
}

/// Authenticated-encryption algorithms supported for secret storage.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AeadAlgo {
    /// ChaCha20-Poly1305 — the project default.
    ChaCha20Poly1305,
}

impl AeadAlgo {
    /// Nonce length, in bytes, for this AEAD (consumed by the decrypt path).
    #[must_use]
    pub const fn nonce_len(self) -> usize {
        match self {
            Self::ChaCha20Poly1305 => 12,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chacha_nonce_len_is_96_bits() {
        assert_eq!(AeadAlgo::ChaCha20Poly1305.nonce_len(), 12);
    }
}
