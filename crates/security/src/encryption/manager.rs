//! `SecretCipher`: owns a ChaCha20-Poly1305 key and composes the seal/open halves.

use chacha20poly1305::aead::OsRng;
use chacha20poly1305::{ChaCha20Poly1305, Key, KeyInit};

use crate::encryption::{decrypt, encrypt};
use crate::error::Result;

/// Symmetric authenticated cipher for encrypting stored secrets at rest.
pub struct SecretCipher {
    key: Key,
}

impl SecretCipher {
    /// Build a cipher with a fresh random 256-bit key from the OS CSPRNG.
    #[must_use]
    pub fn generate() -> Self {
        Self {
            key: ChaCha20Poly1305::generate_key(&mut OsRng),
        }
    }

    /// Build a cipher from an existing 32-byte key.
    #[must_use]
    pub fn from_key(key: [u8; 32]) -> Self {
        Self { key: key.into() }
    }

    /// Encrypt `plaintext`, returning `nonce || ciphertext`.
    ///
    /// # Errors
    /// [`crate::error::SecurityError::Encrypt`] if the AEAD operation fails.
    pub fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        encrypt::seal(&self.key, plaintext)
    }

    /// Decrypt a blob produced by [`Self::encrypt`].
    ///
    /// # Errors
    /// [`crate::error::SecurityError::Decrypt`] if authentication fails.
    pub fn decrypt(&self, sealed: &[u8]) -> Result<Vec<u8>> {
        decrypt::open(&self.key, sealed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypt_then_decrypt_roundtrips() {
        let c = SecretCipher::generate();
        let sealed = c.encrypt(b"oauth-refresh-token").unwrap();
        assert_eq!(c.decrypt(&sealed).unwrap(), b"oauth-refresh-token");
    }

    #[test]
    fn tampered_ciphertext_fails() {
        let c = SecretCipher::generate();
        let mut sealed = c.encrypt(b"secret").unwrap();
        *sealed.last_mut().unwrap() ^= 0xFF;
        assert!(c.decrypt(&sealed).is_err());
    }

    #[test]
    fn wrong_key_fails() {
        let sealed = SecretCipher::generate().encrypt(b"secret").unwrap();
        assert!(SecretCipher::generate().decrypt(&sealed).is_err());
    }

    #[test]
    fn from_key_is_deterministic_for_decryption() {
        let key = [7u8; 32];
        let sealed = SecretCipher::from_key(key).encrypt(b"hello").unwrap();
        assert_eq!(
            SecretCipher::from_key(key).decrypt(&sealed).unwrap(),
            b"hello"
        );
    }
}
