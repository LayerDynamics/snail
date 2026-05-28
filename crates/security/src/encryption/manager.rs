//! `SecretCipher`: owns a ChaCha20-Poly1305 key and composes the seal/open halves.

use chacha20poly1305::aead::OsRng;
use chacha20poly1305::{ChaCha20Poly1305, Key, KeyInit};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::encryption::{decrypt, encrypt};
use crate::error::Result;

/// Symmetric authenticated cipher for encrypting stored secrets at rest.
///
/// The 256-bit key is held as a raw `[u8; 32]` and **wiped from memory on drop**
/// ([`ZeroizeOnDrop`]): for a privacy-first server whose threat model includes
/// core dumps and swap, the long-lived key must not linger in freed heap. (The
/// transient `Key` rebuilt per AEAD call lives only for that call.)
#[derive(ZeroizeOnDrop)]
pub struct SecretCipher {
    key: [u8; 32],
}

impl SecretCipher {
    /// Build a cipher with a fresh random 256-bit key from the OS CSPRNG.
    #[must_use]
    pub fn generate() -> Self {
        let mut generated = ChaCha20Poly1305::generate_key(&mut OsRng);
        let mut key = [0u8; 32];
        key.copy_from_slice(generated.as_slice());
        // Wipe the transient `GenericArray` copy so only the (zeroize-on-drop)
        // persisted key remains.
        generated.as_mut_slice().zeroize();
        Self { key }
    }

    /// Build a cipher from an existing 32-byte key.
    #[must_use]
    pub fn from_key(key: [u8; 32]) -> Self {
        Self { key }
    }

    /// Encrypt `plaintext`, returning `nonce || ciphertext`.
    ///
    /// # Errors
    /// [`crate::error::SecurityError::Encrypt`] if the AEAD operation fails.
    pub fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        encrypt::seal(&Key::from(self.key), plaintext)
    }

    /// Decrypt a blob produced by [`Self::encrypt`]. The recovered plaintext is
    /// returned in a [`Zeroizing`] buffer so the decrypted secret is wiped when
    /// the caller drops it, rather than lingering in freed heap.
    ///
    /// # Errors
    /// [`crate::error::SecurityError::Decrypt`] if authentication fails.
    pub fn decrypt(&self, sealed: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        Ok(Zeroizing::new(decrypt::open(&Key::from(self.key), sealed)?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypt_then_decrypt_roundtrips() {
        let c = SecretCipher::generate();
        let sealed = c.encrypt(b"oauth-refresh-token").unwrap();
        assert_eq!(
            c.decrypt(&sealed).unwrap().as_slice(),
            b"oauth-refresh-token"
        );
    }

    #[test]
    fn cipher_is_zeroize_on_drop_and_decrypt_is_zeroizing() {
        // Compile-time guarantee: if the key's zeroize-on-drop is ever removed,
        // this fails to build. The decrypted plaintext is returned in a Zeroizing
        // buffer (also a compile-time check via the bound below).
        fn assert_zeroize_on_drop<T: zeroize::ZeroizeOnDrop>() {}
        assert_zeroize_on_drop::<SecretCipher>();
        let c = SecretCipher::generate();
        let sealed = c.encrypt(b"secret").unwrap();
        let plain: Zeroizing<Vec<u8>> = c.decrypt(&sealed).unwrap();
        assert_eq!(plain.as_slice(), b"secret");
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
            SecretCipher::from_key(key)
                .decrypt(&sealed)
                .unwrap()
                .as_slice(),
            b"hello"
        );
    }
}
