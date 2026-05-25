//! AEAD open (decryption) half of the secret cipher.

use chacha20poly1305::aead::Aead;
use chacha20poly1305::{ChaCha20Poly1305, Key, KeyInit, Nonce};

use crate::encryption::algos::AeadAlgo;
use crate::error::{Result, SecurityError};

/// Decrypt a `nonce || ciphertext` blob produced by [`super::encrypt::seal`].
///
/// # Errors
/// [`SecurityError::Decrypt`] if the blob is shorter than the nonce or the
/// authentication tag does not verify (tampering or wrong key).
pub fn open(key: &Key, sealed: &[u8]) -> Result<Vec<u8>> {
    let nonce_len = AeadAlgo::ChaCha20Poly1305.nonce_len();
    if sealed.len() < nonce_len {
        return Err(SecurityError::Decrypt(
            "sealed blob shorter than nonce".into(),
        ));
    }
    let (nonce_bytes, ciphertext) = sealed.split_at(nonce_len);
    let nonce = Nonce::from_slice(nonce_bytes);
    let cipher = ChaCha20Poly1305::new(key);
    cipher
        .decrypt(nonce, ciphertext)
        .map_err(|e| SecurityError::Decrypt(e.to_string()))
}
