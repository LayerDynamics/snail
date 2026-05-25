//! AEAD seal (encryption) half of the secret cipher.

use chacha20poly1305::aead::{Aead, OsRng};
use chacha20poly1305::{AeadCore, ChaCha20Poly1305, Key, KeyInit};

use crate::error::{Result, SecurityError};

/// Encrypt `plaintext` under `key`, returning `nonce || ciphertext`.
///
/// A fresh random 96-bit nonce is generated per call and prepended to the output,
/// so the same key+plaintext never yields the same bytes and nonces are never reused.
///
/// # Errors
/// [`SecurityError::Encrypt`] if the AEAD operation fails.
pub fn seal(key: &Key, plaintext: &[u8]) -> Result<Vec<u8>> {
    let cipher = ChaCha20Poly1305::new(key);
    let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);
    let ciphertext = cipher
        .encrypt(&nonce, plaintext)
        .map_err(|e| SecurityError::Encrypt(e.to_string()))?;
    let mut out = Vec::with_capacity(nonce.len() + ciphertext.len());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}
