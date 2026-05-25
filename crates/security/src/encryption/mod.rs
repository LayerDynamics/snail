//! Cryptographic primitives: Argon2id password hashing and ChaCha20-Poly1305
//! secret encryption.

pub mod algos;
pub mod decrypt;
pub mod encrypt;
pub mod hash;
pub mod manager;
pub mod salt;

pub use hash::PasswordHasher;
pub use manager::SecretCipher;
