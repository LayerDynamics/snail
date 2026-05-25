//! Secure salt generation for password hashing — the canonical salt source.

use argon2::password_hash::SaltString;
use argon2::password_hash::rand_core::OsRng;

/// Generate a fresh random PHC salt from the OS CSPRNG.
#[must_use]
pub fn generate() -> SaltString {
    SaltString::generate(&mut OsRng)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_salts_are_unique() {
        assert_ne!(generate().as_str(), generate().as_str());
    }
}
