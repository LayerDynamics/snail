//! SASL mechanisms (PLAIN and LOGIN). The file keeps the scaffold spelling
//! `sals`; "SASL" is the protocol. Decoded credentials are verified elsewhere
//! (the [`crate::auth::Authenticator`]).

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;

use crate::error::{IdentityError, Result};

/// SASL mechanisms Snail supports over an (already TLS-protected) channel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SaslMechanism {
    /// `PLAIN` — a single base64 `authzid\0authcid\0passwd` response.
    Plain,
    /// `LOGIN` — two base64 steps (username, then password).
    Login,
}

impl SaslMechanism {
    /// Parse a mechanism name (case-insensitive).
    #[must_use]
    pub fn parse(name: &str) -> Option<Self> {
        match name.trim().to_ascii_uppercase().as_str() {
            "PLAIN" => Some(Self::Plain),
            "LOGIN" => Some(Self::Login),
            _ => None,
        }
    }
}

/// Username + password decoded from a SASL exchange.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SaslCredentials {
    /// The authentication identity (authcid).
    pub username: String,
    /// The presented password.
    pub password: String,
}

/// Decode a SASL `PLAIN` response: base64 of `[authzid]\0authcid\0passwd`.
///
/// # Errors
/// [`IdentityError::Sasl`] if the base64 or the `\0`-separated structure is invalid.
pub fn decode_plain(response_b64: &str) -> Result<SaslCredentials> {
    let raw = BASE64
        .decode(response_b64.trim())
        .map_err(|e| IdentityError::Sasl(format!("base64: {e}")))?;
    let parts: Vec<&[u8]> = raw.split(|&b| b == 0).collect();
    if parts.len() != 3 {
        return Err(IdentityError::Sasl(
            "PLAIN must be authzid\\0authcid\\0passwd".into(),
        ));
    }
    let username = field_to_string(parts[1], "authcid")?;
    let password = field_to_string(parts[2], "passwd")?;
    if username.is_empty() {
        return Err(IdentityError::Sasl("empty authcid".into()));
    }
    Ok(SaslCredentials { username, password })
}

/// Decode a single base64 `LOGIN` field (the username or the password step).
///
/// # Errors
/// [`IdentityError::Sasl`] if the base64 or UTF-8 is invalid.
pub fn decode_login_field(field_b64: &str) -> Result<String> {
    let raw = BASE64
        .decode(field_b64.trim())
        .map_err(|e| IdentityError::Sasl(format!("base64: {e}")))?;
    String::from_utf8(raw).map_err(|e| IdentityError::Sasl(format!("utf-8: {e}")))
}

fn field_to_string(bytes: &[u8], what: &str) -> Result<String> {
    std::str::from_utf8(bytes)
        .map(ToString::to_string)
        .map_err(|e| IdentityError::Sasl(format!("{what} not utf-8: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn b64(s: &[u8]) -> String {
        BASE64.encode(s)
    }

    #[test]
    fn parses_mechanism_names() {
        assert_eq!(SaslMechanism::parse("plain"), Some(SaslMechanism::Plain));
        assert_eq!(SaslMechanism::parse("LOGIN"), Some(SaslMechanism::Login));
        assert_eq!(SaslMechanism::parse("scram-sha-256"), None);
    }

    #[test]
    fn decodes_plain_authcid_and_passwd() {
        let resp = b64(b"\0alice\0s3cret");
        let creds = decode_plain(&resp).unwrap();
        assert_eq!(creds.username, "alice");
        assert_eq!(creds.password, "s3cret");
    }

    #[test]
    fn plain_with_authzid_still_uses_authcid() {
        let resp = b64(b"admin\0alice\0s3cret");
        let creds = decode_plain(&resp).unwrap();
        assert_eq!(creds.username, "alice");
    }

    #[test]
    fn rejects_malformed_plain() {
        assert!(decode_plain(&b64(b"alice\0nopass")).is_err()); // only 2 parts
        assert!(decode_plain("not base64!!!").is_err());
        assert!(decode_plain(&b64(b"\0\0pw")).is_err()); // empty authcid
    }

    #[test]
    fn decodes_login_field() {
        assert_eq!(decode_login_field(&b64(b"alice")).unwrap(), "alice");
    }
}
