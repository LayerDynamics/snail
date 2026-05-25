//! XOAUTH2 SASL parsing and bearer-token validation.

use std::collections::HashMap;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;

use crate::error::{IdentityError, Result};

/// A parsed XOAUTH2 initial client response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct XOAuth2 {
    /// The username the client claims.
    pub username: String,
    /// The bearer token to validate.
    pub bearer_token: String,
}

/// Parse an XOAUTH2 SASL response: base64 of
/// `user=<user>\x01auth=Bearer <token>\x01\x01`.
///
/// # Errors
/// [`IdentityError::OAuth`] if base64/UTF-8 is invalid or required fields are absent.
pub fn parse_xoauth2(response_b64: &str) -> Result<XOAuth2> {
    let raw = BASE64
        .decode(response_b64.trim())
        .map_err(|e| IdentityError::OAuth(format!("base64: {e}")))?;
    let text =
        std::str::from_utf8(&raw).map_err(|e| IdentityError::OAuth(format!("utf-8: {e}")))?;

    let mut username = None;
    let mut bearer_token = None;
    for field in text.split('\x01') {
        if let Some(user) = field.strip_prefix("user=") {
            username = Some(user.to_string());
        } else if let Some(token) = field.strip_prefix("auth=Bearer ") {
            bearer_token = Some(token.to_string());
        }
    }

    Ok(XOAuth2 {
        username: username.ok_or_else(|| IdentityError::OAuth("missing user field".into()))?,
        bearer_token: bearer_token
            .ok_or_else(|| IdentityError::OAuth("missing Bearer token".into()))?,
    })
}

/// Validates bearer tokens, mapping a valid token to the username it authenticates.
pub trait TokenValidator: Send + Sync {
    /// Return the username a token authenticates, or `None` if it is invalid.
    fn validate(&self, token: &str) -> Option<String>;
}

/// An in-memory token→username validator. The seam a real OIDC/JWKS validator
/// plugs into; full token signature/expiry validation is deferred.
#[derive(Debug, Default, Clone)]
pub struct StaticTokenValidator {
    tokens: HashMap<String, String>,
}

impl StaticTokenValidator {
    /// Create an empty validator.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a `token` as authenticating `username`.
    #[must_use]
    pub fn with_token(mut self, token: impl Into<String>, username: impl Into<String>) -> Self {
        self.tokens.insert(token.into(), username.into());
        self
    }
}

impl TokenValidator for StaticTokenValidator {
    fn validate(&self, token: &str) -> Option<String> {
        self.tokens.get(token).cloned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn xoauth2(user: &str, token: &str) -> String {
        BASE64.encode(format!("user={user}\x01auth=Bearer {token}\x01\x01"))
    }

    #[test]
    fn parses_user_and_bearer_token() {
        let parsed = parse_xoauth2(&xoauth2("alice@example.com", "tok123")).unwrap();
        assert_eq!(parsed.username, "alice@example.com");
        assert_eq!(parsed.bearer_token, "tok123");
    }

    #[test]
    fn rejects_missing_token() {
        let resp = BASE64.encode("user=alice\x01\x01");
        assert!(parse_xoauth2(&resp).is_err());
    }

    #[test]
    fn static_validator_maps_token_to_user() {
        let v = StaticTokenValidator::new().with_token("tok123", "alice");
        assert_eq!(v.validate("tok123").as_deref(), Some("alice"));
        assert_eq!(v.validate("bogus"), None);
    }
}
