//! XOAUTH2 SASL parsing and bearer-token validation.

use std::collections::HashMap;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;

use crate::error::{IdentityError, Result};

/// A parsed XOAUTH2 initial client response.
///
/// The `claimed_username` is **client-supplied and unverified** — it is whatever
/// the client put in the `user=` field, not an authenticated identity. Bind it to
/// the token via [`XOAuth2::authenticate`] (or the [`authenticate_xoauth2`]
/// one-shot) before trusting any identity; never authenticate as
/// `claimed_username` off a bare token-validity check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct XOAuth2 {
    /// The username the client **claims** — unverified until bound to the token.
    pub claimed_username: String,
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

    // Reject empty fields too, so a parseable-but-empty `user=`/token can never
    // slip past the identity binding in `authenticate` (e.g. matching a validator
    // that returned an empty username).
    Ok(XOAuth2 {
        claimed_username: username
            .filter(|u| !u.is_empty())
            .ok_or_else(|| IdentityError::OAuth("missing or empty user field".into()))?,
        bearer_token: bearer_token
            .filter(|t| !t.is_empty())
            .ok_or_else(|| IdentityError::OAuth("missing or empty Bearer token".into()))?,
    })
}

impl XOAuth2 {
    /// Authenticate this response against `validator`, returning the
    /// **token-authenticated** username (the validator's canonical form, never
    /// the client-claimed string).
    ///
    /// This is the sound way to consume an XOAUTH2 response: it binds the
    /// client-claimed [`claimed_username`](Self::claimed_username) to the identity
    /// the bearer token actually authenticates. A token that is invalid — or that
    /// authenticates a *different* user than the client claimed — fails. Without
    /// this binding, any valid token could authenticate as an arbitrary user.
    ///
    /// The comparison is case-insensitive (email-style usernames). All failures
    /// collapse to [`IdentityError::AuthFailed`], so a caller cannot distinguish
    /// an invalid token from a username mismatch.
    ///
    /// # Errors
    /// [`IdentityError::AuthFailed`] if the token is invalid or its authenticated
    /// username does not match the claimed one.
    pub fn authenticate(&self, validator: &dyn TokenValidator) -> Result<String> {
        match validator.validate(&self.bearer_token) {
            Some(authenticated) if authenticated.eq_ignore_ascii_case(&self.claimed_username) => {
                Ok(authenticated)
            }
            _ => Err(IdentityError::AuthFailed),
        }
    }
}

/// Parse and authenticate an XOAUTH2 SASL response in one step, returning the
/// token-authenticated username.
///
/// This is **the** entry point for wiring XOAUTH2 into a protocol session: it
/// never exposes the unverified claimed username, so there is no opportunity to
/// trust it. Do not reconstruct the flow from [`parse_xoauth2`] plus a bare
/// [`TokenValidator::validate`] call — that path invites authenticating as the
/// client-claimed identity.
///
/// # Errors
/// [`IdentityError::OAuth`] if the response is malformed;
/// [`IdentityError::AuthFailed`] if the token is invalid or does not authenticate
/// the claimed user.
pub fn authenticate_xoauth2(response_b64: &str, validator: &dyn TokenValidator) -> Result<String> {
    parse_xoauth2(response_b64)?.authenticate(validator)
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
        assert_eq!(parsed.claimed_username, "alice@example.com");
        assert_eq!(parsed.bearer_token, "tok123");
    }

    #[test]
    fn rejects_missing_token() {
        let resp = BASE64.encode("user=alice\x01\x01");
        assert!(parse_xoauth2(&resp).is_err());
    }

    #[test]
    fn rejects_empty_user_or_token() {
        assert!(parse_xoauth2(&BASE64.encode("user=\x01auth=Bearer tok\x01\x01")).is_err());
        assert!(parse_xoauth2(&BASE64.encode("user=alice\x01auth=Bearer \x01\x01")).is_err());
    }

    #[test]
    fn static_validator_maps_token_to_user() {
        let v = StaticTokenValidator::new().with_token("tok123", "alice");
        assert_eq!(v.validate("tok123").as_deref(), Some("alice"));
        assert_eq!(v.validate("bogus"), None);
    }

    #[test]
    fn valid_token_authenticates_as_its_own_user() {
        let v = StaticTokenValidator::new().with_token("tok123", "alice@example.com");
        let id = parse_xoauth2(&xoauth2("alice@example.com", "tok123"))
            .unwrap()
            .authenticate(&v)
            .unwrap();
        assert_eq!(id, "alice@example.com");
    }

    #[test]
    fn binding_is_case_insensitive() {
        let v = StaticTokenValidator::new().with_token("tok123", "alice@example.com");
        let id = parse_xoauth2(&xoauth2("Alice@Example.COM", "tok123"))
            .unwrap()
            .authenticate(&v)
            .unwrap();
        // The authoritative (validator) form is returned, not the claimed casing.
        assert_eq!(id, "alice@example.com");
    }

    #[test]
    fn valid_token_for_different_user_does_not_authenticate_as_claimed() {
        // The attack: a token that genuinely authenticates `alice` is presented
        // with a claimed user of `victim`. Binding must refuse — a valid token
        // can only ever authenticate as its own subject.
        let v = StaticTokenValidator::new().with_token("alice-token", "alice@example.com");
        let err = parse_xoauth2(&xoauth2("victim@example.com", "alice-token"))
            .unwrap()
            .authenticate(&v)
            .unwrap_err();
        assert!(matches!(err, IdentityError::AuthFailed));
    }

    #[test]
    fn invalid_token_fails_to_authenticate() {
        let v = StaticTokenValidator::new().with_token("tok123", "alice@example.com");
        let err = parse_xoauth2(&xoauth2("alice@example.com", "bogus"))
            .unwrap()
            .authenticate(&v)
            .unwrap_err();
        assert!(matches!(err, IdentityError::AuthFailed));
    }

    #[test]
    fn authenticate_xoauth2_binds_end_to_end() {
        let v = StaticTokenValidator::new().with_token("tok123", "alice@example.com");
        // Happy path: parse + bind in one call.
        assert_eq!(
            authenticate_xoauth2(&xoauth2("alice@example.com", "tok123"), &v).unwrap(),
            "alice@example.com"
        );
        // Spoofed claimed user is refused end-to-end.
        assert!(matches!(
            authenticate_xoauth2(&xoauth2("victim@example.com", "tok123"), &v).unwrap_err(),
            IdentityError::AuthFailed
        ));
    }
}
