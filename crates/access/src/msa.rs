//! Mail Submission Agent (RFC 6409): authenticated SMTP submission. Wraps the
//! mail-engine SMTP session and gates the mail transaction behind a SASL `AUTH`
//! step verified through `identity`.

use identity::decode_plain;
use mail::{SmtpCommand, SmtpReply, SmtpSession};

use crate::SessionAuth;

/// An authenticated submission session: SASL `AUTH PLAIN` then a normal SMTP
/// transaction (which is refused until authentication succeeds).
pub struct MsaSession<'a, A: SessionAuth> {
    auth: &'a A,
    smtp: SmtpSession,
    user: Option<String>,
}

impl<'a, A: SessionAuth> MsaSession<'a, A> {
    /// Start an unauthenticated submission session.
    pub fn new(auth: &'a A) -> Self {
        Self {
            auth,
            smtp: SmtpSession::new(),
            user: None,
        }
    }

    /// Whether the session has authenticated.
    #[must_use]
    pub fn is_authenticated(&self) -> bool {
        self.user.is_some()
    }

    /// The authenticated username, if any.
    #[must_use]
    pub fn user(&self) -> Option<&str> {
        self.user.as_deref()
    }

    /// Handle a SASL `AUTH PLAIN <base64>` initial response.
    pub fn authenticate_plain(&mut self, response_b64: &str) -> SmtpReply {
        match decode_plain(response_b64) {
            Ok(creds) if self.auth.check(&creds.username, &creds.password) => {
                self.user = Some(creds.username);
                SmtpReply::new(235, "Authentication successful")
            }
            Ok(_) => SmtpReply::new(535, "Authentication credentials invalid"),
            Err(_) => SmtpReply::new(501, "Malformed AUTH response"),
        }
    }

    /// Handle an SMTP command. The mail transaction (`MAIL`/`RCPT`/`DATA`) is
    /// refused with `530` until the session has authenticated (submission policy).
    pub fn handle(&mut self, command: SmtpCommand) -> SmtpReply {
        let needs_auth = matches!(
            command,
            SmtpCommand::MailFrom(_) | SmtpCommand::RcptTo(_) | SmtpCommand::Data
        );
        if needs_auth && !self.is_authenticated() {
            return SmtpReply::new(530, "Authentication required");
        }
        self.smtp.handle(command)
    }

    /// The underlying SMTP session (e.g. to take the completed envelope).
    pub fn smtp_mut(&mut self) -> &mut SmtpSession {
        &mut self.smtp
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine as _;
    use base64::engine::general_purpose::STANDARD as BASE64;

    struct StubAuth;
    impl SessionAuth for StubAuth {
        fn check(&self, username: &str, password: &str) -> bool {
            username == "alice@example.com" && password == "pw"
        }
    }

    fn auth_plain(user: &str, pass: &str) -> String {
        BASE64.encode(format!("\0{user}\0{pass}"))
    }

    #[test]
    fn valid_auth_then_transaction_allowed() {
        let auth = StubAuth;
        let mut s = MsaSession::new(&auth);
        assert_eq!(
            s.authenticate_plain(&auth_plain("alice@example.com", "pw"))
                .code,
            235
        );
        assert!(s.is_authenticated());
        s.handle(SmtpCommand::parse("EHLO me").unwrap());
        assert_eq!(
            s.handle(SmtpCommand::parse("MAIL FROM:<alice@example.com>").unwrap())
                .code,
            250
        );
    }

    #[test]
    fn invalid_auth_is_rejected() {
        let auth = StubAuth;
        let mut s = MsaSession::new(&auth);
        assert_eq!(
            s.authenticate_plain(&auth_plain("alice@example.com", "wrong"))
                .code,
            535
        );
        assert!(!s.is_authenticated());
    }

    #[test]
    fn transaction_refused_before_auth() {
        let auth = StubAuth;
        let mut s = MsaSession::new(&auth);
        s.handle(SmtpCommand::parse("EHLO me").unwrap());
        assert_eq!(
            s.handle(SmtpCommand::parse("MAIL FROM:<alice@example.com>").unwrap())
                .code,
            530
        );
    }
}
