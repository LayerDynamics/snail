//! The SMTP protocol: command parsing, server replies, and a server-side
//! session state machine. Pure and synchronous — the async socket loop that
//! drives it is wired at the composition root (m15). This is the RFC 5321
//! subset Snail speaks: HELO/EHLO, MAIL FROM, RCPT TO, DATA, RSET, NOOP, QUIT.

use crate::error::{MailError, Result};
use crate::snailmail::{Envelope, Mailbox};

/// A parsed SMTP command (client → server).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SmtpCommand {
    /// `HELO <domain>`
    Helo(String),
    /// `EHLO <domain>`
    Ehlo(String),
    /// `MAIL FROM:<reverse-path>` — `None` is the null sender `<>`.
    MailFrom(Option<Mailbox>),
    /// `RCPT TO:<forward-path>`
    RcptTo(Mailbox),
    /// `DATA`
    Data,
    /// `RSET`
    Rset,
    /// `NOOP`
    Noop,
    /// `QUIT`
    Quit,
}

impl SmtpCommand {
    /// Parse one SMTP command line (without trailing CRLF).
    ///
    /// # Errors
    /// [`MailError::Malformed`] on an unknown verb or a malformed path.
    pub fn parse(line: &str) -> Result<Self> {
        let line = line.trim_end_matches(['\r', '\n']);
        let (verb, rest) = match line.split_once(' ') {
            Some((v, r)) => (v, r.trim()),
            None => (line, ""),
        };
        match verb.to_ascii_uppercase().as_str() {
            "HELO" => non_empty(rest, "HELO").map(|d| Self::Helo(d.to_string())),
            "EHLO" => non_empty(rest, "EHLO").map(|d| Self::Ehlo(d.to_string())),
            "MAIL" => Ok(Self::MailFrom(parse_path_opt(rest, "FROM:")?)),
            "RCPT" => Ok(Self::RcptTo(parse_path_opt(rest, "TO:")?.ok_or_else(
                || MailError::Malformed("RCPT TO cannot be the null path".into()),
            )?)),
            "DATA" => Ok(Self::Data),
            "RSET" => Ok(Self::Rset),
            "NOOP" => Ok(Self::Noop),
            "QUIT" => Ok(Self::Quit),
            other => Err(MailError::Malformed(format!("unknown command `{other}`"))),
        }
    }
}

fn non_empty<'a>(s: &'a str, what: &str) -> Result<&'a str> {
    if s.is_empty() {
        Err(MailError::Malformed(format!("{what} requires an argument")))
    } else {
        Ok(s)
    }
}

/// Parse `FROM:<addr>` / `TO:<addr>`. `<>` (the null path) yields `None`.
fn parse_path_opt(rest: &str, prefix: &str) -> Result<Option<Mailbox>> {
    let after = rest
        .strip_prefix(prefix)
        .or_else(|| rest.strip_prefix(&prefix.to_ascii_lowercase()))
        .ok_or_else(|| MailError::Malformed(format!("expected `{prefix}<addr>`")))?
        .trim();
    let inner = after
        .strip_prefix('<')
        .and_then(|s| s.strip_suffix('>'))
        .ok_or_else(|| MailError::Malformed("path must be wrapped in <>".into()))?;
    if inner.is_empty() {
        return Ok(None); // null reverse-path
    }
    Ok(Some(Mailbox::parse(inner)?))
}

/// A server reply: a 3-digit code and message text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SmtpReply {
    /// The 3-digit reply code (e.g. 250).
    pub code: u16,
    /// Human-readable text.
    pub text: String,
}

impl SmtpReply {
    /// Build a reply.
    pub fn new(code: u16, text: impl Into<String>) -> Self {
        Self {
            code,
            text: text.into(),
        }
    }

    /// Format on the wire as `<code> <text>\r\n`.
    #[must_use]
    pub fn to_wire(&self) -> String {
        format!("{} {}\r\n", self.code, self.text)
    }

    /// Whether this is a positive (2xx/3xx) reply.
    #[must_use]
    pub fn is_positive(&self) -> bool {
        (200..400).contains(&self.code)
    }
}

/// The phase of a server-side SMTP session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Phase {
    /// Connected; awaiting HELO/EHLO.
    Greeting,
    /// Identified; awaiting MAIL FROM.
    Identified,
    /// Have a sender; awaiting RCPT TO.
    Sender,
    /// Have ≥1 recipient; awaiting more RCPT or DATA.
    Recipients,
    /// Receiving the DATA body (terminated by a lone `.`).
    Data,
    /// The session has ended (QUIT).
    Closed,
}

/// Default maximum recipients accepted per transaction. RFC 5321 §4.5.3.1.8 sets
/// a *floor* of 100 (a server must accept at least that many); this is the ceiling
/// above which further `RCPT TO` are refused with `452`, bounding both the
/// recipient `Vec` and the post-`DATA` per-recipient delivery fan-out.
pub const DEFAULT_MAX_RECIPIENTS: usize = 1000;

/// A server-side SMTP session: feed it commands, get replies; once a transaction
/// completes it yields the [`Envelope`] and the session collects the DATA body.
#[derive(Debug)]
pub struct SmtpSession {
    phase: Phase,
    helo: Option<String>,
    sender: Option<Mailbox>,
    recipients: Vec<Mailbox>,
    max_recipients: usize,
}

impl Default for SmtpSession {
    fn default() -> Self {
        Self {
            phase: Phase::Greeting,
            helo: None,
            sender: None,
            recipients: Vec::new(),
            max_recipients: DEFAULT_MAX_RECIPIENTS,
        }
    }
}

impl SmtpSession {
    /// A fresh session in the greeting phase, with the default recipient cap.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// A fresh session with an explicit maximum recipient count (RFC 5321 requires
    /// at least 100; lower values are for tests).
    #[must_use]
    pub fn with_max_recipients(max_recipients: usize) -> Self {
        Self {
            max_recipients,
            ..Self::default()
        }
    }

    /// The current phase.
    #[must_use]
    pub fn phase(&self) -> Phase {
        self.phase
    }

    /// Handle a command, advancing state and returning the reply to send. When
    /// `DATA` is accepted the phase becomes [`Phase::Data`]; the caller then
    /// reads body lines and calls [`Self::take_envelope`] for the result.
    pub fn handle(&mut self, command: SmtpCommand) -> SmtpReply {
        match (self.phase, command) {
            (_, SmtpCommand::Quit) => {
                self.phase = Phase::Closed;
                SmtpReply::new(221, "Bye")
            }
            (_, SmtpCommand::Noop) => SmtpReply::new(250, "OK"),
            (_, SmtpCommand::Rset) => {
                self.sender = None;
                self.recipients.clear();
                if self.helo.is_some() {
                    self.phase = Phase::Identified;
                }
                SmtpReply::new(250, "OK")
            }
            (_, SmtpCommand::Helo(domain) | SmtpCommand::Ehlo(domain)) => {
                self.helo = Some(domain.clone());
                self.sender = None;
                self.recipients.clear();
                self.phase = Phase::Identified;
                SmtpReply::new(250, format!("Hello {domain}"))
            }
            (Phase::Identified, SmtpCommand::MailFrom(sender)) => {
                self.sender = sender;
                self.phase = Phase::Sender;
                SmtpReply::new(250, "OK")
            }
            (Phase::Sender | Phase::Recipients, SmtpCommand::RcptTo(rcpt)) => {
                if self.recipients.len() >= self.max_recipients {
                    // Refuse further recipients (RFC 5321 §4.5.3.1.10) — the
                    // already-accepted ones still form a valid transaction.
                    SmtpReply::new(452, "4.5.3 Too many recipients")
                } else {
                    self.recipients.push(rcpt);
                    self.phase = Phase::Recipients;
                    SmtpReply::new(250, "OK")
                }
            }
            (Phase::Recipients, SmtpCommand::Data) => {
                self.phase = Phase::Data;
                SmtpReply::new(354, "Start mail input; end with <CRLF>.<CRLF>")
            }
            (_, SmtpCommand::MailFrom(_)) => SmtpReply::new(503, "Bad sequence: need EHLO first"),
            (_, SmtpCommand::RcptTo(_)) => {
                SmtpReply::new(503, "Bad sequence: need MAIL FROM first")
            }
            (_, SmtpCommand::Data) => SmtpReply::new(503, "Bad sequence: need RCPT TO first"),
        }
    }

    /// After DATA, take the completed [`Envelope`] (sender + recipients) and
    /// reset the transaction back to the identified phase for reuse.
    ///
    /// Returns `None` if no recipients were accepted.
    pub fn take_envelope(&mut self) -> Option<Envelope> {
        if self.recipients.is_empty() {
            return None;
        }
        let envelope = Envelope::new(self.sender.take(), std::mem::take(&mut self.recipients));
        self.phase = Phase::Identified;
        Some(envelope)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_core_commands() {
        assert_eq!(
            SmtpCommand::parse("EHLO mail.example.com").unwrap(),
            SmtpCommand::Ehlo("mail.example.com".into())
        );
        assert_eq!(
            SmtpCommand::parse("MAIL FROM:<alice@example.com>").unwrap(),
            SmtpCommand::MailFrom(Some(Mailbox::parse("alice@example.com").unwrap()))
        );
        assert_eq!(
            SmtpCommand::parse("MAIL FROM:<>").unwrap(),
            SmtpCommand::MailFrom(None)
        );
        assert_eq!(SmtpCommand::parse("data").unwrap(), SmtpCommand::Data);
        assert!(SmtpCommand::parse("WIDGET now").is_err());
        assert!(SmtpCommand::parse("RCPT TO:<>").is_err()); // null forward-path invalid
    }

    #[test]
    fn full_transaction_flow_yields_envelope() {
        let mut s = SmtpSession::new();
        assert_eq!(s.handle(SmtpCommand::parse("EHLO x").unwrap()).code, 250);
        assert_eq!(
            s.handle(SmtpCommand::parse("MAIL FROM:<a@x.com>").unwrap())
                .code,
            250
        );
        assert_eq!(
            s.handle(SmtpCommand::parse("RCPT TO:<b@y.com>").unwrap())
                .code,
            250
        );
        let data_reply = s.handle(SmtpCommand::Data);
        assert_eq!(data_reply.code, 354);
        assert_eq!(s.phase(), Phase::Data);
        let env = s.take_envelope().unwrap();
        assert_eq!(env.recipients.len(), 1);
        assert_eq!(env.sender.unwrap().to_string(), "a@x.com");
    }

    #[test]
    fn recipients_past_the_cap_are_refused() {
        // Tight cap of 2: the first two RCPT are accepted, the third is refused
        // with 452, and the transaction still delivers to the accepted two.
        let mut s = SmtpSession::with_max_recipients(2);
        s.handle(SmtpCommand::parse("EHLO x").unwrap());
        s.handle(SmtpCommand::parse("MAIL FROM:<a@x.com>").unwrap());
        assert_eq!(
            s.handle(SmtpCommand::parse("RCPT TO:<b@y.com>").unwrap())
                .code,
            250
        );
        assert_eq!(
            s.handle(SmtpCommand::parse("RCPT TO:<c@y.com>").unwrap())
                .code,
            250
        );
        assert_eq!(
            s.handle(SmtpCommand::parse("RCPT TO:<d@y.com>").unwrap())
                .code,
            452,
            "a recipient past the cap must be refused"
        );
        assert_eq!(s.handle(SmtpCommand::Data).code, 354);
        let env = s.take_envelope().unwrap();
        assert_eq!(
            env.recipients.len(),
            2,
            "only the accepted recipients remain"
        );
    }

    #[test]
    fn rejects_out_of_order_commands() {
        let mut s = SmtpSession::new();
        // RCPT before MAIL, MAIL before EHLO → 503.
        assert_eq!(
            s.handle(SmtpCommand::parse("MAIL FROM:<a@x.com>").unwrap())
                .code,
            503
        );
        assert_eq!(s.handle(SmtpCommand::parse("EHLO x").unwrap()).code, 250);
        assert_eq!(s.handle(SmtpCommand::Data).code, 503); // no RCPT yet
    }

    #[test]
    fn reply_wire_format_and_positivity() {
        assert_eq!(SmtpReply::new(250, "OK").to_wire(), "250 OK\r\n");
        assert!(SmtpReply::new(354, "go").is_positive());
        assert!(!SmtpReply::new(503, "bad").is_positive());
    }
}
