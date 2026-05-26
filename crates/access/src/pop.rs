//! POP3 server session: USER/PASS authentication then STAT/LIST/RETR/DELE over
//! a mailbox in the `mail` store. Pure and synchronous — the socket loop is
//! wired at the composition root (m15). Message numbers are 1-based per RFC 1939.

use std::collections::HashSet;

use mail::{MailStore, StoredMessage};

use crate::SessionAuth;

/// A parsed POP3 command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PopCommand {
    /// `CAPA` — capability listing (RFC 2449).
    Capa,
    /// `STLS` — begin a TLS upgrade (RFC 2595).
    Stls,
    /// `USER <name>`
    User(String),
    /// `PASS <password>`
    Pass(String),
    /// `STAT`
    Stat,
    /// `LIST [msg]`
    List(Option<usize>),
    /// `RETR <msg>`
    Retr(usize),
    /// `DELE <msg>`
    Dele(usize),
    /// `RSET`
    Rset,
    /// `NOOP`
    Noop,
    /// `QUIT`
    Quit,
}

impl PopCommand {
    /// Parse a POP3 command line.
    ///
    /// # Errors
    /// `Err(message)` (suitable for an `-ERR` reply) on an unknown command or
    /// a malformed argument.
    pub fn parse(line: &str) -> std::result::Result<Self, String> {
        let line = line.trim_end_matches(['\r', '\n']);
        let (verb, arg) = match line.split_once(' ') {
            Some((v, a)) => (v, a.trim()),
            None => (line, ""),
        };
        let num = || {
            arg.parse::<usize>()
                .map_err(|_| format!("invalid message number `{arg}`"))
        };
        match verb.to_ascii_uppercase().as_str() {
            "CAPA" => Ok(Self::Capa),
            "STLS" => Ok(Self::Stls),
            "USER" if !arg.is_empty() => Ok(Self::User(arg.to_string())),
            "PASS" => Ok(Self::Pass(arg.to_string())),
            "STAT" => Ok(Self::Stat),
            "LIST" if arg.is_empty() => Ok(Self::List(None)),
            "LIST" => Ok(Self::List(Some(num()?))),
            "RETR" => Ok(Self::Retr(num()?)),
            "DELE" => Ok(Self::Dele(num()?)),
            "RSET" => Ok(Self::Rset),
            "NOOP" => Ok(Self::Noop),
            "QUIT" => Ok(Self::Quit),
            other => Err(format!("unknown command `{other}`")),
        }
    }
}

/// A POP3 reply: `+OK`/`-ERR` status, an optional one-line message, and optional
/// multi-line payload (e.g. a retrieved message or a listing).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PopReply {
    /// Whether this is a `+OK` (true) or `-ERR` (false) reply.
    pub ok: bool,
    /// The status-line message.
    pub message: String,
    /// Multi-line payload lines (RETR/LIST), if any.
    pub lines: Vec<String>,
}

impl PopReply {
    fn ok(message: impl Into<String>) -> Self {
        Self {
            ok: true,
            message: message.into(),
            lines: Vec::new(),
        }
    }
    fn err(message: impl Into<String>) -> Self {
        Self {
            ok: false,
            message: message.into(),
            lines: Vec::new(),
        }
    }
}

/// POP3 session phase.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PopState {
    /// Awaiting USER/PASS.
    Authorization,
    /// Authenticated; processing mailbox commands.
    Transaction,
    /// QUIT received.
    Closed,
}

/// A POP3 session over a mailbox in `store`, authenticating via `auth`.
pub struct Pop3Session<'a, A: SessionAuth, S: MailStore> {
    auth: &'a A,
    store: &'a S,
    state: PopState,
    pending_user: Option<String>,
    mailbox: Option<String>,
    messages: Vec<StoredMessage>,
    deleted: HashSet<u64>,
    /// The server offers `STLS` (a certificate is configured).
    tls_available: bool,
    /// The connection is already encrypted (an `STLS` upgrade completed).
    tls_active: bool,
}

impl<'a, A: SessionAuth, S: MailStore> Pop3Session<'a, A, S> {
    /// Start a session with no TLS offered (a plaintext-only listener — used when
    /// the server has no certificate configured).
    pub fn new(auth: &'a A, store: &'a S) -> Self {
        Self {
            auth,
            store,
            state: PopState::Authorization,
            pending_user: None,
            mailbox: None,
            messages: Vec::new(),
            deleted: HashSet::new(),
            tls_available: false,
            tls_active: false,
        }
    }

    /// Start a TLS-capable session. `active` is `true` when the connection is
    /// already encrypted (the session that resumes after an `STLS` upgrade);
    /// `false` for the initial plaintext phase that advertises and permits
    /// `STLS`. While TLS is available but not yet active the session refuses
    /// `USER`/`PASS`, so credentials are never accepted in cleartext.
    pub fn with_tls(auth: &'a A, store: &'a S, active: bool) -> Self {
        Self {
            auth,
            store,
            state: PopState::Authorization,
            pending_user: None,
            mailbox: None,
            messages: Vec::new(),
            deleted: HashSet::new(),
            tls_available: true,
            tls_active: active,
        }
    }

    /// The current phase.
    #[must_use]
    pub fn state(&self) -> PopState {
        self.state
    }

    /// Live (non-deleted) messages with their 1-based number.
    fn live(&self) -> impl Iterator<Item = (usize, &StoredMessage)> {
        self.messages
            .iter()
            .enumerate()
            .filter(|(_, m)| !self.deleted.contains(&m.id))
            .map(|(i, m)| (i + 1, m))
    }

    fn message_at(&self, number: usize) -> Option<&StoredMessage> {
        let m = self.messages.get(number.checked_sub(1)?)?;
        if self.deleted.contains(&m.id) {
            None
        } else {
            Some(m)
        }
    }

    /// Process one command, returning the reply to send.
    pub fn handle(&mut self, command: PopCommand) -> PopReply {
        match (self.state, command) {
            (_, PopCommand::Quit) => {
                if self.state == PopState::Transaction
                    && let Some(mailbox) = &self.mailbox
                {
                    for id in &self.deleted {
                        self.store.remove(mailbox, *id);
                    }
                }
                self.state = PopState::Closed;
                PopReply::ok("Bye")
            }
            (_, PopCommand::Noop) => PopReply::ok(""),
            // CAPA is valid in any phase; it lists STLS until TLS is active so a
            // client knows it can (must) upgrade before authenticating (RFC 2449).
            (_, PopCommand::Capa) => {
                let mut reply = PopReply::ok("Capability list follows");
                reply.lines = vec!["USER".to_string()];
                if self.tls_available && !self.tls_active {
                    reply.lines.push("STLS".to_string());
                }
                reply
            }
            // STLS is only valid before authentication (RFC 2595 §4). The socket
            // loop performs the handshake after this `+OK`.
            (PopState::Authorization, PopCommand::Stls) => {
                if self.tls_active {
                    PopReply::err("STLS already active")
                } else if self.tls_available {
                    PopReply::ok("Begin TLS negotiation")
                } else {
                    PopReply::err("STLS not supported")
                }
            }
            (PopState::Transaction, PopCommand::Stls) => {
                PopReply::err("STLS only allowed before authentication")
            }
            (PopState::Authorization, PopCommand::User(name)) => {
                if self.tls_available && !self.tls_active {
                    // Never accept credentials in cleartext when TLS is offered.
                    PopReply::err("[AUTH] STLS required before authentication")
                } else {
                    self.pending_user = Some(name);
                    PopReply::ok("send PASS")
                }
            }
            (PopState::Authorization, PopCommand::Pass(password)) => {
                if self.tls_available && !self.tls_active {
                    return PopReply::err("[AUTH] STLS required before authentication");
                }
                let Some(user) = self.pending_user.take() else {
                    return PopReply::err("USER required first");
                };
                if self.auth.check(&user, &password) {
                    self.messages = self.store.list(&user);
                    self.mailbox = Some(user);
                    self.state = PopState::Transaction;
                    PopReply::ok(format!("{} message(s)", self.messages.len()))
                } else {
                    PopReply::err("authentication failed")
                }
            }
            (PopState::Transaction, PopCommand::Stat) => {
                let (count, octets) = self.live().fold((0usize, 0usize), |(c, o), (_, m)| {
                    (c + 1, o + m.message.to_bytes().len())
                });
                PopReply::ok(format!("{count} {octets}"))
            }
            (PopState::Transaction, PopCommand::List(None)) => {
                let mut reply = PopReply::ok("scan listing follows");
                reply.lines = self
                    .live()
                    .map(|(n, m)| format!("{n} {}", m.message.to_bytes().len()))
                    .collect();
                reply
            }
            (PopState::Transaction, PopCommand::List(Some(n))) => match self.message_at(n) {
                Some(m) => PopReply::ok(format!("{n} {}", m.message.to_bytes().len())),
                None => PopReply::err("no such message"),
            },
            (PopState::Transaction, PopCommand::Retr(n)) => match self.message_at(n) {
                Some(m) => {
                    let bytes = m.message.to_bytes();
                    let mut reply = PopReply::ok(format!("{} octets", bytes.len()));
                    reply.lines = String::from_utf8_lossy(&bytes)
                        .split("\r\n")
                        .map(ToString::to_string)
                        .collect();
                    reply
                }
                None => PopReply::err("no such message"),
            },
            (PopState::Transaction, PopCommand::Dele(n)) => match self.message_at(n) {
                Some(m) => {
                    self.deleted.insert(m.id);
                    PopReply::ok(format!("message {n} deleted"))
                }
                None => PopReply::err("no such message"),
            },
            (PopState::Transaction, PopCommand::Rset) => {
                self.deleted.clear();
                PopReply::ok("reset")
            }
            (PopState::Authorization, _) => PopReply::err("authenticate first"),
            (PopState::Transaction, PopCommand::User(_) | PopCommand::Pass(_)) => {
                PopReply::err("already authenticated")
            }
            (PopState::Closed, _) => PopReply::err("session closed"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mail::{Envelope, Mailbox, MemoryMailStore, Message};

    /// A stub authenticator that accepts one fixed credential pair.
    struct StubAuth {
        user: String,
        pass: String,
    }
    impl SessionAuth for StubAuth {
        fn check(&self, username: &str, password: &str) -> bool {
            username == self.user && password == self.pass
        }
    }

    fn seeded_store(mailbox: &str, n: usize) -> MemoryMailStore {
        let store = MemoryMailStore::new();
        for i in 0..n {
            let msg = Message::parse(
                Envelope::new(None, vec![Mailbox::parse(mailbox).unwrap()]),
                format!("Subject: m{i}\r\n\r\nbody {i}").as_bytes(),
            )
            .unwrap();
            store.deliver(mailbox, msg);
        }
        store
    }

    fn auth() -> StubAuth {
        StubAuth {
            user: "bob@example.com".into(),
            pass: "pw".into(),
        }
    }

    #[test]
    fn parses_commands() {
        assert_eq!(
            PopCommand::parse("USER bob@example.com").unwrap(),
            PopCommand::User("bob@example.com".into())
        );
        assert_eq!(PopCommand::parse("RETR 2").unwrap(), PopCommand::Retr(2));
        assert_eq!(PopCommand::parse("LIST").unwrap(), PopCommand::List(None));
        assert!(PopCommand::parse("RETR x").is_err());
        assert!(PopCommand::parse("FROB").is_err());
    }

    #[test]
    fn auth_then_stat_and_retr() {
        let auth = auth();
        let store = seeded_store("bob@example.com", 2);
        let mut s = Pop3Session::new(&auth, &store);
        assert!(s.handle(PopCommand::User("bob@example.com".into())).ok);
        let pass = s.handle(PopCommand::Pass("pw".into()));
        assert!(pass.ok);
        assert_eq!(s.state(), PopState::Transaction);
        let stat = s.handle(PopCommand::Stat);
        assert!(stat.ok);
        assert!(stat.message.starts_with("2 ")); // "2 <octets>"
        let retr = s.handle(PopCommand::Retr(1));
        assert!(retr.ok);
        assert!(retr.lines.iter().any(|l| l.contains("Subject: m0")));
    }

    #[test]
    fn wrong_password_is_rejected() {
        let auth = auth();
        let store = seeded_store("bob@example.com", 1);
        let mut s = Pop3Session::new(&auth, &store);
        s.handle(PopCommand::User("bob@example.com".into()));
        assert!(!s.handle(PopCommand::Pass("nope".into())).ok);
        assert_eq!(s.state(), PopState::Authorization);
    }

    #[test]
    fn dele_then_quit_expunges() {
        let auth = auth();
        let store = seeded_store("bob@example.com", 2);
        let mut s = Pop3Session::new(&auth, &store);
        s.handle(PopCommand::User("bob@example.com".into()));
        s.handle(PopCommand::Pass("pw".into()));
        assert!(s.handle(PopCommand::Dele(1)).ok);
        // DELE hides it from LIST within the session.
        assert_eq!(s.handle(PopCommand::List(None)).lines.len(), 1);
        assert!(s.handle(PopCommand::Quit).ok);
        // QUIT expunged the deleted message from the store.
        assert_eq!(store.count("bob@example.com"), 1);
    }

    #[test]
    fn parses_capa_and_stls() {
        assert_eq!(PopCommand::parse("CAPA").unwrap(), PopCommand::Capa);
        assert_eq!(PopCommand::parse("STLS").unwrap(), PopCommand::Stls);
    }

    #[test]
    fn capa_lists_stls_before_tls_and_not_after() {
        let auth = auth();
        let store = seeded_store("bob@example.com", 0);
        let mut s = Pop3Session::with_tls(&auth, &store, false);
        let before = s.handle(PopCommand::Capa);
        assert!(
            before.lines.iter().any(|l| l == "STLS"),
            "{:?}",
            before.lines
        );

        let mut s = Pop3Session::with_tls(&auth, &store, true);
        let after = s.handle(PopCommand::Capa);
        assert!(
            !after.lines.iter().any(|l| l == "STLS"),
            "{:?}",
            after.lines
        );
    }

    #[test]
    fn user_pass_refused_before_tls_when_available() {
        let auth = auth();
        let store = seeded_store("bob@example.com", 1);
        let mut s = Pop3Session::with_tls(&auth, &store, false);
        let u = s.handle(PopCommand::User("bob@example.com".into()));
        assert!(!u.ok, "USER must be refused before STLS");
        let p = s.handle(PopCommand::Pass("pw".into()));
        assert!(!p.ok, "PASS must be refused before STLS");
        assert_eq!(s.state(), PopState::Authorization);
    }

    #[test]
    fn stls_granted_then_auth_allowed_after_upgrade() {
        let auth = auth();
        let store = seeded_store("bob@example.com", 1);
        // STLS offered before TLS, refused once active or when unsupported.
        let mut s = Pop3Session::with_tls(&auth, &store, false);
        assert!(s.handle(PopCommand::Stls).ok);
        let mut s = Pop3Session::with_tls(&auth, &store, true);
        assert!(!s.handle(PopCommand::Stls).ok);
        let mut s = Pop3Session::new(&auth, &store);
        assert!(!s.handle(PopCommand::Stls).ok);

        // After the upgrade (active=true) USER/PASS authenticate normally.
        let mut s = Pop3Session::with_tls(&auth, &store, true);
        assert!(s.handle(PopCommand::User("bob@example.com".into())).ok);
        assert!(s.handle(PopCommand::Pass("pw".into())).ok);
        assert_eq!(s.state(), PopState::Transaction);
    }
}
