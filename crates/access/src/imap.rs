//! IMAP4rev1 server session (a focused subset): CAPABILITY, LOGIN, SELECT, LIST,
//! FETCH, NOOP, LOGOUT. Pure and synchronous — the socket loop is wired at the
//! composition root (m15). `INBOX` maps to the authenticated user's mailbox.

use mail::{MailStore, StoredMessage};

use crate::SessionAuth;

/// What a `FETCH` should return for a message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FetchItem {
    /// `RFC822` / `BODY[]` — the full message.
    Full,
    /// `RFC822.SIZE` — just the octet count.
    Size,
}

/// A parsed IMAP command (without its tag).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ImapCommand {
    /// `CAPABILITY`
    Capability,
    /// `STARTTLS` — begin a TLS upgrade (RFC 2595 / RFC 3501).
    StartTls,
    /// `LOGIN <user> <pass>`
    Login { username: String, password: String },
    /// `SELECT <mailbox>`
    Select(String),
    /// `LIST <reference> <pattern>`
    List { reference: String, pattern: String },
    /// `FETCH <seq> <item>`
    Fetch { seq: usize, item: FetchItem },
    /// `NOOP`
    Noop,
    /// `LOGOUT`
    Logout,
}

/// A tagged IMAP command line: a client tag plus the command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaggedCommand {
    /// The client-chosen tag (echoed in the status response).
    pub tag: String,
    /// The parsed command.
    pub command: ImapCommand,
}

impl TaggedCommand {
    /// Parse `<tag> COMMAND [args]`.
    ///
    /// # Errors
    /// `Err(message)` (for a `BAD` response) on a missing tag or unknown command.
    pub fn parse(line: &str) -> std::result::Result<Self, String> {
        let line = line.trim_end_matches(['\r', '\n']);
        let mut parts = line.splitn(3, ' ');
        let tag = parts
            .next()
            .filter(|t| !t.is_empty())
            .ok_or("missing tag")?;
        let verb = parts.next().ok_or("missing command")?;
        let args = parts.next().unwrap_or("").trim();
        let command = match verb.to_ascii_uppercase().as_str() {
            "CAPABILITY" => ImapCommand::Capability,
            "STARTTLS" => ImapCommand::StartTls,
            "NOOP" => ImapCommand::Noop,
            "LOGOUT" => ImapCommand::Logout,
            "LOGIN" => {
                let (u, p) = args.split_once(' ').ok_or("LOGIN needs <user> <pass>")?;
                ImapCommand::Login {
                    username: unquote(u).to_string(),
                    password: unquote(p.trim()).to_string(),
                }
            }
            "SELECT" => ImapCommand::Select(unquote(args).to_string()),
            "LIST" => {
                let (r, p) = args.split_once(' ').ok_or("LIST needs <ref> <pattern>")?;
                ImapCommand::List {
                    reference: unquote(r).to_string(),
                    pattern: unquote(p.trim()).to_string(),
                }
            }
            "FETCH" => {
                let (seq, item) = args.split_once(' ').ok_or("FETCH needs <seq> <item>")?;
                let seq = seq
                    .parse::<usize>()
                    .map_err(|_| "invalid sequence number")?;
                let item = match item.trim().to_ascii_uppercase().as_str() {
                    "RFC822" | "BODY[]" | "BODY.PEEK[]" => FetchItem::Full,
                    "RFC822.SIZE" => FetchItem::Size,
                    other => return Err(format!("unsupported FETCH item `{other}`")),
                };
                ImapCommand::Fetch { seq, item }
            }
            other => return Err(format!("unknown command `{other}`")),
        };
        Ok(Self {
            tag: tag.to_string(),
            command,
        })
    }
}

fn unquote(s: &str) -> &str {
    s.strip_prefix('"')
        .and_then(|s| s.strip_suffix('"'))
        .unwrap_or(s)
}

/// An IMAP response: zero or more untagged `*` lines plus a tagged status line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImapResponse {
    /// Untagged response lines (without the leading `* `).
    pub untagged: Vec<String>,
    /// The tagged status line (e.g. `A1 OK LOGIN completed`).
    pub status: String,
}

/// IMAP session phase.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImapState {
    /// Before LOGIN.
    NotAuthenticated,
    /// Logged in, no mailbox selected.
    Authenticated,
    /// A mailbox is selected.
    Selected,
}

/// An IMAP session over a mailbox in `store`, authenticating via `auth`.
pub struct ImapSession<'a, A: SessionAuth, S: MailStore> {
    auth: &'a A,
    store: &'a S,
    state: ImapState,
    user: Option<String>,
    selected: Vec<StoredMessage>,
    /// The server offers `STARTTLS` (a certificate is configured).
    tls_available: bool,
    /// The connection is already encrypted (a `STARTTLS` upgrade completed).
    tls_active: bool,
}

impl<'a, A: SessionAuth, S: MailStore> ImapSession<'a, A, S> {
    /// Start a session with no TLS offered (a plaintext-only listener — used when
    /// the server has no certificate configured).
    pub fn new(auth: &'a A, store: &'a S) -> Self {
        Self {
            auth,
            store,
            state: ImapState::NotAuthenticated,
            user: None,
            selected: Vec::new(),
            tls_available: false,
            tls_active: false,
        }
    }

    /// Start a TLS-capable session. `active` is `true` when the connection is
    /// already encrypted (i.e. the session that resumes after a `STARTTLS`
    /// upgrade); `false` for the initial plaintext phase that advertises and
    /// permits `STARTTLS`. While TLS is available but not yet active the session
    /// advertises `LOGINDISABLED` and refuses `LOGIN`, so credentials are never
    /// accepted in cleartext.
    pub fn with_tls(auth: &'a A, store: &'a S, active: bool) -> Self {
        Self {
            auth,
            store,
            state: ImapState::NotAuthenticated,
            user: None,
            selected: Vec::new(),
            tls_available: true,
            tls_active: active,
        }
    }

    /// The current phase.
    #[must_use]
    pub fn state(&self) -> ImapState {
        self.state
    }

    /// Map an IMAP mailbox name to a store key. `INBOX` is the user's address.
    fn mailbox_key(&self, name: &str) -> Option<String> {
        let user = self.user.as_ref()?;
        if name.eq_ignore_ascii_case("INBOX") {
            Some(user.clone())
        } else {
            Some(format!("{user}/{name}"))
        }
    }

    /// Handle a tagged command, returning the response to send.
    pub fn handle(&mut self, tagged: TaggedCommand) -> ImapResponse {
        let tag = tagged.tag;
        let ok = |status: &str| ImapResponse {
            untagged: Vec::new(),
            status: format!("{tag} OK {status}"),
        };
        let no = |status: &str| ImapResponse {
            untagged: Vec::new(),
            status: format!("{tag} NO {status}"),
        };
        match tagged.command {
            ImapCommand::Capability => {
                // Advertise STARTTLS and LOGINDISABLED until the connection is
                // encrypted, so conforming clients refuse to send credentials in
                // cleartext (RFC 3501 §6.2.1, §7.2.1; RFC 2595).
                let mut caps = String::from("CAPABILITY IMAP4rev1");
                if self.tls_available && !self.tls_active {
                    caps.push_str(" STARTTLS LOGINDISABLED");
                }
                ImapResponse {
                    untagged: vec![caps],
                    status: format!("{tag} OK CAPABILITY completed"),
                }
            }
            ImapCommand::StartTls => {
                if self.tls_active {
                    no("STARTTLS already active")
                } else if self.tls_available {
                    // The socket loop performs the handshake after this reply.
                    ok("Begin TLS negotiation now")
                } else {
                    no("STARTTLS not supported")
                }
            }
            ImapCommand::Noop => ok("NOOP completed"),
            ImapCommand::Logout => {
                self.state = ImapState::NotAuthenticated;
                ImapResponse {
                    untagged: vec!["BYE Snail logging out".to_string()],
                    status: format!("{tag} OK LOGOUT completed"),
                }
            }
            ImapCommand::Login { username, password } => {
                if self.tls_available && !self.tls_active {
                    // LOGINDISABLED: never accept credentials before STARTTLS.
                    no("[PRIVACYREQUIRED] LOGIN disabled until STARTTLS")
                } else if self.auth.check(&username, &password) {
                    self.user = Some(username);
                    self.state = ImapState::Authenticated;
                    ok("LOGIN completed")
                } else {
                    no("LOGIN failed")
                }
            }
            _ if self.state == ImapState::NotAuthenticated => no("must authenticate first"),
            ImapCommand::Select(mailbox) => {
                let Some(key) = self.mailbox_key(&mailbox) else {
                    return no("not authenticated");
                };
                self.selected = self.store.list(&key);
                self.state = ImapState::Selected;
                ImapResponse {
                    untagged: vec![
                        format!("{} EXISTS", self.selected.len()),
                        "FLAGS (\\Seen \\Deleted)".to_string(),
                    ],
                    status: format!("{tag} OK [READ-WRITE] SELECT completed"),
                }
            }
            ImapCommand::List { .. } => ImapResponse {
                untagged: vec!["LIST (\\HasNoChildren) \"/\" \"INBOX\"".to_string()],
                status: format!("{tag} OK LIST completed"),
            },
            ImapCommand::Fetch { seq, item } => {
                if self.state != ImapState::Selected {
                    return no("no mailbox selected");
                }
                match self.selected.get(seq.wrapping_sub(1)) {
                    Some(stored) => {
                        let bytes = stored.message.to_bytes();
                        let untagged = match item {
                            FetchItem::Size => format!("{seq} FETCH (RFC822.SIZE {})", bytes.len()),
                            FetchItem::Full => format!(
                                "{seq} FETCH (RFC822 {{{}}}\r\n{})",
                                bytes.len(),
                                String::from_utf8_lossy(&bytes)
                            ),
                        };
                        ImapResponse {
                            untagged: vec![untagged],
                            status: format!("{tag} OK FETCH completed"),
                        }
                    }
                    None => no("no such message"),
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mail::{Envelope, Mailbox, MemoryMailStore, Message};

    struct StubAuth;
    impl SessionAuth for StubAuth {
        fn check(&self, username: &str, password: &str) -> bool {
            username == "bob@example.com" && password == "pw"
        }
    }

    fn store_with(n: usize) -> MemoryMailStore {
        let store = MemoryMailStore::new();
        for i in 0..n {
            let msg = Message::parse(
                Envelope::new(None, vec![Mailbox::parse("bob@example.com").unwrap()]),
                format!("Subject: m{i}\r\n\r\nbody{i}").as_bytes(),
            )
            .unwrap();
            store.deliver("bob@example.com", msg);
        }
        store
    }

    fn login(s: &mut ImapSession<StubAuth, MemoryMailStore>) {
        let r = s.handle(TaggedCommand::parse("A1 LOGIN bob@example.com pw").unwrap());
        assert!(r.status.contains("OK"));
    }

    #[test]
    fn parses_tagged_commands() {
        let cmd = TaggedCommand::parse("A1 LOGIN alice secret").unwrap();
        assert_eq!(cmd.tag, "A1");
        assert_eq!(
            cmd.command,
            ImapCommand::Login {
                username: "alice".into(),
                password: "secret".into()
            }
        );
        assert!(TaggedCommand::parse("A2 FROB").is_err());
    }

    #[test]
    fn requires_login_before_select() {
        let (auth, store) = (StubAuth, store_with(1));
        let mut s = ImapSession::new(&auth, &store);
        let r = s.handle(TaggedCommand::parse("A1 SELECT INBOX").unwrap());
        assert!(r.status.contains("NO"));
    }

    #[test]
    fn select_reports_exists_and_fetch_returns_message() {
        let (auth, store) = (StubAuth, store_with(2));
        let mut s = ImapSession::new(&auth, &store);
        login(&mut s);
        let sel = s.handle(TaggedCommand::parse("A2 SELECT INBOX").unwrap());
        assert!(sel.untagged.iter().any(|l| l == "2 EXISTS"));
        assert_eq!(s.state(), ImapState::Selected);
        let fetch = s.handle(TaggedCommand::parse("A3 FETCH 1 RFC822").unwrap());
        assert!(fetch.status.contains("OK"));
        assert!(fetch.untagged[0].contains("Subject: m0"));
    }

    #[test]
    fn bad_login_is_rejected() {
        let (auth, store) = (StubAuth, store_with(0));
        let mut s = ImapSession::new(&auth, &store);
        let r = s.handle(TaggedCommand::parse("A1 LOGIN bob@example.com wrong").unwrap());
        assert!(r.status.contains("NO"));
        assert_eq!(s.state(), ImapState::NotAuthenticated);
    }

    #[test]
    fn parses_starttls() {
        let cmd = TaggedCommand::parse("a STARTTLS").unwrap();
        assert_eq!(cmd.command, ImapCommand::StartTls);
    }

    #[test]
    fn capability_advertises_starttls_and_logindisabled_before_tls() {
        let (auth, store) = (StubAuth, store_with(0));
        let mut s = ImapSession::with_tls(&auth, &store, false);
        let r = s.handle(TaggedCommand::parse("A1 CAPABILITY").unwrap());
        assert!(r.untagged[0].contains("STARTTLS"), "{:?}", r.untagged);
        assert!(r.untagged[0].contains("LOGINDISABLED"), "{:?}", r.untagged);
    }

    #[test]
    fn capability_drops_starttls_and_logindisabled_after_tls() {
        let (auth, store) = (StubAuth, store_with(0));
        let mut s = ImapSession::with_tls(&auth, &store, true);
        let r = s.handle(TaggedCommand::parse("A1 CAPABILITY").unwrap());
        assert!(!r.untagged[0].contains("STARTTLS"), "{:?}", r.untagged);
        assert!(!r.untagged[0].contains("LOGINDISABLED"), "{:?}", r.untagged);
    }

    #[test]
    fn login_refused_before_tls_when_available() {
        let (auth, store) = (StubAuth, store_with(0));
        let mut s = ImapSession::with_tls(&auth, &store, false);
        let r = s.handle(TaggedCommand::parse("A1 LOGIN bob@example.com pw").unwrap());
        assert!(r.status.contains("NO"), "{}", r.status);
        assert!(r.status.contains("PRIVACYREQUIRED"), "{}", r.status);
        assert_eq!(s.state(), ImapState::NotAuthenticated);
    }

    #[test]
    fn login_allowed_after_tls_upgrade() {
        let (auth, store) = (StubAuth, store_with(0));
        let mut s = ImapSession::with_tls(&auth, &store, true);
        let r = s.handle(TaggedCommand::parse("A1 LOGIN bob@example.com pw").unwrap());
        assert!(r.status.contains("OK"), "{}", r.status);
        assert_eq!(s.state(), ImapState::Authenticated);
    }

    #[test]
    fn starttls_granted_when_available_and_refused_otherwise() {
        let (auth, store) = (StubAuth, store_with(0));
        // Available, not yet active: granted.
        let mut s = ImapSession::with_tls(&auth, &store, false);
        assert!(
            s.handle(TaggedCommand::parse("A1 STARTTLS").unwrap())
                .status
                .contains("OK")
        );
        // Already active: refused.
        let mut s = ImapSession::with_tls(&auth, &store, true);
        assert!(
            s.handle(TaggedCommand::parse("A1 STARTTLS").unwrap())
                .status
                .contains("NO")
        );
        // No certificate configured: refused.
        let mut s = ImapSession::new(&auth, &store);
        assert!(
            s.handle(TaggedCommand::parse("A1 STARTTLS").unwrap())
                .status
                .contains("NO")
        );
    }
}
