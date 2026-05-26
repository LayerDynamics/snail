//! Web (HTTP/webmail) access: a request → response handler over the mail store,
//! authenticated via [`SessionAuth`]. The HTTP socket layer is wired at the
//! composition root (m15); this is the request routing and store access.

use mail::MailStore;

use crate::SessionAuth;

/// A web access request carrying the caller's credentials.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WebRequest {
    /// List `(id, subject)` summaries for the user's mailbox.
    ListMailbox {
        /// Account username.
        user: String,
        /// Account password.
        password: String,
    },
    /// Fetch one message's raw bytes by id.
    FetchMessage {
        /// Account username.
        user: String,
        /// Account password.
        password: String,
        /// Message id.
        id: u64,
    },
}

/// A web access response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WebResponse {
    /// Authentication failed (HTTP 401 equivalent).
    Unauthorized,
    /// A listing of `(id, subject)` summaries.
    Listing(Vec<(u64, String)>),
    /// A message's raw bytes.
    Message(Vec<u8>),
    /// The requested message was not found (HTTP 404 equivalent).
    NotFound,
}

/// Handles web access requests against the mail store.
pub struct WebAccess<'a, A: SessionAuth, S: MailStore> {
    auth: &'a A,
    store: &'a S,
}

impl<'a, A: SessionAuth, S: MailStore> WebAccess<'a, A, S> {
    /// Build a handler over an authenticator and store.
    pub fn new(auth: &'a A, store: &'a S) -> Self {
        Self { auth, store }
    }

    /// Route and handle a request.
    pub fn handle(&self, request: WebRequest) -> WebResponse {
        match request {
            WebRequest::ListMailbox { user, password } => {
                if !self.auth.check(&user, &password) {
                    return WebResponse::Unauthorized;
                }
                let listing = self
                    .store
                    .list(&user)
                    .into_iter()
                    .map(|m| {
                        let subject = m.message.subject().unwrap_or("(no subject)").to_string();
                        (m.id, subject)
                    })
                    .collect();
                WebResponse::Listing(listing)
            }
            WebRequest::FetchMessage { user, password, id } => {
                if !self.auth.check(&user, &password) {
                    return WebResponse::Unauthorized;
                }
                match self.store.list(&user).into_iter().find(|m| m.id == id) {
                    Some(m) => WebResponse::Message(m.message.to_bytes()),
                    None => WebResponse::NotFound,
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

    fn store() -> MemoryMailStore {
        let store = MemoryMailStore::new();
        let msg = Message::parse(
            Envelope::new(None, vec![Mailbox::parse("bob@example.com").unwrap()]),
            b"Subject: Hello\r\n\r\nhi",
        )
        .unwrap();
        store.deliver("bob@example.com", msg);
        store
    }

    #[test]
    fn lists_with_valid_credentials() {
        let (auth, store) = (StubAuth, store());
        let web = WebAccess::new(&auth, &store);
        let resp = web.handle(WebRequest::ListMailbox {
            user: "bob@example.com".into(),
            password: "pw".into(),
        });
        match resp {
            WebResponse::Listing(items) => {
                assert_eq!(items.len(), 1);
                assert_eq!(items[0].1, "Hello");
            }
            other => panic!("expected listing, got {other:?}"),
        }
    }

    #[test]
    fn rejects_bad_credentials() {
        let (auth, store) = (StubAuth, store());
        let web = WebAccess::new(&auth, &store);
        let resp = web.handle(WebRequest::ListMailbox {
            user: "bob@example.com".into(),
            password: "wrong".into(),
        });
        assert_eq!(resp, WebResponse::Unauthorized);
    }

    #[test]
    fn fetch_missing_message_is_not_found() {
        let (auth, store) = (StubAuth, store());
        let web = WebAccess::new(&auth, &store);
        let resp = web.handle(WebRequest::FetchMessage {
            user: "bob@example.com".into(),
            password: "pw".into(),
            id: 9999,
        });
        assert_eq!(resp, WebResponse::NotFound);
    }
}
