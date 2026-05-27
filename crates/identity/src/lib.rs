//! Authentication for the Snail mail server: the account/identity model,
//! password authentication over m10's credential store, SASL (PLAIN/LOGIN),
//! XOAUTH2 bearer-token auth, and per-connection authentication state.

pub mod auth;
pub mod check;
pub mod connect;
pub mod data;
pub mod error;
pub mod oauth;
pub mod sals;

pub use auth::Authenticator;
pub use connect::{ConnectionAuth, ConnectionState};
pub use data::{Account, Identity, Role};
pub use error::{IdentityError, Result};
pub use oauth::{
    StaticTokenValidator, TokenValidator, XOAuth2, authenticate_xoauth2, parse_xoauth2,
};
pub use sals::{SaslCredentials, SaslMechanism, decode_login_field, decode_plain};
