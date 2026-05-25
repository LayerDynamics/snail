//! Account precondition checks applied during authentication (independent of
//! password verification).

use crate::data::Account;
use crate::error::{IdentityError, Result};

/// Verify that `account` is allowed to authenticate (currently: enabled).
///
/// # Errors
/// [`IdentityError::AccountDisabled`] if the account is disabled.
pub fn check_account(account: &Account) -> Result<()> {
    if account.enabled {
        Ok(())
    } else {
        Err(IdentityError::AccountDisabled(account.username.clone()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enabled_account_passes() {
        assert!(check_account(&Account::user("alice")).is_ok());
    }

    #[test]
    fn disabled_account_is_rejected() {
        let err = check_account(&Account::user("alice").disabled()).unwrap_err();
        assert!(matches!(err, IdentityError::AccountDisabled(_)));
    }
}
