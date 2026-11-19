//! Passphrase acquisition: the shared prompts and the unlock + no-records
//! confirmation helper (`ssh agent` uses it; ordinary commands prompt through
//! [`crate::console`] the same way).
//!
//! The upstream unlock sequence every vault access shares (`secret.c`, pinned
//! `angt/secret` revision):
//!
//! - [`PROMPT_PASSPHRASE`] — upstream `s_ask_pass("Passphrase: ")`.
//! - [`unlock_with_confirmation`] — upstream `s_open_secret` → `s_ask_pass` →
//!   `s_get_secret(NULL, 0)`: any decryptable record passes; otherwise the
//!   passphrase is re-entered and both derivations are compared in constant
//!   time (`Passphrases don't match!` on mismatch). Empty input is upstream's
//!   `s_exit(0)` ([`UnlockError::Cancelled`]).
//!
//! This module contains **no unsafe code**. `Session::unlock` zeroizes the
//! entered passphrase on every return path, and the re-derived check session
//! is dropped (zeroized) immediately after the comparison.

use wsecret_core::error::Error;
use wsecret_core::format::Header;
use wsecret_core::session::{Session, sessions_same_key};
use wsecret_core::store::Store;

/// Prompt for the initial passphrase (upstream `s_ask_pass("Passphrase: ")`).
pub const PROMPT_PASSPHRASE: &str = "Passphrase: ";
/// Prompt for the no-records confirmation (upstream `s_get_secret`'s retype:
/// `s_ask_pass("No secrets stored with this passphrase.\nPlease, retype it to confirm: ")`).
pub const PROMPT_CONFIRM_NEW_PARTITION: &str =
    "No secrets stored with this passphrase.\nPlease, retype it to confirm: ";

/// Fatal outcomes of [`unlock_with_confirmation`]. [`UnlockError::Cancelled`]
/// is the one non-fatal case: upstream exits **0** on empty input
/// (`s_exit(0)`); the mismatch renders as `Fatal: Passphrases don't match!`
/// through the normal error path and exits 1.
#[derive(Debug)]
pub enum UnlockError {
    /// Empty passphrase input (upstream `s_exit(0)` — exit 0, not fatal).
    Cancelled,
    /// The retype did not match the first entry (upstream:
    /// "Passphrases don't match!").
    PassphraseMismatch,
    /// Store/unlock failure through the normal error path.
    Core(Error),
}

/// The upstream unlock + confirmation sequence (`s_open_secret` →
/// `s_ask_pass` → `s_get_secret(NULL, 0)` retype). Any decryptable record
/// passes; otherwise the passphrase is re-entered and both derivations are
/// compared constant-time ([`sessions_same_key`]).
pub(crate) fn unlock_with_confirmation<F>(
    store: &mut Store,
    header: &Header,
    prompt: &mut F,
) -> Result<Session, UnlockError>
where
    F: FnMut(&str) -> std::io::Result<Vec<u8>>,
{
    let _acquisition = wsecret_core::windows::security::begin_secret_acquisition()
        .map_err(UnlockError::Core)?;
    let mut pass = prompt(PROMPT_PASSPHRASE).map_err(|e| UnlockError::Core(Error::Io(e)))?;
    if pass.is_empty() {
        return Err(UnlockError::Cancelled);
    }
    // `Session::unlock` zeroizes `pass` on every return path.
    let session = Session::unlock(header, &mut pass).map_err(UnlockError::Core)?;

    // Upstream `pass_ok`: does ANY record decrypt with this key?
    let mut decryptable = false;
    store
        .scan_each(&session, None, &mut |_| {
            decryptable = true;
            Ok(())
        })
        .map_err(UnlockError::Core)?;

    if !decryptable {
        let mut again = prompt(PROMPT_CONFIRM_NEW_PARTITION)
            .map_err(|e| UnlockError::Core(Error::Io(e)))?;
        if again.is_empty() {
            return Err(UnlockError::Cancelled);
        }
        let check = Session::unlock(header, &mut again).map_err(UnlockError::Core)?;
        if !sessions_same_key(&session, &check).map_err(UnlockError::Core)? {
            return Err(UnlockError::PassphraseMismatch);
        }
        // Keys are equal (upstream keeps the re-derived one); `check` drops
        // here, zeroizing its at-rest copy.
    }
    Ok(session)
}

#[cfg(test)]
mod tests {
    use super::*;
    use wsecret_core::format::OPS_LIMIT_MIN;

    fn temp_store(name: &str) -> (std::path::PathBuf, Store, Header) {
        let path = std::env::temp_dir().join(format!(
            "wsecret-unlock-{name}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_file(&path);
        let (store, header, _receipt) = Store::create(&path, OPS_LIMIT_MIN).expect("create");
        (path, store, header)
    }

    #[test]
    fn unlock_prompts_once_when_records_exist() {
        let (path, mut store, header) = temp_store("once");
        let session = Session::unlock(&header, &mut b"pass-a".to_vec()).expect("unlock");
        store
            .append_or_reuse(None, &session, b"k", b"v")
            .expect("record");

        let mut calls = Vec::new();
        let out = unlock_with_confirmation(&mut store, &header, &mut |p| {
            calls.push(p.to_owned());
            Ok(b"pass-a".to_vec())
        })
        .expect("unlock_with_confirmation");
        assert_eq!(calls, vec![PROMPT_PASSPHRASE]);
        assert!(!out.is_locked());
        drop(store);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn unlock_confirms_retype_when_no_records_decrypt() {
        let (path, mut store, header) = temp_store("confirm");
        let mut calls = Vec::new();
        let out = unlock_with_confirmation(&mut store, &header, &mut |p| {
            calls.push(p.to_owned());
            Ok(b"pass-b".to_vec())
        })
        .expect("unlock_with_confirmation");
        assert_eq!(calls, vec![PROMPT_PASSPHRASE, PROMPT_CONFIRM_NEW_PARTITION]);
        assert!(!out.is_locked());
        drop(store);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn unlock_retype_mismatch_is_fatal() {
        let (path, mut store, header) = temp_store("mismatch");
        let mut n = 0;
        let err = match unlock_with_confirmation(&mut store, &header, &mut |_p| {
            n += 1;
            Ok(if n == 1 {
                b"pass-c".to_vec()
            } else {
                b"other".to_vec()
            })
        }) {
            Err(e) => e,
            Ok(_) => panic!("mismatch must fail"),
        };
        assert!(matches!(err, UnlockError::PassphraseMismatch));
        drop(store);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn unlock_empty_input_exits_zero() {
        let (path, mut store, header) = temp_store("empty");
        let err = match unlock_with_confirmation(&mut store, &header, &mut |_p| Ok(Vec::new())) {
            Err(e) => e,
            Ok(_) => panic!("empty input cancels"),
        };
        assert!(matches!(err, UnlockError::Cancelled));
        drop(store);
        let _ = std::fs::remove_file(&path);
    }
}
