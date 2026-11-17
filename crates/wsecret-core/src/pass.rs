//! Deterministic-secret derivation chain and output normalization
//! (plan §1.5–§1.6, upstream `s_normalize_and_show`).
//!
//! Behavior port of upstream `s_pass` + `s_normalize_and_show`
//! (`secret.c`, pinned `angt/secret` commit
//! `e98103def4e062a6f9a8fa5e7693abe15f20817a`):
//!
//! - **Chain** (`s_pass`): `k_0` = the session key (upstream `s.x.key`, the
//!   `MASTER`-derived key); `k_i = hydro_pwhash_deterministic(32, subkey_i,
//!   "PASSWD\0\0", k_{i-1}, opslimit, memlimit=0, threads=1)` where
//!   `opslimit` is the store header's; the output is
//!   `normalize_password(k_last)`.
//! - **Normalization** (`s_normalize_and_show`): `n = 1 + '~' - '!' = 94`;
//!   for each input byte `b < 2n` (188) emit `'!' + (b % n)`; stop after
//!   25 emitted characters (`S_PWDGENLEN`). The 188 = 2×94 bound keeps the
//!   mapping unbiased.
//!
//! Every subkey is validated with upstream `s_keylen` semantics (non-empty,
//! no byte `<= 0x20`, at most 255 bytes) before any derivation happens, so
//! the error path holds no key material.

use crate::error::Error;
use crate::format::check_name;
use crate::session::Session;
use libhydrogen_sys::memzero;

/// Upstream `S_PWDGENLEN`: normalized passwords are exactly 25 characters
/// when enough input bytes are consumed.
pub const PWDGENLEN: usize = 25;

/// Upstream `s_normalize_and_show` mapping, verbatim: `'!' + (b % 94)` for
/// each input byte `b < 188`, stopping after [`PWDGENLEN`] emitted
/// characters (input consumed until then or until the buffer end).
pub fn normalize_password(bytes: &[u8]) -> Vec<u8> {
    const N: u8 = 1 + b'~' - b'!'; // 94
    let mut out = Vec::with_capacity(PWDGENLEN);
    for &b in bytes {
        if out.len() >= PWDGENLEN {
            break;
        }
        if b < 2 * N {
            out.push(b'!'.wrapping_add(b % N));
        }
    }
    out
}

/// Upstream `s_pass` chain over `subkeys` (each an argv `KEY`/`SUBKEY`
/// string, validated like `s_keylen`), starting from the session key and
/// using the `PASSWD` context and the header's `opslimit`. The chain itself
/// runs inside [`Session::derive_chain`] (the key never leaves the session);
/// this function adds upstream's name validation and normalizes the result.
///
/// With an empty `subkeys` slice the chain degenerates to `k_0` (the
/// session key) normalized directly — the natural reading of the loop
/// with zero iterations.
pub fn deterministic_pass(s: &Session, subkeys: &[&[u8]]) -> Result<Vec<u8>, Error> {
    for sub in subkeys {
        // Upstream `s_keylen` semantics, shared with record-name validation
        // (`error::check_name`); the CLI prints its fatal message instead.
        check_name(sub).map_err(Error::Name)?;
    }

    let mut k_last = s.derive_chain(subkeys)?;
    let out = normalize_password(&k_last);
    memzero(&mut k_last);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::NameError;
    use crate::format::Header;
    use libhydrogen_sys::{CTX_MASTER, CTX_PASSWD, pwhash_deterministic};

    /// Upstream `S_KEYLENMAX`, the `s_keylen` bound shared by
    /// `error::check_name`.
    const KEYLENMAX: usize = 255;

    /// The fixed test tuple: passphrase + header for the `MASTER` derivation.
    const PASS: &[u8] = b"correct horse battery staple";

    /// Builds a session the same way upstream `s_unlock` does:
    /// `k = pwhash_deterministic(32, pass, "MASTER\0\0", hdr.master,
    /// hdr.ops_limit, 0, 1)`; `unlock` erases the passphrase buffer.
    fn test_session() -> (Session, Header) {
        let header = Header {
            version: 0,
            master: [0x2au8; 32],
            ops_limit: 10_000,
        };
        let mut pass = PASS.to_vec();
        let session = Session::unlock(&header, &mut pass).expect("unlock cannot fail here");
        assert!(pass.iter().all(|&b| b == 0), "unlock must erase the passphrase");
        (session, header)
    }

    // ---- normalize_password ----

    #[test]
    fn normalize_maps_bytes_under_188() {
        // b % 94 shifted by '!': 0 → '!', 93 → '~', 94 → '!', 187 → '~'.
        assert_eq!(normalize_password(&[0, 93, 94, 187]), b"!~!~");
        // A full 32-byte key with every byte < 188 yields exactly 25 chars.
        let input: Vec<u8> = (0..32).map(|i| (i * 3 % 188) as u8).collect();
        let out = normalize_password(&input);
        assert_eq!(out.len(), PWDGENLEN);
    }

    #[test]
    fn normalize_skips_bytes_at_least_188() {
        // 188..=255 are skipped entirely (not reduced mod 94).
        // 5 % 94 = 5 → '!' + 5 = 0x26 ('&').
        assert_eq!(normalize_password(&[188, 255, 5]), b"\x26");
        // Skipped bytes do not count toward the 25-char cap.
        let mut input = vec![200u8; 10];
        input.extend(0..25);
        assert_eq!(normalize_password(&input).len(), PWDGENLEN);
    }

    #[test]
    fn normalize_stops_after_25_chars() {
        let out = normalize_password(&[0u8; 64]);
        assert_eq!(out, vec![b'!'; PWDGENLEN]);
        // Variable length: fewer input bytes than the cap pass through.
        assert_eq!(normalize_password(&[0, 1, 2]).len(), 3);
        assert_eq!(normalize_password(&[]), Vec::<u8>::new());
        // Input stops at 25 EMITTED chars even with skipped bytes after.
        let mut input = vec![0u8; 25];
        input.push(200);
        input.extend(0..10);
        assert_eq!(normalize_password(&input).len(), PWDGENLEN);
    }

    #[test]
    fn normalize_output_is_printable_ascii_range() {
        let out = normalize_password(&(0..=255u8).collect::<Vec<_>>());
        assert!(out.iter().all(|&c| (b'!'..=b'~').contains(&c)));
        assert_eq!(out.len(), PWDGENLEN);
    }

    // ---- deterministic_pass ----

    #[test]
    fn deterministic_pass_matches_independent_derivation() {
        let (session, header) = test_session();
        let subkeys: &[&[u8]] = &[b"alice", b"bob", b"carol"];

        // Independent second derivation: hand-rolled chain through the
        // pinned KDF, mirroring upstream `s_pass`'s loop.
        let mut prev = {
            let mut key = [0u8; 32];
            let mut master_key = [0u8; 32];
            master_key.copy_from_slice(&header.master);
            pwhash_deterministic(&mut key, PASS, &CTX_MASTER, &master_key, header.ops_limit);
            key
        };
        let mut cur = [0u8; 32];
        for sub in subkeys {
            pwhash_deterministic(&mut cur, sub, &CTX_PASSWD, &prev, header.ops_limit);
            core::mem::swap(&mut prev, &mut cur);
        }
        let expected = normalize_password(&prev);
        memzero(&mut prev);
        memzero(&mut cur);

        let got = deterministic_pass(&session, subkeys).unwrap();
        assert_eq!(got, expected);
        assert_eq!(got.len(), PWDGENLEN);
    }

    #[test]
    fn deterministic_pass_is_deterministic_per_tuple() {
        let (session, _) = test_session();
        let a = deterministic_pass(&session, &[b"k1"]).unwrap();
        let b = deterministic_pass(&session, &[b"k1"]).unwrap();
        assert_eq!(a, b);

        // Order and content matter.
        let ab = deterministic_pass(&session, &[b"a", b"b"]).unwrap();
        let ba = deterministic_pass(&session, &[b"b", b"a"]).unwrap();
        assert_ne!(ab, ba);
    }

    #[test]
    fn deterministic_pass_without_subkeys_normalizes_session_key() {
        let (session, _) = test_session();
        let out = deterministic_pass(&session, &[]).unwrap();
        // Zero subkeys degenerates to k_0 = the raw session key, normalized
        // (upstream `s_pass` with no SUBKEY arguments).
        let mut k0 = session.derive_chain(&[]).unwrap();
        let expected = normalize_password(&k0);
        memzero(&mut k0);
        assert_eq!(out, expected);
    }

    #[test]
    fn deterministic_pass_validates_subkeys() {
        let (session, _) = test_session();
        assert!(matches!(
            deterministic_pass(&session, &[b""]),
            Err(Error::Name(NameError::Empty))
        ));
        assert!(matches!(
            deterministic_pass(&session, &[b"has space"]),
            Err(Error::Name(NameError::SpecialChar))
        ));
        assert!(matches!(
            deterministic_pass(&session, &[b"has\ttab"]),
            Err(Error::Name(NameError::SpecialChar))
        ));
        assert!(matches!(
            deterministic_pass(&session, &[&[b'k'; KEYLENMAX + 1]]),
            Err(Error::Name(NameError::TooLong))
        ));
        // 255 bytes is still fine.
        assert!(deterministic_pass(&session, &[&[b'k'; KEYLENMAX]]).is_ok());
    }

    // ---- Differential test against the verbatim pinned C (`secret.c`:
    // `s_header` + `s_unlock` + `s_derive` chain + `s_normalize_and_show`
    // mapping, compiled with `-DNOMAIN` on MSVC /std:c11). The values below
    // are the observed C outputs for the same tuple. ----

    #[test]
    fn matches_upstream_c_oracle() {
        let (session, _) = test_session();
        assert_eq!(
            deterministic_pass(&session, &[b"alice", b"bob", b"carol"]).unwrap(),
            b"6lbG><sw1:~+<s'6g45HM7?;}"
        );
        assert_eq!(
            deterministic_pass(&session, &[]).unwrap(),
            b"rD([VreU-P`3Agd+^8Ae"
        );
    }
}
