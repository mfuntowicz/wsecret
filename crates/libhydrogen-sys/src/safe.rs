//! Safe, thin wrappers over the raw libhydrogen FFI declarations.
//!
//! No allocation, no copying beyond what the C functions do: every function
//! forwards its arguments to one C call. Cryptography stays in the pinned C
//! library (commit `6c58976b3b9178441218c12bca2cc414d9efe30d`); this module
//! only fixes the signatures so callers cannot pass inconsistent lengths.
//!
//! Context strings are fixed 8-byte domains with explicit trailing NULs,
//! matching upstream `secret.c`'s `char ctx[8] = "MASTER"` (which zero-fills
//! to `"MASTER\0\0"`). They are never `&str` casts.

use core::ffi::{c_char, c_int, c_void};
use std::sync::Once;

use crate::{
    hydro_equal, hydro_hash_hash, hydro_init, hydro_memzero, hydro_pwhash_deterministic,
    hydro_random_buf, hydro_secretbox_decrypt, hydro_secretbox_encrypt,
};

/// 8-byte context domain for the master-key derivation (upstream `"MASTER"`).
pub const CTX_MASTER: [u8; 8] = *b"MASTER\0\0";

/// 8-byte context domain for secret entry encryption (upstream `"SECRET"`).
pub const CTX_SECRET: [u8; 8] = *b"SECRET\0\0";

/// 8-byte context domain for passphrase-key derivation (upstream `"PASSWD"`).
pub const CTX_PASSWD: [u8; 8] = *b"PASSWD\0\0";

/// `hydro_secretbox_HEADERBYTES` = SIV(20) + MAC(16).
pub const SECRETBOX_HEADERBYTES: usize = 20 + 16;

/// Ciphertext size of a fixed 512-byte store entry.
pub const ENTRY_BYTES: usize = 512;

/// Plaintext size of a fixed 512-byte store entry.
pub const ENTRY_PAYLOAD: usize = ENTRY_BYTES - SECRETBOX_HEADERBYTES;

/// Fixed message id used for all secretbox operations (upstream passes 0).
pub const MSG_ID: u64 = 0;

/// `hydro_hash_KEYBYTES`: the key size `hash` forwards to `hydro_hash_hash`.
pub const HASH_KEYBYTES: usize = 32;

/// `hydro_pwhash_deterministic` parameters that reproduce upstream `s_derive`
/// (`memlimit = 0`, `threads = 1`; the caller supplies the header's opslimit).
const PWHASH_MEMLIMIT: usize = 0;
const PWHASH_THREADS: u8 = 1;

static INIT: Once = Once::new();

/// Initializes the libhydrogen PRNG exactly once. Idempotent and thread-safe;
/// `hydro_init()` always returns 0.
#[inline]
pub fn init() {
    INIT.call_once(|| {
        // SAFETY: `hydro_init` takes no arguments and cannot fail (see
        // `impl/core.h`: it only ensures the PRNG is seeded and returns 0).
        let rc: c_int = unsafe { hydro_init() };
        debug_assert_eq!(rc, 0);
    });
}

/// Derives 32 bytes from `pass` with the pinned libhydrogen KDF, using the
/// parameters of upstream `s_derive` (memlimit 0, threads 1).
///
/// Deterministic for a fixed input tuple, as required for `.secret` store
/// compatibility. Panics if the C call reports failure (it cannot for these
/// fixed valid parameters; see plan §1.4).
#[inline]
pub fn pwhash_deterministic(
    out: &mut [u8; 32],
    pass: &[u8],
    ctx: &[u8; 8],
    master: &[u8; 32],
    ops_limit: u64,
) {
    init();
    // SAFETY: all pointers are valid for the lengths passed; `out` is exactly
    // `h_len` bytes, `ctx` is exactly `hydro_pwhash_CONTEXTBYTES`, `master` is
    // exactly `hydro_pwhash_MASTERKEYBYTES`, and `pass` is only read through
    // `passwd_len` bytes. `out` cannot alias `pass` or `master` (`&mut` vs
    // `&`). The three arrays are trivially `Copy` and passed by reference, so
    // no stack copy of `pass` is made here.
    let rc = unsafe {
        hydro_pwhash_deterministic(
            out.as_mut_ptr(),
            out.len(),
            pass.as_ptr().cast::<c_char>(),
            pass.len(),
            ctx.as_ptr().cast::<c_char>(),
            master.as_ptr(),
            ops_limit,
            PWHASH_MEMLIMIT,
            PWHASH_THREADS,
        )
    };
    assert!(rc == 0, "hydro_pwhash_deterministic failed (rc={rc})");
}

/// Encrypts `msg` (476 bytes) into `out` (512 bytes = 36-byte header + 476)
/// with message id 0.
#[inline]
pub fn secretbox_encrypt(out: &mut [u8; ENTRY_BYTES], msg: &[u8; ENTRY_PAYLOAD], ctx: &[u8; 8], key: &[u8; 32]) {
    init();
    // SAFETY: `out` is `HEADERBYTES + msg.len()` bytes; `msg` and `key` are
    // read-only and cannot alias `out` (`&mut` vs `&`); `ctx` is exactly
    // `hydro_secretbox_CONTEXTBYTES`. The arrays are passed by reference, so
    // no stack copy of `msg` is made here.
    let rc = unsafe {
        hydro_secretbox_encrypt(
            out.as_mut_ptr(),
            msg.as_ptr().cast::<c_void>(),
            msg.len(),
            MSG_ID,
            ctx.as_ptr().cast::<c_char>(),
            key.as_ptr(),
        )
    };
    debug_assert_eq!(rc, 0);
}

/// Decrypts `ct` (512 bytes) into `out` (476 bytes). Returns `false` on MAC
/// failure; the C implementation zeroes the plaintext buffer on failure.
#[inline]
pub fn secretbox_decrypt(out: &mut [u8; ENTRY_PAYLOAD], ct: &[u8; ENTRY_BYTES], ctx: &[u8; 8], key: &[u8; 32]) -> bool {
    // No `init()` needed here: decrypting with a fixed key is pure and the
    // RNG is untouched.
    // SAFETY: `out` is exactly `clen - HEADERBYTES` bytes; `ct` and `key` are
    // read-only and cannot alias `out`; `ctx` is exactly
    // `hydro_secretbox_CONTEXTBYTES`.
    let rc: c_int = unsafe {
        hydro_secretbox_decrypt(
            out.as_mut_ptr().cast::<c_void>(),
            ct.as_ptr(),
            ct.len(),
            MSG_ID,
            ctx.as_ptr().cast::<c_char>(),
            key.as_ptr(),
        )
    };
    rc == 0
}

/// Fills `out` with random bytes from the libhydrogen PRNG.
#[inline]
pub fn random_buf(out: &mut [u8]) {
    init();
    // SAFETY: `out` is valid for `out.len()` writable bytes.
    unsafe {
        hydro_random_buf(out.as_mut_ptr().cast::<c_void>(), out.len());
    }
}

/// Zeroizes `x` through `hydro_memzero`, which the compiler cannot optimize
/// away.
#[inline]
pub fn memzero(x: &mut [u8]) {
    // SAFETY: `x` is valid for `x.len()` writable bytes.
    unsafe {
        hydro_memzero(x.as_mut_ptr().cast::<c_void>(), x.len());
    }
}

/// Constant-time equality of two byte slices. Slices of different lengths are
/// never equal and are not compared in constant time (the length is public).
///
/// Note on an upstream quirk (present at the pinned revision and current
/// libhydrogen): `hydro_equal` returns `false` when both pointers are
/// identical (`if (b1 == b2) d = ~d;` in `impl/core.h`), contradicting content
/// equality. Upstream `secret.c` never passes aliased buffers (verified at its
/// three call sites), so the C behavior is preserved verbatim here for
/// distinct buffers; the wrapper only special-cases the identical-buffer case
/// where content equality is trivially true and no comparison (or timing)
/// occurs.
#[inline]
pub fn equal(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    if a.as_ptr() == b.as_ptr() {
        return true;
    }
    // SAFETY: the identical-buffer case returned above, so `a` and `b` point
    // to distinct memory; both pointers are valid for the shared length and
    // `hydro_equal` only reads.
    unsafe { hydro_equal(a.as_ptr().cast::<c_void>(), b.as_ptr().cast::<c_void>(), a.len()) }
}

/// Hashes `input` into `out` (16..=65535 bytes, `hydro_hash_BYTES_MIN/MAX`)
/// under `ctx`, unkeyed, exactly as the §5.6 mutex-name derivation expects.
///
/// Panics on invalid output lengths (the C call returns -1).
#[inline]
pub fn hash(out: &mut [u8], input: &[u8], ctx: &[u8; 8]) {
    // SAFETY: pointers are valid for the lengths passed; `out` cannot alias
    // `input` (`&mut` vs `&`); `ctx` is exactly `hydro_hash_CONTEXTBYTES`.
    // A NULL key requests the unkeyed KMAC variant, as upstream does.
    let rc = unsafe {
        hydro_hash_hash(
            out.as_mut_ptr(),
            out.len(),
            input.as_ptr().cast::<c_void>(),
            input.len(),
            ctx.as_ptr().cast::<c_char>(),
            core::ptr::null(),
        )
    };
    assert!(rc == 0, "hydro_hash_hash failed (rc={rc})");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn init_is_idempotent() {
        init();
        init();
    }

    #[test]
    fn pwhash_deterministic_is_deterministic() {
        let pass = b"correct horse battery staple";
        let master = [0x2au8; 32];
        let mut out1 = [0u8; 32];
        let mut out2 = [0u8; 32];
        pwhash_deterministic(&mut out1, pass, &CTX_MASTER, &master, 10_000);
        pwhash_deterministic(&mut out2, pass, &CTX_MASTER, &master, 10_000);
        assert_eq!(out1, out2, "two derivations of the same tuple must match");
        // Different context must change the output.
        let mut out3 = [0u8; 32];
        pwhash_deterministic(&mut out3, pass, &CTX_PASSWD, &master, 10_000);
        assert_ne!(out1, out3, "different context must change the output");
    }

    #[test]
    fn secretbox_round_trip() {
        let key = [7u8; 32];
        let mut msg = [0u8; ENTRY_PAYLOAD];
        for (i, b) in msg.iter_mut().enumerate() {
            *b = i as u8;
        }
        let mut ct = [0u8; ENTRY_BYTES];
        secretbox_encrypt(&mut ct, &msg, &CTX_SECRET, &key);
        assert_ne!(&ct[SECRETBOX_HEADERBYTES..], &msg[..], "plaintext must be encrypted");
        let mut out = [0u8; ENTRY_PAYLOAD];
        assert!(secretbox_decrypt(&mut out, &ct, &CTX_SECRET, &key));
        assert_eq!(out, msg);
    }

    #[test]
    fn secretbox_decrypt_flipped_bit_fails() {
        let key = [7u8; 32];
        let msg = [0x5au8; ENTRY_PAYLOAD];
        let mut ct = [0u8; ENTRY_BYTES];
        secretbox_encrypt(&mut ct, &msg, &CTX_SECRET, &key);

        // Flip one ciphertext bit.
        let mut bad = ct;
        bad[SECRETBOX_HEADERBYTES] ^= 0x01;
        let mut out = [0xaau8; ENTRY_PAYLOAD];
        assert!(!secretbox_decrypt(&mut out, &bad, &CTX_SECRET, &key));
        assert_eq!(out, [0u8; ENTRY_PAYLOAD], "C must zero the buffer on failure");

        // Flip one MAC bit.
        let mut bad_mac = ct;
        bad_mac[SECRETBOX_HEADERBYTES - 1] ^= 0x80;
        assert!(!secretbox_decrypt(&mut out, &bad_mac, &CTX_SECRET, &key));
    }

    #[test]
    fn random_buf_fills_nonzero() {
        let mut buf = [0u8; 64];
        random_buf(&mut buf);
        assert!(buf.iter().any(|&b| b != 0), "buffer is all zero");
    }

    #[test]
    fn memzero_zeroes() {
        let mut buf = [0xffu8; 32];
        memzero(&mut buf);
        assert_eq!(buf, [0u8; 32]);
    }

    #[test]
    fn equal_true_and_false() {
        // Same slice: identical pointers (upstream C quirk is covered in
        // `equal`'s docs; the wrapper special-cases it).
        let x = b"abc".to_vec();
        assert!(equal(&x, &x));

        // Distinct buffers with equal content: exercises the C path.
        let a = b"abc".to_vec();
        let b = b"abc".to_vec();
        assert_ne!(a.as_ptr(), b.as_ptr(), "test setup: buffers must be distinct");
        assert!(equal(&a, &b));

        assert!(!equal(&a, b"abd"));
        assert!(!equal(&a, b"abcd"));
    }

    #[test]
    fn hash_produces_32_bytes() {
        let mut out = [0u8; 32];
        hash(&mut out, b"input", &CTX_MASTER);
        assert_ne!(out, [0u8; 32]);

        let mut out2 = [0u8; 32];
        hash(&mut out2, b"input", &CTX_MASTER);
        assert_eq!(out, out2);

        let mut out3 = [0u8; 32];
        hash(&mut out3, b"input", &CTX_SECRET);
        assert_ne!(out, out3, "different context must change the output");
    }

    #[test]
    fn context_constants_have_trailing_nuls() {
        assert_eq!(&CTX_MASTER, b"MASTER\0\0");
        assert_eq!(&CTX_SECRET, b"SECRET\0\0");
        assert_eq!(&CTX_PASSWD, b"PASSWD\0\0");
    }
}
