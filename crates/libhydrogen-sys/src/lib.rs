//! `libhydrogen-sys`: thin FFI binding to the pinned libhydrogen C library.
//!
//! The raw `extern "C"` declarations below mirror `vendor/hydrogen.h` from
//! libhydrogen commit `6c58976b3b9178441218c12bca2cc414d9efe30d` and stay
//! private to the crate. The public API is the safe wrapper surface in
//! [`safe`] (re-exported at the crate root).

mod safe;
pub use safe::*;

use core::ffi::{c_char, c_int, c_void};

unsafe extern "C" {
    fn hydro_init() -> c_int;

    fn hydro_random_buf(out: *mut c_void, out_len: usize);

    fn hydro_memzero(pnt: *mut c_void, len: usize);

    fn hydro_equal(b1_: *const c_void, b2_: *const c_void, len: usize) -> bool;

    fn hydro_pwhash_deterministic(
        h: *mut u8,
        h_len: usize,
        passwd: *const c_char,
        passwd_len: usize,
        ctx: *const c_char,
        master_key: *const u8,
        opslimit: u64,
        memlimit: usize,
        threads: u8,
    ) -> c_int;

    fn hydro_secretbox_encrypt(
        c: *mut u8,
        m_: *const c_void,
        mlen: usize,
        msg_id: u64,
        ctx: *const c_char,
        key: *const u8,
    ) -> c_int;

    fn hydro_secretbox_decrypt(
        m_: *mut c_void,
        c: *const u8,
        clen: usize,
        msg_id: u64,
        ctx: *const c_char,
        key: *const u8,
    ) -> c_int;

    fn hydro_hash_hash(
        out: *mut u8,
        out_len: usize,
        in_: *const c_void,
        in_len: usize,
        ctx: *const c_char,
        key: *const u8,
    ) -> c_int;

}
