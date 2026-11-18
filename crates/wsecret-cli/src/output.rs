//! `show`/`dump` output rendering (plan §1.11, audit P7 corrections applied).
//!
//! Behavior port of upstream `s_show` and its helpers (`secret.c`, pinned
//! `angt/secret` commit `e98103def4e062a6f9a8fa5e7693abe15f20817a`):
//!
//! - `dump` bypasses TOTP ONLY. Terminal rendering applies to BOTH `show`
//!   and `dump`: on a console, non-printable values are Base64-encoded
//!   (standard alphabet, `=` padding, no line wraps) and a newline is
//!   appended; printable values are written raw + newline. Redirected:
//!   exact original non-TOTP bytes, no added newline, for both commands.
//! - The console newline is a SEPARATE write after the body — upstream's
//!   own shape (`s_write(1, value, len)` then `if (isatty(1)) s_write(1,
//!   "\n", 1)`) — so the stdout byte stream is unchanged while raw bodies
//!   BORROW the value with zero copies. Transformed bodies (Base64
//!   renders, TOTP digits) live in zeroizing [`SecretBytes`] owners erased
//!   on drop — including error and unwind paths; no secret render is ever
//!   left behind in an ordinary heap `Vec`.
//! - `show` additionally dispatches to TOTP for names containing `"totp"`
//!   (case-sensitive substring; `"totp32"` wins), writing exactly the 6
//!   ASCII digits; the console newline still applies, the redirected path
//!   writes exactly the 6 digits and nothing else (upstream `s_show`:
//!   `s_write(1, totp.b, 6)` then the final `isatty(1)` newline).
//! - On an invalid TOTP secret upstream dies with `Fatal: Invalid secret`
//!   (exit 1) BEFORE writing any bytes. That fatal path is the CLI main
//!   layer's contract (plan §4, `Error::INVALID_TOTP`); this module emits
//!   the empty byte string for that case so no partial output is produced.

use std::ptr;

use windows_sys::Win32::Foundation::{HANDLE, INVALID_HANDLE_VALUE};
use windows_sys::Win32::Storage::FileSystem::WriteFile;
use windows_sys::Win32::System::Console::{GetStdHandle, STD_ERROR_HANDLE, STD_OUTPUT_HANDLE};
use wsecret_core::error::Error;
use wsecret_core::session::SecretBytes;
use wsecret_core::totp::totp_for;

/// Upstream `strstr(out.name, "totp")` gate of `s_show`: case-sensitive
/// substring, anywhere in the name. Matches upstream `strstr` semantics
/// (including the empty needle, which we never pass).
fn contains(hay: &[u8], needle: &[u8]) -> bool {
    needle.len() <= hay.len() && hay.windows(needle.len()).any(|w| w == needle)
}

/// Upstream `s_printable` (exact port, `secret.c` L329-350): the permissive
/// byte predicate, NOT strict UTF-8 validation.
///
/// Accepts printable ASCII `0x20..=0x7e`, `\n`, `\t`, and UTF-8 sequences of
/// a lead byte `0xc2..=0xf4` followed by 1..3 continuation bytes
/// `0x80..=0xbf` (continuation count `1 + (c >= 0xc2) + (c >= 0xe0) +
/// (c >= 0xf0)`). Consequently NOT every overlong sequence or surrogate
/// encoding is rejected — a lead byte whose sequence merely has the right
/// continuation count passes, exactly as upstream.
pub fn s_printable(value: &[u8]) -> bool {
    let mut pos = 0usize;
    while pos < value.len() {
        let c = value[pos];
        pos += 1;

        if (c >= b' ' && c <= b'~') || c == b'\n' || c == b'\t' {
            continue;
        }

        if !(0xc2..=0xf4).contains(&c) {
            return false;
        }

        // Upstream: `1u + (c >= 0xc2) + (c >= 0xe0) + (c >= 0xf0)` with
        // `c` already known `>= 0xc2`, i.e. 2 for 2-byte leads, 3 for
        // 3-byte leads, 4 for 4-byte leads (bytes total incl. the lead).
        let n = 1usize + 1 + usize::from(c >= 0xe0) + usize::from(c >= 0xf0);

        for _ in 1..n {
            if pos == value.len() {
                return false;
            }
            let d = value[pos];
            pos += 1;
            if d.wrapping_sub(0x80) > 0x3f {
                return false;
            }
        }
    }
    true
}

/// Base64 length of a render of `value_len` bytes (4 chars per 3-byte
/// group, `=`-padded).
fn base64_len(value_len: usize) -> usize {
    value_len.div_ceil(3) * 4
}

/// Standard Base64 (RFC 4648 alphabet `A-Za-z0-9+/`, `=` padding), exact
/// port of upstream's per-3-byte-group loop in `s_show`: every group emits
/// 4 characters, incomplete final groups are zero-padded on the right and
/// the unused positions are `=`.
pub fn base64_encode(value: &[u8]) -> Vec<u8> {
    let mut out = vec![0u8; base64_len(value.len())];
    base64_encode_into(value, &mut out);
    out
}

/// [`base64_encode`] into a caller-owned buffer of exactly
/// [`base64_len`]`(value.len())` bytes. The render path uses this to
/// encode straight into a zeroizing [`SecretBytes`] owner (no transient
/// heap copy of the encoding).
fn base64_encode_into(value: &[u8], out: &mut [u8]) {
    const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ\
                             abcdefghijklmnopqrstuvwxyz\
                             0123456789+/";

    debug_assert_eq!(out.len(), base64_len(value.len()));
    let mut pos = 0usize;
    for chunk in value.chunks(3) {
        let n = chunk.len();
        let mut v: u32 = 0;
        for &b in chunk {
            v = (v << 8) | u32::from(b);
        }
        v <<= 8 * (3 - n);
        for j in 0..=n {
            out[pos] = B64[(v >> (18 - 6 * j)) as usize & 63];
            pos += 1;
        }
        for _ in (n + 1)..=3 {
            out[pos] = b'=';
            pos += 1;
        }
    }
}

/// One rendered `show`/`dump` body plus its console-newline flag (plan
/// §1.11).
///
/// The CLI writes [`Rendered::as_slice`] and then, when
/// [`Rendered::newline`] is set, a separate `"\n"` — upstream's own write
/// shape (`secret.c` `s_show` / `s_normalize_and_show`), so the stdout byte
/// stream is unchanged while raw bodies borrow the value with ZERO copies.
pub struct Rendered<'a> {
    body: Body<'a>,
    newline: bool,
}

/// Where a rendered body's bytes live.
enum Body<'a> {
    /// The original value bytes, borrowed and written as-is: no copy of
    /// secret material.
    Raw(&'a [u8]),
    /// A transformed render of the value (Base64 on a console, or the 6
    /// TOTP digits) in a zeroizing [`SecretBytes`] owner. Transient secret
    /// material is erased on drop — including error and unwind paths.
    Owned(SecretBytes),
}

impl Rendered<'_> {
    /// The exact body bytes to write before the optional newline.
    pub fn as_slice(&self) -> &[u8] {
        match &self.body {
            Body::Raw(bytes) => bytes,
            Body::Owned(secret) => secret.as_slice(),
        }
    }

    /// Whether a `\n` must be written after the body (console only; always
    /// false on the invalid-TOTP sentinel).
    pub fn newline(&self) -> bool {
        self.newline
    }

    /// Whether the body is empty (the invalid-TOTP sentinel: the caller
    /// must fatal `Invalid secret` before writing anything).
    pub fn is_empty(&self) -> bool {
        self.as_slice().is_empty()
    }
}

/// Renders one `show`/`dump` body (plan §1.11); the console newline is a
/// separate write driven by [`Rendered::newline`].
///
/// - `dump == true` bypasses the TOTP dispatch ONLY.
/// - Console (`is_console == true`): TOTP names → 6 digits; otherwise raw
///   value if [`s_printable`], else Base64. Redirected: TOTP names →
///   exactly the 6 digits; otherwise the exact original bytes.
/// - `show` on a `totp` name whose value is an invalid TOTP secret renders
///   as an EMPTY body with the newline suppressed (upstream prints
///   `Fatal: Invalid secret` and exits 1 before any stdout bytes; that
///   fatal is the CLI layer's job).
/// - Raw bodies borrow `value` directly (zero copies); Base64 and TOTP
///   bodies are produced in zeroizing owners.
pub fn render_value<'a>(
    value: &'a [u8],
    dump: bool,
    name: &[u8],
    is_console: bool,
) -> Result<Rendered<'a>, Error> {
    let unix_now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    render_value_at(value, dump, name, is_console, unix_now)
}

/// [`render_value`] with the unix timestamp injected (upstream samples
/// `time(NULL)` inside `s_show`; `totp_for` derives `counter = unix_now/30`).
/// Tests pin `unix_now` to a fixed window for determinism.
fn render_value_at<'a>(
    value: &'a [u8],
    dump: bool,
    name: &[u8],
    is_console: bool,
    unix_now: u64,
) -> Result<Rendered<'a>, Error> {
    if !dump && contains(name, b"totp") {
        return match totp_for(name, value, unix_now) {
            // The 6 digits are derived secret material: held in a zeroizing
            // owner until the write completes.
            Some(code) => Ok(Rendered {
                body: Body::Owned(SecretBytes::from_slice(&code)?),
                newline: is_console,
            }),
            // Fatal path reserved for the caller (§4 `INVALID_TOTP`);
            // nothing at all reaches stdout before that fatal.
            None => Ok(Rendered {
                body: Body::Raw(&[]),
                newline: false,
            }),
        };
    }
    if is_console && !s_printable(value) {
        // Base64 is a transformed copy of the value: encode straight into a
        // zeroizing owner (no transient heap `Vec` of the encoding).
        let mut encoded = SecretBytes::new(base64_len(value.len()))?;
        base64_encode_into(value, encoded.as_mut_slice());
        return Ok(Rendered {
            body: Body::Owned(encoded),
            newline: true,
        });
    }
    // Raw output (printable on a console, anything redirected): borrow the
    // value bytes directly — zero copies.
    Ok(Rendered {
        body: Body::Raw(value),
        newline: is_console,
    })
}

/// Writes `bytes` to stdout as raw bytes: no CRT text mode, no CRLF
/// translation, no code-page conversion, no BOM (upstream `s_write(1, …)`
/// is a plain byte write). This deliberately bypasses `std::io::stdout()`,
/// whose Windows console path converts UTF-8 to UTF-16 (`WriteConsoleW`) —
/// that would corrupt arbitrary bytes that [`s_printable`] accepts (e.g.
/// overlong sequences). A direct `WriteFile` on the stdout handle is the
/// faithful `write(1, …)` equivalent. Short writes are retried until the
/// buffer is fully consumed; errors are reported to the caller (the plan §4
/// decision to replace upstream's silent `s_write` truncation with error
/// reporting).
pub fn write_stdout(bytes: &[u8]) -> std::io::Result<()> {
    // SAFETY: `GetStdHandle` is a plain query with a constant argument.
    let handle = unsafe { GetStdHandle(STD_OUTPUT_HANDLE) };
    if handle.is_null() || handle == INVALID_HANDLE_VALUE {
        return Err(std::io::Error::other("stdout handle is not available"));
    }
    write_handle(handle, bytes)
}

/// Writes `bytes` to stderr as raw bytes — same contract as
/// [`write_stdout`] (`WriteFile` on `STD_ERROR_HANDLE` via the same
/// [`write_handle`] loop): no CRT text mode, CRLF translation, code-page
/// conversion or BOM. This matters for `Fatal: …` lines carrying raw
/// (possibly non-UTF-8) name bytes: `std::io::stderr()`'s console path
/// transcodes UTF-8 to UTF-16 (`WriteConsoleW`) and would corrupt them.
pub fn write_stderr(bytes: &[u8]) -> std::io::Result<()> {
    // SAFETY: `GetStdHandle` is a plain query with a constant argument.
    let handle = unsafe { GetStdHandle(STD_ERROR_HANDLE) };
    if handle.is_null() || handle == INVALID_HANDLE_VALUE {
        return Err(std::io::Error::other("stderr handle is not available"));
    }
    write_handle(handle, bytes)
}

/// `WriteFile` loop over an open synchronous handle (shared by
/// [`write_stdout`], [`write_stderr`] and their tests). No allocation;
/// writes proceed in `u32`-sized chunks with short writes resumed.
fn write_handle(handle: HANDLE, mut bytes: &[u8]) -> std::io::Result<()> {
    while !bytes.is_empty() {
        let chunk = bytes.len().min(u32::MAX as usize);
        let mut written: u32 = 0;
        // SAFETY: `handle` is open and synchronous; `bytes[..chunk]` is valid
        // readable memory for the duration of the call; `&mut written` is a
        // valid out-pointer; a null OVERLAPPED requests synchronous I/O.
        let ok = unsafe {
            WriteFile(
                handle,
                bytes[..chunk].as_ptr(),
                chunk as u32,
                &mut written,
                ptr::null_mut(),
            )
        };
        if ok == 0 {
            return Err(std::io::Error::last_os_error());
        }
        if written == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::WriteZero,
                "stdout write accepted 0 bytes",
            ));
        }
        bytes = &bytes[written as usize..];
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use wsecret_core::totp::{totp, totp32};

    const UNIX_NOW: u64 = 1_234_567_890;

    // --- s_printable ----------------------------------------------------

    #[test]
    fn printable_ascii_and_whitespace_passthrough() {
        assert!(s_printable(b"hello world"));
        assert!(s_printable(b"a\nb\tc"));
        assert!(s_printable(
            b"~ !\"#$%&'()*+,-./0123456789:;<=>?@AZ[\\]^_`az{|}~"
        ));
        assert!(s_printable(b""));
    }

    #[test]
    fn printable_rejects_control_bytes() {
        assert!(!s_printable(b"\x00"));
        assert!(!s_printable(b"ok\x07"));
        assert!(!s_printable(b"\x1f"));
        assert!(!s_printable(b"\x7f")); // DEL, above '~'
    }

    #[test]
    fn printable_rejects_stray_high_bytes() {
        assert!(!s_printable(&[0x80]));
        assert!(!s_printable(&[0xbf]));
        assert!(!s_printable(&[0xc0]));
        assert!(!s_printable(&[0xc1]));
        assert!(!s_printable(&[0xf5]));
        assert!(!s_printable(&[0xff]));
    }

    #[test]
    fn printable_accepts_utf8_lead_and_continuations() {
        // 2-byte lead + continuation
        assert!(s_printable(&[0xc2, 0xa2]));
        // 3-byte lead + 2 continuations
        assert!(s_printable(&[0xe2, 0x82, 0xac]));
        // 4-byte lead + 3 continuations
        assert!(s_printable(&[0xf0, 0x90, 0x8d, 0x88]));
    }

    #[test]
    fn printable_rejects_truncated_sequences_and_bad_continuations() {
        // truncated at end of buffer
        assert!(!s_printable(&[0xc2]));
        assert!(!s_printable(&[0xe2, 0x82]));
        assert!(!s_printable(&[0xf0, 0x90, 0x8d]));
        // non-continuation where a continuation is required
        assert!(!s_printable(&[0xc2, 0x41]));
        assert!(!s_printable(&[0xe2, 0x82, 0x41]));
        assert!(!s_printable(&[0xf0, 0x90, 0x8d, 0x41]));
    }

    #[test]
    fn printable_rejects_embedded_control_or_high_byte() {
        assert!(!s_printable(b"ab\x01"));
        assert!(!s_printable(&[b'a', 0x80]));
    }

    #[test]
    fn printable_keeps_upstream_quirks_not_strict_utf8() {
        // Overlong encoding of '/' (E0 80 AF): valid lead/continuation
        // shape, accepted — NOT rejected as strict UTF-8 validation would.
        assert!(s_printable(&[0xe0, 0x80, 0xaf]));
        // Surrogate U+D800 (ED A0 80): accepted, likewise not rejected.
        assert!(s_printable(&[0xed, 0xa0, 0x80]));
    }

    // --- base64_encode ---------------------------------------------------

    #[test]
    fn base64_empty_is_empty() {
        assert_eq!(base64_encode(b""), b"");
    }

    #[test]
    fn base64_single_byte_remainder_pads_twice() {
        assert_eq!(base64_encode(b"M"), b"TQ==");
    }

    #[test]
    fn base64_two_byte_remainder_pads_once() {
        assert_eq!(base64_encode(b"Ma"), b"TWE=");
    }

    #[test]
    fn base64_three_byte_group_no_padding() {
        assert_eq!(base64_encode(b"Man"), b"TWFu");
    }

    #[test]
    fn base64_full_block_uses_standard_alphabet() {
        assert_eq!(base64_encode(b"foobar"), b"Zm9vYmFy");
    }

    #[test]
    fn base64_high_bytes() {
        assert_eq!(base64_encode(&[0xfb, 0xff]), b"+/8=");
    }

    #[test]
    fn base64_exact_4x_growth() {
        assert_eq!(base64_encode(b"12345"), b"MTIzNDU=");
    }

    // --- render_value: printable passthrough + console newline ----------
    //
    // Every assertion below pins the EXACT stdout byte sequence: the body
    // plus the flagged console newline (the CLI writes the two parts
    // separately, as upstream's two `s_write` calls do).

    /// The exact stdout bytes of a render: body plus the flagged console
    /// newline.
    fn out(rendered: &Rendered<'_>) -> Vec<u8> {
        let mut bytes = rendered.as_slice().to_vec();
        if rendered.newline() {
            bytes.push(b'\n');
        }
        bytes
    }

    /// `out` over [`render_value`] (panics only on the fail-closed
    /// allocation error path).
    fn render(value: &[u8], dump: bool, name: &[u8], is_console: bool) -> Vec<u8> {
        out(&render_value(value, dump, name, is_console).expect("render"))
    }

    /// `out` over [`render_value_at`] with a pinned timestamp.
    fn render_at(
        value: &[u8],
        dump: bool,
        name: &[u8],
        is_console: bool,
        unix_now: u64,
    ) -> Vec<u8> {
        out(&render_value_at(value, dump, name, is_console, unix_now).expect("render"))
    }

    #[test]
    fn raw_bodies_borrow_and_transformed_bodies_are_zeroizing() {
        // Raw output is borrowed directly (zero copies) in every mode.
        let value: &[u8] = b"hello";
        for (dump, console) in [(false, false), (false, true), (true, false), (true, true)] {
            let rendered = render_value(value, dump, b"plain", console).expect("render");
            assert!(
                matches!(&rendered.body, Body::Raw(_)),
                "raw output must borrow the value (dump={dump}, console={console})"
            );
            assert_eq!(rendered.newline(), console);
        }
        // Base64 renders and TOTP digits are transformed secret material:
        // held by the zeroizing owner, never an ordinary `Vec`.
        let rendered = render_value(&[0x00, 0x01, 0x02], false, b"bin", true).expect("render");
        assert!(matches!(&rendered.body, Body::Owned(_)));
        let rendered = render_value_at(b"12345678901234567890", false, b"totp", false, UNIX_NOW)
            .expect("render");
        assert!(matches!(&rendered.body, Body::Owned(_)));
    }

    #[test]
    fn render_printable_console_raw_plus_newline() {
        let name = b"test";
        assert_eq!(render(b"hello\n", false, name, true), b"hello\n\n".to_vec());
    }

    #[test]
    fn render_printable_redirected_exact_bytes_no_newline() {
        let name = b"test";
        assert_eq!(render(b"hello\n", false, name, false), b"hello\n".to_vec());
    }

    // --- render_value: binary -> Base64 on console, raw when redirected --

    #[test]
    fn render_binary_console_base64_plus_newline() {
        let name = b"bin";
        let value: &[u8] = &[0x00, 0x01, 0x02];
        assert_eq!(render(value, true, name, true), b"AAEC\n".to_vec());
    }

    #[test]
    fn render_binary_redirected_raw_bytes_no_newline() {
        let name = b"bin";
        let value: &[u8] = &[0x00, 0x01, 0x02, 0xff];
        assert_eq!(render(value, false, name, false), value.to_vec());
        // dump renders identically when redirected
        assert_eq!(render(value, true, name, false), value.to_vec());
    }

    #[test]
    fn render_empty_value() {
        // console: nothing to Base64, just the newline; redirected: nothing
        assert_eq!(render(b"", false, b"e", true), b"\n".to_vec());
        assert_eq!(render(b"", false, b"e", false), b"".to_vec());
    }

    // --- render_value: TOTP dispatch ------------------------------------

    #[test]
    fn render_show_totp_name_six_digits_console_plus_newline() {
        let name = b"svc/totp";
        let value = b"12345678901234567890";
        // Independent oracle: `totp` over counter UNIX_NOW/30 (the value is
        // a valid 20-byte RFC 4226-style key, so both oracles are defined).
        let code = totp(value, UNIX_NOW / 30).expect("valid key");
        let mut expected = code.to_vec();
        assert_eq!(expected.len(), 6);
        assert!(expected.iter().all(u8::is_ascii_digit));
        expected.push(b'\n');
        assert_eq!(render_at(value, false, name, true, UNIX_NOW), expected);
    }

    #[test]
    fn render_show_totp_name_six_digits_redirected_no_newline() {
        let name = b"totp-key";
        let value = b"12345678901234567890";
        let code = totp(value, UNIX_NOW / 30).expect("valid key");
        assert_eq!(
            render_at(value, false, name, false, UNIX_NOW),
            code.to_vec()
        );
    }

    #[test]
    fn render_totp32_wins_over_totp() {
        let name = b"mytotp32";
        // A valid base32 secret; `totp32` decodes it first, so its code is
        // the base32-dispatched one. Assert the render path used exactly
        // `totp32` and NOT the raw-bytes `totp` route.
        let value = b"MFRGGZDF";
        let code32 = totp32(value, UNIX_NOW / 30).expect("valid base32");
        let code_raw = totp(value, UNIX_NOW / 30).expect("valid key");
        assert_ne!(
            code32, code_raw,
            "fixture must distinguish the two dispatches"
        );
        assert_eq!(
            render_at(value, false, name, false, UNIX_NOW),
            code32.to_vec()
        );
    }

    #[test]
    fn render_totp_name_is_case_sensitive() {
        // "TOTP" does not match: plain value rendering applies.
        let name = b"svc/TOTP";
        let value = b"hello";
        assert_eq!(
            render_at(value, false, name, false, UNIX_NOW),
            value.to_vec()
        );
        assert_eq!(
            render_at(value, false, name, true, UNIX_NOW),
            b"hello\n".to_vec()
        );
    }

    #[test]
    fn render_dump_bypasses_totp_only() {
        let name = b"svc/totp";
        let value = b"12345678901234567890";
        // redirected dump: the original bytes, NOT the 6 digits
        assert_eq!(
            render_at(value, true, name, false, UNIX_NOW),
            value.to_vec()
        );
        // console dump: terminal rendering identical to show's non-TOTP
        // path — printable value written raw + newline (NOT the digits)
        assert_eq!(render_at(value, true, name, true, UNIX_NOW), {
            let mut e = value.to_vec();
            e.push(b'\n');
            e
        });
    }

    #[test]
    fn render_dump_binary_on_console_is_base64() {
        let name = b"totp-bin"; // totp name, but dump bypasses TOTP
        let value: &[u8] = &[0xfb, 0xff, 0x00];
        assert_eq!(
            render_at(value, true, name, true, UNIX_NOW),
            b"+/8A\n".to_vec()
        );
    }

    #[test]
    fn render_show_invalid_totp_secret_renders_empty() {
        // Upstream: `!totp.b[0]` -> `Fatal: Invalid secret`, exit 1, no
        // stdout bytes. The render layer yields an empty byte string with
        // the newline SUPPRESSED (the fatal is the CLI layer's
        // `INVALID_TOTP` contract).
        assert_eq!(
            render_at(b"", false, b"totp", true, UNIX_NOW),
            Vec::<u8>::new()
        );
        assert_eq!(
            render_at(b"", false, b"totp", false, UNIX_NOW),
            Vec::<u8>::new()
        );
        // >64-byte keys are invalid for s_totp as well
        let big = [0xabu8; 65];
        assert_eq!(
            render_at(&big, false, b"totp", true, UNIX_NOW),
            Vec::<u8>::new()
        );
        assert_eq!(
            render_at(&big, false, b"totp", false, UNIX_NOW),
            Vec::<u8>::new()
        );
    }

    #[test]
    fn render_totp_digits_ascii_only() {
        let name = b"x/totp/y";
        let value = b"any-key-1234567890";
        let bytes = render_at(value, false, name, false, UNIX_NOW);
        assert_eq!(bytes.len(), 6);
        assert!(bytes.iter().all(u8::is_ascii_digit));
    }

    // --- C8 show/dump dispatch matrix with exact codes --------------------
    //
    // Codes below are exact KATs at `UNIX_NOW` (counter `UNIX_NOW/30 =
    // 41152263`) cross-checked against an independent HMAC-SHA-1 oracle
    // (Node `crypto`), so dispatch changes that route to the wrong primitive
    // fail with a literal mismatch rather than "some six digits".

    #[test]
    fn c8_show_emits_six_code_bytes_dump_emits_seed_bytes() {
        let value = b"JBSWY3DPEHPK3PXP";
        // `show` on a plain `totp` name: the value IS the raw key.
        assert_eq!(
            render_at(value, false, b"/totp", false, UNIX_NOW),
            b"390074".to_vec()
        );
        // `show` on a `totp32` name: the value is base32-decoded first, so
        // the code differs for the same bytes.
        assert_eq!(
            render_at(value, false, b"/totp32", false, UNIX_NOW),
            b"742275".to_vec()
        );
        // `dump` emits the seed bytes unchanged — both for `totp` and
        // `totp32` names, redirected (no newline) and console (+newline).
        assert_eq!(
            render_at(value, true, b"/totp", false, UNIX_NOW),
            value.to_vec()
        );
        assert_eq!(
            render_at(value, true, b"/totp32", false, UNIX_NOW),
            value.to_vec()
        );
        let mut console = value.to_vec();
        console.push(b'\n');
        assert_eq!(render_at(value, true, b"/totp", true, UNIX_NOW), console);
        // show on console: the same six digits + the console newline.
        assert_eq!(
            render_at(value, false, b"/totp", true, UNIX_NOW),
            b"390074\n".to_vec()
        );
    }

    #[test]
    fn c8_base32_quirks_through_the_render_layer() {
        // Accepted: canonical, `=`-terminated, and the 15-char
        // non-canonical seed (its own pinned code, NOT the 16-char one).
        assert_eq!(
            render_at(b"JBSWY3DPEHPK3PXP", false, b"x/totp32", false, UNIX_NOW),
            b"742275".to_vec()
        );
        assert_eq!(
            render_at(b"JBSWY3DPEHPK3PXP=", false, b"x/totp32", false, UNIX_NOW),
            b"742275".to_vec(),
            "'=' terminates; same code as unpadded"
        );
        assert_eq!(
            render_at(b"JBSWY3DPEHPK3PX", false, b"x/totp32", false, UNIX_NOW),
            b"141085".to_vec(),
            "15-char non-canonical seed accepted (audit P6)"
        );
        // `AB=CD` decodes as `AB` only.
        assert_eq!(
            render_at(b"AB=CD", false, b"x/totp32", false, UNIX_NOW),
            b"112569".to_vec()
        );
        // `MY` trailing partial group zero-padded (66 00).
        assert_eq!(
            render_at(b"MY", false, b"x/totp32", false, UNIX_NOW),
            b"452364".to_vec()
        );
        // Capacity: 102×'A' accepted, 103×'A' → the fatal path renders empty.
        assert_eq!(
            render_at(&[b'A'; 102], false, b"x/totp32", false, UNIX_NOW),
            b"712049".to_vec()
        );
    }

    #[test]
    fn c8_rejected_inputs_render_empty_for_the_fatal_layer() {
        // Lowercase, `0`-containing, `MY\r\n`, and 103×'A' are all upstream
        // `Invalid secret` cases: the render layer must emit NOTHING (the
        // CLI layer turns that into `Fatal: Invalid secret`, exit 1).
        for value in [
            &b"jbswy3dpehpk3pxp"[..],
            &b"JBSWY3DPEHPK3PX0"[..],
            &b"MY\r\n"[..],
            &[b'A'; 103][..],
        ] {
            assert_eq!(
                render_at(value, false, b"x/totp32", false, UNIX_NOW),
                Vec::<u8>::new(),
                "value {value:?}"
            );
        }
    }

    // --- write_stdout: raw byte fidelity ---------------------------------

    #[test]
    fn write_handle_round_trips_raw_bytes_unchanged() {
        use std::os::windows::io::AsRawHandle;

        let path = std::env::temp_dir().join(format!(
            "wsecret-output-test-{}-{}.bin",
            std::process::id(),
            UNIX_NOW
        ));
        // Bytes that a CRT text-mode write or code-page conversion would
        // corrupt: CR/LF pairs, NUL, high bytes, invalid UTF-8.
        let payload: &[u8] = b"a\r\nb\x00\xff\x80\xc0\xe0\x80\xaf";
        {
            let file = std::fs::File::create(&path).expect("create temp file");
            write_handle(file.as_raw_handle() as HANDLE, payload).expect("raw write");
        }
        let read_back = std::fs::read(&path).expect("read back temp file");
        assert_eq!(read_back, payload, "write_handle must not transform bytes");
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn write_handle_reports_errors_and_zero_writes() {
        // An invalid handle must surface as an error (plan §4: silent
        // `s_write` truncation replaced by error reporting).
        assert!(write_handle(INVALID_HANDLE_VALUE, b"x").is_err());
        // Empty buffers are a no-op success (short-circuit, no syscall).
        assert!(write_handle(INVALID_HANDLE_VALUE, b"").is_ok());
    }

    #[test]
    fn write_stdout_empty_buffer_succeeds() {
        assert!(write_stdout(b"").is_ok());
    }

    // --- write_stderr: mirror of write_stdout ---------------------------

    #[test]
    fn write_stderr_round_trips_raw_bytes_unchanged() {
        use std::os::windows::io::AsRawHandle;
        use windows_sys::Win32::System::Console::SetStdHandle;

        let path = std::env::temp_dir().join(format!(
            "wsecret-stderr-test-{}-{}.bin",
            std::process::id(),
            UNIX_NOW
        ));
        // Raw name bytes in a `Fatal:` line: CRLF/NUL/high bytes that
        // WriteConsoleW transcoding would corrupt.
        let payload: &[u8] = b"Fatal: Secret \x00\xff\xc0\xaf not found\r\n";
        let file = std::fs::File::create(&path).expect("create temp file");
        // SAFETY: redirecting the process stderr to an open file handle for
        // the duration of the test; the previous handle is saved and
        // restored in the same test (no other test touches stderr).
        unsafe {
            let saved = GetStdHandle(STD_ERROR_HANDLE);
            assert_ne!(
                SetStdHandle(STD_ERROR_HANDLE, file.as_raw_handle() as HANDLE),
                0,
                "SetStdHandle failed"
            );
            let res = write_stderr(payload);
            assert_ne!(SetStdHandle(STD_ERROR_HANDLE, saved), 0);
            res.expect("raw stderr write");
        }
        drop(file);
        let read_back = std::fs::read(&path).expect("read back temp file");
        assert_eq!(read_back, payload, "write_stderr must not transform bytes");
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn write_stderr_empty_buffer_succeeds() {
        assert!(write_stderr(b"").is_ok());
    }
}
