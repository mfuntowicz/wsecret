//! Console prompting for the `wsecret` CLI (plan §5.4).
//!
//! Behavior port of upstream `s_input` / `s_ask_pass` / `s_do` stdin handling
//! (`secret.c`, pinned `angt/secret` commit
//! `e98103def4e062a6f9a8fa5e7693abe15f20817a`):
//!
//! - Prompts go to `CONIN$`/`CONOUT$` directly (upstream `/dev/tty`), so
//!   redirected stdin stays byte-oriented for secret values.
//! - The console input mode is saved, `ENABLE_ECHO_INPUT` cleared (upstream
//!   `ECHO | ECHONL`), line input kept, and the EXACT saved mode restored via
//!   a guard on every path: success, error, and console-control cancellation.
//! - One `ReadConsoleW` line read; the UTF-16 scratch and its UTF-8
//!   conversion are zeroized (`hydro_memzero`) before return — including the
//!   error paths. No `FlushConsoleInputBuffer` (type-ahead is preserved,
//!   upstream never flushes).
//! - Upstream `s_input` post-read artifacts are reproduced exactly: the
//!   console mode is restored FIRST, then one `"\n"` is written to the
//!   console (upstream `s_write(fd, "\n", 1)` before validation), then the
//!   input is validated.
//! - Validation (upstream `s_input` order): input that filled the read
//!   buffer without a line terminator → [`ConsoleError::InputTooLong`]
//!   (`"Input too long!"`); input ending without a terminator below the
//!   buffer limit (EOF / Ctrl+Z / cancelled read) → empty-input `s_exit(0)`;
//!   any content byte `< 0x20` (tabs, CR, NUL, …) →
//!   [`ConsoleError::InvalidInput`] (`"Invalid input!"`); empty line → the
//!   caller's empty-input policy.
//! - Caps follow upstream byte semantics: `s_ask_pass` reads into
//!   `uint8_t pass[128]` (127 content bytes + newline), the `s_input`
//!   secret path into `uint8_t secret[512]` (511 content bytes + newline).
//! - UTF-8 is the NORMAL console mapping (plan §5.4 audit P5): the line is
//!   decoded UTF-16 → UTF-8 and byte-capped in UTF-8 bytes. Raw-byte
//!   passphrases for legacy locales use [`read_passphrase_hex`] instead —
//!   hex from the console only, never argv/env.
//!
//! This module contains **no `unsafe`** (plan §3.4/audit P10): every Win32
//! call lives in `wsecret-core::windows::console`'s safe facade. The
//! upstream `/dev/tty` `fcntl` write-lock has no `CONIN$` equivalent
//! (console input is serialized by the console itself) — documented
//! divergence, no message is printed for it.

use std::fmt;
use std::io::{self, Read};

use windows_sys::Win32::Foundation::ERROR_OPERATION_ABORTED;
use windows_sys::Win32::System::Console::ENABLE_ECHO_INPUT;
use wsecret_core::windows::console as con;

/// Upstream `s_ask_pass`: `uint8_t pass[128]` — at most 127 content bytes
/// plus the terminating newline.
pub const PASSPHRASE_MAX_BYTES: usize = 127;

/// Interactive secret input (`s_input(secret, sizeof(secret), "Secret: ")`,
/// `sizeof = S_ENTRYSIZE = 512`): at most 511 content bytes plus newline.
pub const SECRET_MAX_BYTES: usize = 511;

/// Redirected-stdin secret input: `s_read(0, secret, sizeof(secret))` reads
/// at most 512 raw bytes; longer input is left unread (upstream splits it).
pub const SECRET_STDIN_MAX_BYTES: usize = 512;

/// `--pass-hex` line cap: 127 secret bytes need at most 254 hex characters.
pub const HEX_MAX_CHARS: usize = 2 * PASSPHRASE_MAX_BYTES;

/// Console failure catalog. [`fmt::Display`] renders the exact upstream
/// message body (the CLI prints `Fatal: {err}` + `exit 1`, matching
/// `s_fatal`); no diagnostic ever carries input bytes.
#[derive(Debug)]
pub enum ConsoleError {
    /// Upstream `s_fatal("Input too long!")`.
    InputTooLong,
    /// Upstream `s_fatal("Invalid input!")`.
    InvalidInput,
    /// `CONIN$` could not be opened, read, or mode-switched — upstream
    /// `s_fatal("/dev/tty: %s", strerror(errno))` shape.
    ConsoleIn(io::Error),
    /// `CONOUT$` could not be opened or written.
    ConsoleOut(io::Error),
}

impl fmt::Display for ConsoleError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ConsoleError::InputTooLong => f.write_str("Input too long!"),
            ConsoleError::InvalidInput => f.write_str("Invalid input!"),
            ConsoleError::ConsoleIn(e) => write!(f, "CONIN$: {e}"),
            ConsoleError::ConsoleOut(e) => write!(f, "CONOUT$: {e}"),
        }
    }
}

impl std::error::Error for ConsoleError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            ConsoleError::ConsoleIn(e) | ConsoleError::ConsoleOut(e) => Some(e),
            _ => None,
        }
    }
}

/// Upstream `isatty(1)` (plan §4): `GetConsoleMode` succeeds on the standard
/// OUTPUT handle. Drives terminal rendering (usage text, Base64, trailing
/// newlines) — never input behavior.
pub fn is_console() -> bool {
    con::stdout_is_console()
}

/// Writes `text` to `CONOUT$` — prompts and echo-suppressed output go to the
/// console, never to (possibly redirected) stdout.
pub fn write_console(text: &str) -> Result<(), ConsoleError> {
    let output = con::open_console_output().map_err(ConsoleError::ConsoleOut)?;
    output.write_text(text).map_err(ConsoleError::ConsoleOut)
}

/// Installs the console-ctrl parity handler once (plan §4: "console-ctrl
/// handler ignoring CTRL_C/CTRL_CLOSE equivalents of the upstream ignored
/// signals where legal"). Upstream's `s_handler` is empty (HUP/INT/QUIT/
/// USR1/USR2/PIPE/ALRM/TERM swallowed, `secret.c:863-897`); the Windows
/// analogue acknowledges CTRL_C/CTRL_BREAK/CTRL_CLOSE/CTRL_LOGOFF/
/// CTRL_SHUTDOWN and continues. A prompt cancelled this way surfaces as the
/// upstream `s_exit(0)` empty-input path. Idempotent.
pub fn install_console_ctrl_handler() -> Result<(), ConsoleError> {
    con::install_ctrl_handler().map_err(ConsoleError::ConsoleIn)
}

/// Prompts for a passphrase on the console with echo suppressed
/// (upstream `s_ask_pass("Passphrase: ")`).
///
/// UTF-8 console mapping: at most [`PASSPHRASE_MAX_BYTES`] bytes. Empty
/// input or EOF/cancel at the prompt is upstream `s_exit(0)`: this function
/// exits the process with code 0 after restoring the console mode and
/// writing the trailing console newline; it does not return in that case.
pub fn read_passphrase(prompt: &str) -> Result<Vec<u8>, ConsoleError> {
    let line = read_line_console(prompt, PASSPHRASE_MAX_BYTES)?;
    Ok(passphrase_from_line(line).unwrap_or_else(|ExitZero| std::process::exit(0)))
}

/// `--pass-hex` raw-byte passphrase entry (plan §5.4 audit P5): a
/// non-echoing console line of hex digits decoded into a zeroizing buffer —
/// byte-exact entry for legacy-locale passphrases (e.g. raw byte `E9` from a
/// Latin-1 Unix terminal). Used for unlock AND confirmation. The value comes
/// from the console only, never argv/env.
///
/// Decoding: `[0-9a-fA-F]` pairs only; odd length or any other character →
/// [`ConsoleError::InvalidInput`]; more than [`HEX_MAX_CHARS`] characters →
/// [`ConsoleError::InputTooLong`]; empty input or EOF/cancel → `s_exit(0)`
/// (an empty hex value is an empty passphrase, upstream policy).
pub fn read_passphrase_hex(prompt: &str) -> Result<Vec<u8>, ConsoleError> {
    let mut text = match read_line_console(prompt, HEX_MAX_CHARS)? {
        Some(text) if !text.is_empty() => text,
        _ => std::process::exit(0),
    };
    let bytes = decode_hex(&text);
    con::wipe_bytes(&mut text);
    bytes
}

/// Prompts for a secret value (upstream `s_do`).
///
/// - stdin is a console → the interactive `s_input` path: echo suppressed,
///   at most [`SECRET_MAX_BYTES`] bytes, tabs/newlines/control bytes
///   rejected (`Invalid input!`). EOF or a cancelled read at the prompt is
///   upstream `s_exit(0)` and exits here; an empty LINE returns
///   `Ok(vec![])` so the caller applies upstream's `s_do` policy (rename
///   keeps the old value, otherwise `s_exit(0)` — `secret.c:705-708`).
/// - stdin is redirected → raw bytes up to [`SECRET_STDIN_MAX_BYTES`]: NO
///   Unicode normalization, NO CRLF conversion, NO UTF-8 validation, NO
///   control-character rejection (upstream `s_read(0, secret, 512)`).
///   Longer input is left unread, exactly like upstream. EOF returns
///   `Ok(vec![])` (upstream `s_read` yields length 0, `s_do` decides).
pub fn read_secret(prompt: &str) -> Result<Vec<u8>, ConsoleError> {
    if con::stdin_is_console() {
        match read_line_console(prompt, SECRET_MAX_BYTES)? {
            Some(text) => Ok(text),
            None => std::process::exit(0),
        }
    } else {
        read_raw_stream(&mut io::stdin().lock()).map_err(ConsoleError::ConsoleIn)
    }
}

/// Raw redirected-stdin read (upstream `s_read(0, secret, sizeof(secret))`):
/// up to [`SECRET_STDIN_MAX_BYTES`] bytes, EOF-stopped, remainder left
/// unread. Split out so the raw path is unit-testable over any reader.
fn read_raw_stream(src: &mut impl Read) -> io::Result<Vec<u8>> {
    let mut buf = Vec::with_capacity(SECRET_STDIN_MAX_BYTES);
    src.take(SECRET_STDIN_MAX_BYTES as u64)
        .read_to_end(&mut buf)?;
    Ok(buf)
}

/// Marker for the upstream `s_exit(0)` empty-input outcome (see
/// [`passphrase_from_line`]); mapped to `std::process::exit(0)` at the API
/// boundary so the policy stays unit-testable.
#[derive(Debug)]
struct ExitZero;

/// Upstream `s_ask_pass` empty-input policy: a missing line (EOF/cancel) or
/// a zero-length line is `s_exit(0)`; anything else is the passphrase.
fn passphrase_from_line(line: Option<Vec<u8>>) -> Result<Vec<u8>, ExitZero> {
    match line {
        Some(text) if !text.is_empty() => Ok(text),
        _ => Err(ExitZero),
    }
}

/// The upstream `s_input` line discipline over one `ReadConsoleW` read:
/// prompt → echo off → read → mode restore → console `"\n"` → validate.
/// Returns `Ok(None)` for the `s_exit(0)` outcome (EOF / cancelled read),
/// `Ok(Some(bytes))` for a validated line (possibly empty).
fn read_line_console(prompt: &str, max_bytes: usize) -> Result<Option<Vec<u8>>, ConsoleError> {
    let input = con::open_console_input().map_err(ConsoleError::ConsoleIn)?;
    let output = con::open_console_output().map_err(ConsoleError::ConsoleOut)?;

    // Upstream writes the prompt with echo still on, then switches modes.
    output
        .write_text(prompt)
        .map_err(ConsoleError::ConsoleOut)?;
    let mut guard = EchoGuard::suppress(&input).map_err(ConsoleError::ConsoleIn)?;

    // Content of `max_bytes` UTF-8 bytes maps to at most `max_bytes` UTF-16
    // code units (a 4-byte sequence is 2 units); + CRLF + 1 slack so a legal
    // line can never hit the buffer limit, while a longer line necessarily
    // fills the buffer without a terminator — upstream's "Input too long!"
    // trigger (`ret == size` and no `'\n'`, `secret.c:416-419`).
    let mut units = vec![0u16; max_bytes + 3];
    let read = input.read_utf16(&mut units);

    // Upstream restores the mode BEFORE the newline write and validation;
    // `Drop` keeps the restore on any early return below.
    guard.restore().map_err(ConsoleError::ConsoleIn)?;
    output.write_text("\n").map_err(ConsoleError::ConsoleOut)?;

    let n = match read {
        Ok(n) => n,
        // Console-control cancellation (our handler ignores the event):
        // upstream `read()` returns -1/EINTR → `s_exit(0)`.
        Err(e)
            if e.kind() == io::ErrorKind::Interrupted
                || e.raw_os_error() == Some(ERROR_OPERATION_ABORTED as i32) =>
        {
            return Ok(None);
        }
        Err(e) => return Err(ConsoleError::ConsoleIn(e)),
    };
    let decoded = decode_console_line(&units[..n], n == units.len(), max_bytes);
    con::wipe_units(&mut units);
    decoded
}

/// Interprets one raw console line (UTF-16 code units from `ReadConsoleW`)
/// per upstream `s_input`: strip exactly one trailing terminator
/// (`"\r\n"` — `ReadConsoleW` line-input artifact — or `"\n"`), then the
/// too-long / EOF / control-character rules over the UTF-8 bytes.
///
/// `full` is true when the read filled the whole buffer (the upstream
/// `ret == size` condition). `Ok(None)` = EOF mid-line below the buffer
/// limit (upstream `s_exit(0)`).
fn decode_console_line(
    units: &[u16],
    full: bool,
    max_bytes: usize,
) -> Result<Option<Vec<u8>>, ConsoleError> {
    let mut end = units.len();
    if end > 0 && units[end - 1] == u16::from(b'\n') {
        end -= 1;
        if end > 0 && units[end - 1] == u16::from(b'\r') {
            end -= 1;
        }
    } else if full {
        // Upstream: `buf[len] != '\n'` and `ret == size` → "Input too long!".
        return Err(ConsoleError::InputTooLong);
    } else {
        // Upstream: `buf[len] != '\n'` below the limit (Ctrl+Z/EOF) →
        // `s_exit(0)`.
        return Ok(None);
    }

    // UTF-16 → UTF-8 into a controlled buffer we can wipe on every path
    // (`String::from_utf16` would drop an unzeroized partial copy on error).
    let mut bytes = Vec::with_capacity(max_bytes + 4);
    let mut scratch = [0u8; 4];
    for unit in char::decode_utf16(units[..end].iter().copied()) {
        match unit {
            Ok(ch) => {
                let len = ch.encode_utf8(&mut scratch).len();
                bytes.extend_from_slice(&scratch[..len]);
            }
            Err(_) => {
                con::wipe_bytes(&mut scratch);
                con::wipe_bytes(&mut bytes);
                return Err(ConsoleError::InvalidInput);
            }
        }
        if bytes.len() > max_bytes {
            break;
        }
    }
    con::wipe_bytes(&mut scratch);
    if bytes.len() > max_bytes {
        // The UTF-8 analog of upstream's buffer-full trigger.
        con::wipe_bytes(&mut bytes);
        return Err(ConsoleError::InputTooLong);
    }
    if bytes.iter().any(|&b| b < b' ') {
        // Upstream: `buf[i] < ' '` → "Invalid input!" (tabs, CR, NUL, …).
        con::wipe_bytes(&mut bytes);
        return Err(ConsoleError::InvalidInput);
    }
    Ok(Some(bytes))
}

/// `--pass-hex` decoding: `[0-9a-fA-F]` pairs (upper and lower case), empty
/// input decodes to zero bytes. Odd length or a non-hex character is
/// [`ConsoleError::InvalidInput`]; the partial output is zeroized on the
/// error path. The caller wipes `text` (it holds the secret in hex form).
fn decode_hex(text: &[u8]) -> Result<Vec<u8>, ConsoleError> {
    if text.len() % 2 != 0 {
        return Err(ConsoleError::InvalidInput);
    }
    let mut out = Vec::with_capacity(text.len() / 2);
    for pair in text.chunks_exact(2) {
        match (hex_digit(pair[0]), hex_digit(pair[1])) {
            (Ok(hi), Ok(lo)) => out.push((hi << 4) | lo),
            _ => {
                con::wipe_bytes(&mut out);
                return Err(ConsoleError::InvalidInput);
            }
        }
    }
    Ok(out)
}

fn hex_digit(c: u8) -> Result<u8, ConsoleError> {
    match c {
        b'0'..=b'9' => Ok(c - b'0'),
        b'a'..=b'f' => Ok(c - b'a' + 10),
        b'A'..=b'F' => Ok(c - b'A' + 10),
        _ => Err(ConsoleError::InvalidInput),
    }
}

/// Upstream's mode tweak over a saved console mode: clear `ECHO` (the
/// `ECHO | ECHONL` pair, `secret.c:411`); everything else — notably
/// `ENABLE_LINE_INPUT` and `ENABLE_PROCESSED_INPUT` — is kept.
fn suppressed_mode(saved: u32) -> u32 {
    saved & !ENABLE_ECHO_INPUT
}

/// Minimal console-mode surface so echo suppression and its restoration are
/// unit-testable without a real console (the real impl is
/// [`con::ConsoleInput`]).
trait ModeIo {
    fn get_mode(&self) -> io::Result<u32>;
    fn set_console_mode(&self, mode: u32) -> io::Result<()>;
}

impl ModeIo for con::ConsoleInput {
    fn get_mode(&self) -> io::Result<u32> {
        self.mode()
    }
    fn set_console_mode(&self, mode: u32) -> io::Result<()> {
        self.set_mode(mode)
    }
}

/// Echo-suppression guard (plan §5.4: "restore exact mode via guard on all
/// paths"). [`EchoGuard::restore`] is the explicit restore (its error is
/// reportable); [`Drop`] restores whatever is left, so success, error and
/// console-control cancellation all end with the exact saved mode.
struct EchoGuard<'a, M: ModeIo> {
    io: &'a M,
    saved: u32,
    restored: bool,
}

impl<'a, M: ModeIo> EchoGuard<'a, M> {
    /// Saves the current mode and clears echo input.
    fn suppress(io: &'a M) -> io::Result<Self> {
        let saved = io.get_mode()?;
        io.set_console_mode(suppressed_mode(saved))?;
        Ok(Self {
            io,
            saved,
            restored: false,
        })
    }

    /// Restores the exact saved mode once; later calls (and `Drop`) are
    /// no-ops.
    fn restore(&mut self) -> io::Result<()> {
        if !self.restored {
            self.io.set_console_mode(self.saved)?;
            self.restored = true;
        }
        Ok(())
    }
}

impl<M: ModeIo> Drop for EchoGuard<'_, M> {
    fn drop(&mut self) {
        if !self.restored {
            let _ = self.io.set_console_mode(self.saved);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    /// Recording console-mode fake: exercises set/restore without a console.
    #[derive(Default)]
    struct FakeConsole {
        mode: Cell<u32>,
        sets: Cell<u32>,
    }

    impl ModeIo for FakeConsole {
        fn get_mode(&self) -> io::Result<u32> {
            Ok(self.mode.get())
        }
        fn set_console_mode(&self, mode: u32) -> io::Result<()> {
            self.mode.set(mode);
            self.sets.set(self.sets.get() + 1);
            Ok(())
        }
    }

    fn line(text: &str) -> Vec<u16> {
        text.encode_utf16().collect()
    }

    // --- echo suppression: mode set / exact restore --------------------

    #[test]
    fn echo_suppression_clears_echo_keeps_line_input() {
        // ECHO(4) | LINE(2) | PROCESSED(1) | EXTENDED(8).
        let s = suppressed_mode(0x000F);
        assert_eq!(s & ENABLE_ECHO_INPUT, 0, "echo cleared");
        assert_eq!(s & 0x0002, 0x0002, "line input kept");
        assert_eq!(s & 0x0001, 0x0001, "processed input kept");
        assert_eq!(s & 0x0008, 0x0008, "extended flags kept");
        // ECHO already clear: mode unchanged.
        assert_eq!(suppressed_mode(0x0003), 0x0003);
    }

    #[test]
    fn echo_guard_sets_suppressed_and_restores_exact_mode() {
        let fake = FakeConsole::default();
        fake.mode.set(0x000F);
        {
            let mut guard = EchoGuard::suppress(&fake).unwrap();
            assert_eq!(fake.mode.get(), 0x000F & !ENABLE_ECHO_INPUT);
            guard.restore().unwrap();
            assert_eq!(fake.mode.get(), 0x000F);
        }
        // Drop after explicit restore must not touch the mode again.
        assert_eq!(fake.mode.get(), 0x000F);
        assert_eq!(fake.sets.get(), 2);
    }

    #[test]
    fn console_mode_restored_on_error_path() {
        // The error path (read failure, cancellation) returns early with the
        // guard still alive: Drop restores the exact saved mode.
        let fake = FakeConsole::default();
        fake.mode.set(0x0007);
        {
            let guard = EchoGuard::suppress(&fake).unwrap();
            assert_eq!(fake.mode.get(), 0x0003);
            drop(guard); // simulate early return without explicit restore
        }
        assert_eq!(fake.mode.get(), 0x0007);
    }

    #[test]
    fn drop_restore_is_idempotent() {
        let fake = FakeConsole::default();
        fake.mode.set(0x000F);
        let mut guard = EchoGuard::suppress(&fake).unwrap();
        guard.restore().unwrap();
        drop(guard);
        assert_eq!(fake.sets.get(), 2, "exactly one suppress + one restore");
    }

    // --- UTF-8 conversion and line interpretation ---------------------

    #[test]
    fn utf16_line_converts_to_utf8() {
        // é = U+00E9 → C3 A9; 😀 = U+1F600 (surrogate pair) → F0 9F 98 80.
        let mut units = vec![0x00E9, 0xD83D, 0xDE00];
        units.extend(line("\r\n"));
        let out = decode_console_line(&units, false, 127).unwrap().unwrap();
        assert_eq!(out, [0xC3, 0xA9, 0xF0, 0x9F, 0x98, 0x80]);
    }

    #[test]
    fn line_terminators_are_stripped_exactly_once() {
        assert_eq!(
            decode_console_line(&line("abc\r\n"), false, 127)
                .unwrap()
                .unwrap(),
            b"abc"
        );
        assert_eq!(
            decode_console_line(&line("abc\n"), false, 127)
                .unwrap()
                .unwrap(),
            b"abc"
        );
        // "abc" + CR + Enter: the content CR survives the strip → rejected.
        assert!(matches!(
            decode_console_line(&line("abc\r\r\n"), false, 127),
            Err(ConsoleError::InvalidInput)
        ));
    }

    #[test]
    fn invalid_utf16_is_invalid_input() {
        // Lone trailing high surrogate cannot map to UTF-8.
        let mut units = vec![0x0061, 0xD83D];
        units.extend(line("\r\n"));
        assert!(matches!(
            decode_console_line(&units, false, 127),
            Err(ConsoleError::InvalidInput)
        ));
    }

    // --- control-char rejection ----------------------------------------

    #[test]
    fn control_characters_are_rejected() {
        for bad in ["ab\tc", "a\0b", "a\nb", "a\rb", "a\x1bc"] {
            let mut units = line(bad);
            units.extend(line("\r\n"));
            assert!(
                matches!(
                    decode_console_line(&units, false, 511),
                    Err(ConsoleError::InvalidInput)
                ),
                "expected rejection for {bad:?}"
            );
        }
    }

    #[test]
    fn printable_and_high_bytes_are_accepted() {
        // Upstream rejects only bytes < 0x20: DEL, Latin-1 bytes pass.
        let mut units = line("a\x7f\u{80}");
        units.extend(line("\r\n"));
        let out = decode_console_line(&units, false, 511).unwrap().unwrap();
        assert_eq!(out, [0x61, 0x7F, 0xC2, 0x80]);
    }

    // --- max-length enforcement ---------------------------------------

    #[test]
    fn passphrase_accepts_127_bytes_and_rejects_128() {
        let max = PASSPHRASE_MAX_BYTES;
        let mut units = vec![u16::from(b'a'); max];
        units.extend(line("\r\n"));
        assert_eq!(
            decode_console_line(&units, false, max)
                .unwrap()
                .unwrap()
                .len(),
            max
        );

        let mut units = vec![u16::from(b'a'); max + 1];
        units.extend(line("\r\n"));
        assert!(matches!(
            decode_console_line(&units, false, max),
            Err(ConsoleError::InputTooLong)
        ));
    }

    #[test]
    fn utf8_byte_cap_applies_not_codepoint_cap() {
        // 128 × é = 128 code units but 256 UTF-8 bytes > 127 → too long.
        let mut units = vec![0x00E9u16; 128];
        units.extend(line("\r\n"));
        assert!(matches!(
            decode_console_line(&units, false, PASSPHRASE_MAX_BYTES),
            Err(ConsoleError::InputTooLong)
        ));
    }

    #[test]
    fn buffer_full_without_terminator_is_too_long() {
        // Upstream `ret == size` with no '\n' → "Input too long!".
        let units = vec![u16::from(b'x'); 64];
        assert!(matches!(
            decode_console_line(&units, true, 64),
            Err(ConsoleError::InputTooLong)
        ));
    }

    #[test]
    fn eof_mid_line_below_limit_is_exit_path() {
        // Partial line, buffer not full → upstream `s_exit(0)` (Ok(None)).
        let units = vec![u16::from(b'x'); 5];
        assert!(decode_console_line(&units, false, 64).unwrap().is_none());
        // And a completely empty read likewise.
        assert!(decode_console_line(&[], false, 64).unwrap().is_none());
    }

    #[test]
    fn empty_line_is_some_empty() {
        // Empty line: the caller's policy decides (passphrase exits 0,
        // secret lets `s_do` keep the old value or exit 0).
        let out = decode_console_line(&line("\r\n"), false, 511).unwrap();
        assert_eq!(out.unwrap(), Vec::<u8>::new());
    }

    // --- empty-input exit-0 path --------------------------------------

    #[test]
    fn empty_input_maps_to_exit_zero() {
        assert!(
            passphrase_from_line(None).is_err(),
            "EOF/cancel → s_exit(0)"
        );
        assert!(
            passphrase_from_line(Some(Vec::new())).is_err(),
            "empty line → s_exit(0)"
        );
        assert_eq!(passphrase_from_line(Some(b"x".to_vec())).unwrap(), b"x");
    }

    // --- hex decoding --------------------------------------------------

    #[test]
    fn hex_decodes_valid_pairs() {
        assert_eq!(decode_hex(b"e9").unwrap(), [0xE9]);
        assert_eq!(decode_hex(b"00FF").unwrap(), [0x00, 0xFF]);
        assert_eq!(decode_hex(b"aB").unwrap(), [0xAB]);
    }

    #[test]
    fn hex_rejects_invalid_and_odd_length() {
        assert!(matches!(decode_hex(b"zz"), Err(ConsoleError::InvalidInput)));
        assert!(matches!(decode_hex(b"0g"), Err(ConsoleError::InvalidInput)));
        assert!(matches!(
            decode_hex(b"e90"),
            Err(ConsoleError::InvalidInput)
        ));
        assert!(matches!(decode_hex(b" "), Err(ConsoleError::InvalidInput)));
    }

    #[test]
    fn hex_empty_input_decodes_to_zero_bytes() {
        assert!(decode_hex(b"").unwrap().is_empty());
    }

    #[test]
    fn hex_line_cap_is_enforced() {
        // 254 hex chars = 127 bytes: accepted; one more pair → too long.
        let mut units = vec![u16::from(b'a'); HEX_MAX_CHARS];
        units.extend(line("\r\n"));
        assert_eq!(
            decode_console_line(&units, false, HEX_MAX_CHARS)
                .unwrap()
                .unwrap()
                .len(),
            HEX_MAX_CHARS
        );
        let mut units = vec![u16::from(b'a'); HEX_MAX_CHARS + 2];
        units.extend(line("\r\n"));
        assert!(matches!(
            decode_console_line(&units, false, HEX_MAX_CHARS),
            Err(ConsoleError::InputTooLong)
        ));
    }

    // --- raw stdin secrets ---------------------------------------------

    #[test]
    fn raw_stdin_read_is_capped_and_unmodified() {
        let data = [0x61u8, 0x0D, 0x0A, 0x00, 0xFF, 0x09];
        let mut cursor = io::Cursor::new(data.as_slice());
        let out = read_raw_stream(&mut cursor).unwrap();
        assert_eq!(
            out, data,
            "no normalization/CRLF/validation on the raw path"
        );

        let big = [0x5Au8; 600];
        let mut cursor = io::Cursor::new(big.as_slice());
        let out = read_raw_stream(&mut cursor).unwrap();
        assert_eq!(
            out.len(),
            SECRET_STDIN_MAX_BYTES,
            "capped at 512, remainder unread"
        );
        assert!(out.iter().all(|&b| b == 0x5A));

        let mut cursor = io::Cursor::new(Vec::new());
        assert!(read_raw_stream(&mut cursor).unwrap().is_empty());
    }

    // --- zeroization ---------------------------------------------------

    #[test]
    fn wipe_helpers_erase_buffers() {
        let mut bytes = vec![0xAAu8; 8];
        con::wipe_bytes(&mut bytes);
        assert!(bytes.iter().all(|&b| b == 0));

        let mut units = vec![0xFFFFu16; 4];
        con::wipe_units(&mut units);
        assert!(units.iter().all(|&u| u == 0));
    }

    #[test]
    fn error_display_matches_catalog() {
        assert_eq!(ConsoleError::InputTooLong.to_string(), "Input too long!");
        assert_eq!(ConsoleError::InvalidInput.to_string(), "Invalid input!");
        let io = std::io::Error::from_raw_os_error(2);
        assert_eq!(
            ConsoleError::ConsoleIn(io).to_string(),
            format!("CONIN$: {}", std::io::Error::from_raw_os_error(2))
        );
    }
}
