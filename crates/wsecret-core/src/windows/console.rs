//! Safe `CONIN$`/`CONOUT$` console adapter (plan §5.4) for the CLI prompt
//! layer. This module is part of the sanctioned `unsafe` whitelist
//! (`wsecret-core::windows`, plan §3.1/audit P10): every `unsafe` block is
//! confined to raw Win32 calls, and the CLI reaches the console only through
//! the safe wrappers below ("the console adapter used by the CLI THROUGH this
//! module's safe facade" — plan §3.4).
//!
//! Scope is deliberately thin: handle lifetime, console-mode get/set, one
//! UTF-16 line read, UTF-16 text write, tty-ness probes, and the console-ctrl
//! handler. All prompt policy (echo suppression, caps, validation, hex entry)
//! lives in the CLI's `console` module.

use std::io;
use std::ptr;
use std::sync::atomic::{AtomicBool, Ordering};

use windows_sys::Win32::Foundation::{
    CloseHandle, GENERIC_READ, GENERIC_WRITE, HANDLE, INVALID_HANDLE_VALUE, WAIT_OBJECT_0,
};
use windows_sys::Win32::Storage::FileSystem::{CreateFileW, FILE_SHARE_READ, FILE_SHARE_WRITE};
use windows_sys::Win32::System::Console::{
    ENABLE_ECHO_INPUT, ENABLE_EXTENDED_FLAGS, ENABLE_LINE_INPUT, ENABLE_PROCESSED_INPUT,
    ENABLE_QUICK_EDIT_MODE, GetConsoleMode, GetStdHandle, INPUT_RECORD, KEY_EVENT, ReadConsoleInputW,
    ReadConsoleW, STD_INPUT_HANDLE, STD_OUTPUT_HANDLE, SetConsoleCtrlHandler, SetConsoleMode,
    WriteConsoleW,
};
use windows_sys::Win32::System::Threading::WaitForSingleObject;

/// `CreateFileW` disposition `OPEN_EXISTING` (winbase.h constant; same
/// local definition as `file.rs`).
const OPEN_EXISTING: u32 = 3;

/// An open console input handle (`CONIN$`), closed on drop. Independent of
/// the process's stdin, so prompts work while stdin is redirected
/// (upstream's `/dev/tty` replacement semantics).
pub struct ConsoleInput {
    handle: HANDLE,
}

/// An open console output handle (`CONOUT$`), closed on drop.
pub struct ConsoleOutput {
    handle: HANDLE,
}

impl Drop for ConsoleInput {
    fn drop(&mut self) {
        // SAFETY: `handle` is an owned, still-open handle.
        unsafe {
            let _ = CloseHandle(self.handle);
        }
    }
}

impl Drop for ConsoleOutput {
    fn drop(&mut self) {
        // SAFETY: `handle` is an owned, still-open handle.
        unsafe {
            let _ = CloseHandle(self.handle);
        }
    }
}

fn wide(name: &str) -> Vec<u16> {
    name.encode_utf16().chain(std::iter::once(0)).collect()
}

fn open_console_device(name: &str, access: u32) -> io::Result<HANDLE> {
    let w = wide(name);
    // SAFETY: `w` is a NUL-terminated wide name; null security attributes and
    // template handle request the caller defaults; the result is validated
    // before it is wrapped or used.
    let h = unsafe {
        CreateFileW(
            w.as_ptr(),
            access,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            ptr::null(),
            OPEN_EXISTING,
            0,
            ptr::null_mut(),
        )
    };
    if h.is_null() || h == INVALID_HANDLE_VALUE {
        return Err(io::Error::last_os_error());
    }
    Ok(h)
}

/// Opens `CONIN$` read/write (mode changes require a read/write-capable
/// handle on the input buffer).
pub fn open_console_input() -> io::Result<ConsoleInput> {
    let handle = open_console_device("CONIN$", GENERIC_READ | GENERIC_WRITE)?;
    Ok(ConsoleInput { handle })
}

/// Opens `CONOUT$` for `WriteConsoleW`.
pub fn open_console_output() -> io::Result<ConsoleOutput> {
    let handle = open_console_device("CONOUT$", GENERIC_READ | GENERIC_WRITE)?;
    Ok(ConsoleOutput { handle })
}

impl ConsoleInput {
    /// Current console input mode (`GetConsoleMode`).
    pub fn mode(&self) -> io::Result<u32> {
        let mut mode: u32 = 0;
        // SAFETY: `handle` is a live console input handle; `mode` is a valid
        // out pointer.
        if unsafe { GetConsoleMode(self.handle, &mut mode) } == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(mode)
    }

    /// Sets the console input mode (`SetConsoleMode`).
    pub fn set_mode(&self, mode: u32) -> io::Result<()> {
        // SAFETY: `handle` is a live console input handle; `mode` is a plain
        // bit-set value.
        if unsafe { SetConsoleMode(self.handle, mode) } == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    /// Reads one console line as UTF-16 code units (`ReadConsoleW`, line
    /// input). Returns the number of units written into `buf` — the caller's
    /// buffer bounds the read exactly like upstream's `read(fd, buf, size)`.
    ///
    /// A cancelled read (console-control event handled during the call) is
    /// reported as a raw OS error 995 (`ERROR_OPERATION_ABORTED`); the prompt
    /// layer maps it to upstream's `ret <= 0` empty-input path.
    pub fn read_utf16(&self, buf: &mut [u16]) -> io::Result<usize> {
        if buf.is_empty() || buf.len() > u32::MAX as usize {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "console read buffer size",
            ));
        }
        let mut read: u32 = 0;
        // SAFETY: `buf` is valid for `buf.len()` units of exclusive storage;
        // a null read-control pointer requests default line-input behavior.
        let ok = unsafe {
            ReadConsoleW(
                self.handle,
                buf.as_mut_ptr().cast(),
                buf.len() as u32,
                &mut read,
                ptr::null(),
            )
        };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(read as usize)
    }

    /// Reads one MASKED line as UTF-16 code units without any echo and with
    /// bounded waiting — the broker-owned native input primitive (Quick
    /// Access: "broker-owned native input"). Unlike [`Self::read_utf16`]
    /// (line-input `ReadConsoleW`), this reads raw input RECORDS so the read
    /// can be cancelled and time-bounded:
    ///
    /// - echo is suppressed and line editing/quick-edit are disabled for the
    ///   duration (the saved mode is restored on EVERY exit path, including
    ///   errors, via an RAII guard);
    /// - `WaitForSingleObject` slices of 100 ms poll `cancel` and `deadline`
    ///   between reads;
    /// - `'\r'`/`'\n'` submits, backspace edits, Ctrl+Z on an empty line is
    ///   upstream EOF (`s_exit(0)`), Ctrl+C/Ctrl+Break arrives as key `\x03`
    ///   and reports [`MaskedLine::Cancelled`] (the console-control handler
    ///   never sees it because `ENABLE_PROCESSED_INPUT` is cleared);
    /// - every other character accumulates verbatim (control characters
    ///   included) and the PROMPT layer applies upstream's validation
    ///   (`Invalid input!` for bytes `< 0x20`).
    ///
    /// `max_units` is the upstream buffer rule: the `max_units + 1`-st unit
    /// before the terminator is [`MaskedLine::Overflow`] (`Input too long!`).
    /// The returned `Line` buffer is the caller's to zeroize
    /// ([`wipe_units`]); every other outcome wipes the scratch buffer here.
    pub fn read_masked_line(
        &self,
        max_units: usize,
        deadline: std::time::Instant,
        cancel: &dyn Fn() -> bool,
    ) -> io::Result<MaskedLine> {
        let saved = self.mode()?;
        // Suppress echo and line editing; disable quick-edit so a mouse
        // selection cannot block the read; clear processed input so Ctrl+C
        // arrives as a key record we map to cancellation.
        let masked = (saved | ENABLE_EXTENDED_FLAGS)
            & !(ENABLE_ECHO_INPUT | ENABLE_LINE_INPUT | ENABLE_PROCESSED_INPUT | ENABLE_QUICK_EDIT_MODE);
        struct ModeGuard<'a> {
            input: &'a ConsoleInput,
            saved: u32,
        }
        impl Drop for ModeGuard<'_> {
            fn drop(&mut self) {
                let _ = self.input.set_mode(self.saved);
            }
        }
        let _guard = ModeGuard { input: self, saved };
        self.set_mode(masked)?;

        let mut line: Vec<u16> = Vec::new();
        let mut overflow = false;
        let mut records = [INPUT_RECORD::default(); 16];
        loop {
            if cancel() {
                wipe_units(&mut line);
                return Ok(MaskedLine::Cancelled);
            }
            if std::time::Instant::now() >= deadline {
                wipe_units(&mut line);
                return Ok(MaskedLine::TimedOut);
            }
            // SAFETY: `self.handle` is a live console input handle; the
            // record array is valid for 16 exclusive INPUT_RECORD slots.
            let wait = unsafe { WaitForSingleObject(self.handle, 100) };
            if wait != WAIT_OBJECT_0 {
                continue;
            }
            let mut read: u32 = 0;
            // SAFETY: as above; `read` receives the number of records filled.
            let ok = unsafe {
                ReadConsoleInputW(self.handle, records.as_mut_ptr(), records.len() as u32, &mut read)
            };
            if ok == 0 {
                wipe_units(&mut line);
                return Err(io::Error::last_os_error());
            }
            for record in records.iter().take(read as usize) {
                // SAFETY: `EventType` is read before the union arm; the
                // active arm is `KeyEvent` exactly when EventType says so.
                if record.EventType as u32 != KEY_EVENT {
                    continue;
                }
                let key = unsafe { record.Event.KeyEvent };
                if key.bKeyDown == 0 {
                    continue;
                }
                // SAFETY: `uChar`'s active member for key events is
                // `UnicodeChar` (the ASCII member is the same 2 bytes).
                let ch = unsafe { key.uChar.UnicodeChar };
                if ch == 0 {
                    continue; // extended key (arrows, function keys)
                }
                for _ in 0..key.wRepeatCount.max(1) {
                    match ch {
                        // '\r' / '\n' submit the line.
                        0x0D | 0x0A => {
                            if overflow {
                                wipe_units(&mut line);
                                return Ok(MaskedLine::Overflow);
                            }
                            return Ok(MaskedLine::Line(line));
                        }
                        0x08 => {
                            line.pop();
                        }
                        0x1a if line.is_empty() => {
                            wipe_units(&mut line);
                            return Ok(MaskedLine::Eof);
                        }
                        0x03 => {
                            wipe_units(&mut line);
                            return Ok(MaskedLine::Cancelled);
                        }
                        _ => {
                            if line.len() >= max_units {
                                overflow = true;
                            } else {
                                line.push(ch);
                            }
                        }
                    }
                }
            }
        }
    }
}

/// Outcome of [`ConsoleInput::read_masked_line`].
pub enum MaskedLine {
    /// A terminated line (content without the terminator; the caller wipes).
    Line(Vec<u16>),
    /// Ctrl+Z on an empty line / end of input (upstream `s_exit(0)`).
    Eof,
    /// Cancellation: the cancel flag or Ctrl+C/Ctrl+Break.
    Cancelled,
    /// The deadline expired before a terminator.
    TimedOut,
    /// More than `max_units` units before the terminator (upstream
    /// `Input too long!`).
    Overflow,
}

impl ConsoleOutput {
    /// Writes UTF-16 text to the console (`WriteConsoleW`). Short writes are
    /// reported as errors (plan §5.4: no silent truncation on output).
    pub fn write_text(&self, text: &str) -> io::Result<()> {
        let units: Vec<u16> = text.encode_utf16().collect();
        if units.is_empty() {
            return Ok(());
        }
        let mut written: u32 = 0;
        // SAFETY: `units` is valid for `units.len()` code units; the reserved
        // pointer must be null.
        let ok = unsafe {
            WriteConsoleW(
                self.handle,
                units.as_ptr(),
                units.len() as u32,
                &mut written,
                ptr::null(),
            )
        };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        if written as usize != units.len() {
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "short console write",
            ));
        }
        Ok(())
    }
}

/// Overwrites `buf` with zeros via `hydro_memzero` (volatile; never
/// optimized away). Exposed as a safe wrapper so the CLI's prompt scratch
/// buffers can be erased without depending on the crypto FFI crate
/// (plan §5.4: zeroize UTF-16 and converted buffers).
pub fn wipe_bytes(buf: &mut [u8]) {
    libhydrogen_sys::memzero(buf);
}

/// [`wipe_bytes`] for UTF-16 console read buffers (byte view of `buf`).
pub fn wipe_units(buf: &mut [u16]) {
    if buf.is_empty() {
        return;
    }
    // SAFETY: `buf` is exclusively borrowed; `u16` has no padding bytes, so
    // the byte view covers exactly `len * 2` initialized bytes.
    let bytes =
        unsafe { std::slice::from_raw_parts_mut(buf.as_mut_ptr().cast::<u8>(), buf.len() * 2) };
    libhydrogen_sys::memzero(bytes);
}

/// `GetConsoleMode` succeeds on the standard input handle.
pub fn stdin_is_console() -> bool {
    std_handle_is_console(STD_INPUT_HANDLE)
}

/// `GetConsoleMode` succeeds on the standard output handle (the
/// `isatty(1)` equivalent, plan §4).
pub fn stdout_is_console() -> bool {
    std_handle_is_console(STD_OUTPUT_HANDLE)
}

fn std_handle_is_console(which: u32) -> bool {
    // SAFETY: `GetStdHandle` is a pure query; the returned handle is checked
    // before use.
    let h = unsafe { GetStdHandle(which) };
    if h.is_null() || h == INVALID_HANDLE_VALUE {
        return false;
    }
    let mut mode: u32 = 0;
    // SAFETY: `h` is a non-null standard-handle value; `mode` is a valid out
    // pointer. A non-console handle simply fails this call.
    unsafe { GetConsoleMode(h, &mut mode) != 0 }
}

/// Records whether the ignore-handler is installed. A failed install is not
/// recorded, so it can be retried; a benign race installs the pure handler
/// twice (each event is then acknowledged twice — harmless).
static CTRL_INSTALLED: AtomicBool = AtomicBool::new(false);

/// Installs the console-ctrl parity handler (plan §4: "console-ctrl handler
/// ignoring CTRL_C/CTRL_CLOSE equivalents of the upstream ignored signals
/// where legal"). Upstream installs an EMPTY `s_handler` for
/// HUP/INT/QUIT/USR1/USR2/PIPE/ALRM/TERM (signals swallowed, execution
/// continues, `secret.c:885-897`); the Windows analogue acknowledges
/// CTRL_C/CTRL_BREAK/CTRL_CLOSE/CTRL_LOGOFF/CTRL_SHUTDOWN with `TRUE`
/// (event ignored). LOGOFF/SHUTDOWN ignoring is honored only "where legal"
/// (the OS grants a bounded shutdown delay). Idempotent.
pub fn install_ctrl_handler() -> io::Result<()> {
    if CTRL_INSTALLED.load(Ordering::Relaxed) {
        return Ok(());
    }
    // SAFETY: `ignore_ctrl` matches the `PHANDLER_ROUTINE` signature exactly.
    if unsafe { SetConsoleCtrlHandler(Some(ignore_ctrl), 1) } == 0 {
        return Err(io::Error::last_os_error());
    }
    CTRL_INSTALLED.store(true, Ordering::Relaxed);
    Ok(())
}

/// Console-control handler: acknowledges every event (`TRUE` = handled /
/// ignored), matching upstream's empty signal handler. A read cancelled by
/// an event is surfaced by the input API as an interrupted read and taken to
/// upstream's `s_exit(0)` empty-input path by the prompt layer.
unsafe extern "system" fn ignore_ctrl(_ctrl_type: u32) -> i32 {
    1
}
