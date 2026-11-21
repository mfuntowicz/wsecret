//! Native masked input, isolated from the broker's vault and thread registry.
//!
//! [`BrokerConsole`] launches this same executable in `--native-prompt` mode.
//! Only the two prompt pipe ends are inherited. Neither the WinUI shell nor
//! the vault protocol sees prompt bytes. The helper has no session; it owns
//! a reusable Win32 window with a masked `EDIT`, label and OK/Cancel buttons.
//! UI Automation can start provider threads there without adding a single
//! UI thread to the process that holds the session key.
//!
//! Prompt policy is the CLI/upstream behavior ported verbatim:
//!
//! - prompts: `Passphrase: ` ([`PROMPT_PASSPHRASE`]), the empty-partition
//!   confirmation retype ([`PROMPT_CONFIRM`]), `Secret: `
//!   ([`PROMPT_SECRET`]) — same strings as `wsecret-cli`/upstream;
//! - caps: [`PASSPHRASE_MAX_BYTES`] (upstream `s_ask_pass`, 127 content
//!   bytes) and [`SECRET_MAX_BYTES`] (upstream `s_input`, 511 content
//!   bytes); longer input is [`WireStatus::InputInvalid`]
//!   (`Input too long!`);
//! - validation: bytes `< 0x20` (tabs, CR, NUL, …) are rejected
//!   (`Invalid input!`), exactly upstream `buf[i] < ' '`;
//! - empty at the passphrase prompt aborts the unlock
//!   (upstream `s_exit(0)`); an EMPTY value line is returned to the caller,
//!   which applies upstream `s_do` policy (rename keeps the old value,
//!   otherwise no write);
//! - echo is suppressed by the `ES_PASSWORD` edit control (native masking,
//!   accessibility and high-contrast behavior come from the standard
//!   controls); the control is cleared immediately after every read and
//!   every scratch buffer is zeroized ([`wipe_bytes`]/[`wipe_units`]).
//!   Prompt results travel wrapped in [`WipedBytes`], which wipes itself on
//!   every drop path instead of leaving bytes in a freed heap buffer.
//!
//! Keyboard behavior is native dialog behavior (`IsDialogMessageW`): Enter
//! presses the default OK button, Esc cancels, Tab moves focus.
//!
//! The broker polls the result pipe against the original request deadline and
//! cancellation signal. It drains a racing result on abort (wiping its bytes)
//! or destroys the helper before the channel can be reused. The helper is
//! born in a private kill-on-close job, including during its startup handshake.

use std::cell::RefCell;
use std::fs::File;
use std::io::{self, Read, Write};
use std::mem;
use std::os::windows::io::{AsRawHandle, FromRawHandle};
use std::ptr;
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use windows_sys::Win32::Foundation::{
    ERROR_CLASS_ALREADY_EXISTS, HINSTANCE, HWND, LPARAM, LRESULT, WPARAM,
};
use windows_sys::Win32::Graphics::Gdi::{COLOR_WINDOW, DEFAULT_GUI_FONT, GetStockObject, HBRUSH};
use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;
use windows_sys::Win32::System::SystemServices::SS_LEFT;
use windows_sys::Win32::System::Threading::{AttachThreadInput, GetCurrentThreadId};
use windows_sys::Win32::System::Pipes::PeekNamedPipe;
use windows_sys::Win32::UI::Controls::{EM_EMPTYUNDOBUFFER, EM_GETLINE, EM_SETLIMITTEXT};
use windows_sys::Win32::UI::Input::KeyboardAndMouse::SetFocus;
use windows_sys::Win32::UI::WindowsAndMessaging::{
    BS_DEFPUSHBUTTON, BS_PUSHBUTTON, CreateWindowExW, DC_HASDEFID, DefWindowProcW, DestroyWindow,
    DispatchMessageW, DM_GETDEFID, ES_PASSWORD, GetForegroundWindow, GetMessageW,
    GetSystemMetrics, GetWindowThreadProcessId, HMENU, HWND_TOPMOST, IDCANCEL, IDC_ARROW, IDOK,
    IsDialogMessageW, IsWindow, LoadCursorW, MSG,
    PostMessageW, PostQuitMessage, RegisterClassW, SendMessageW,
    SetForegroundWindow, SetWindowPos, SetWindowTextW, ShowWindow, SM_CXSCREEN, SM_CYSCREEN,
    SWP_NOMOVE, SWP_NOSIZE, SW_HIDE, SW_SHOW, TranslateMessage, WINDOW_EX_STYLE, WINDOW_STYLE,
    WNDCLASSW, WM_APP, WM_CLOSE, WM_COMMAND, WM_DESTROY, WM_SETFONT, WS_CAPTION,
    WS_CHILD,
    WS_EX_CLIENTEDGE, WS_EX_TOPMOST, WS_OVERLAPPED, WS_SYSMENU, WS_TABSTOP, WS_VISIBLE,
};
use windows_sys::w;

use wsecret_core::windows::security::{self, HardenedThread};

use crate::protocol::WireStatus;

/// Upstream `s_ask_pass("Passphrase: ")`.
pub const PROMPT_PASSPHRASE: &str = "Passphrase: ";
/// Upstream `s_get_secret`'s no-records retype.
pub const PROMPT_CONFIRM: &str =
    "No secrets stored with this passphrase.\nPlease, retype it to confirm: ";
/// Upstream `s_input(secret, sizeof(secret), "Secret: ")`.
pub const PROMPT_SECRET: &str = "Secret: ";

/// Upstream `s_ask_pass`: `uint8_t pass[128]` — at most 127 content bytes.
pub const PASSPHRASE_MAX_BYTES: usize = 127;
/// Interactive secret input: `s_input` reads into `S_ENTRYSIZE = 512` — at
/// most 511 content bytes.
pub const SECRET_MAX_BYTES: usize = 511;

/// Native-input failure with an optional Win32 error in the response `aux`.
pub struct PromptError {
    pub status: WireStatus,
    pub aux: u16,
}

impl PromptError {
    fn status(status: WireStatus) -> PromptError {
        PromptError { status, aux: 0 }
    }

    fn io(error: io::Error) -> PromptError {
        let aux = error
            .raw_os_error()
            .unwrap_or(0)
            .clamp(0, u16::MAX as i32) as u16;
        PromptError {
            status: WireStatus::NoConsole,
            aux,
        }
    }
}

// ---- prompt window plumbing ----------------------------------------------

/// Window class of the reusable prompt window.
const PROMPT_CLASS: *const u16 = w!("wsecret_broker_prompt");

/// `WM_APP`-based UI-thread requests. The window procedure answers exactly
/// one prompt per [`WM_APP_PROMPT`] and completes an active prompt on the
/// abort messages.
const WM_APP_PROMPT: u32 = WM_APP + 1;
const WM_APP_CANCEL: u32 = WM_APP + 2;
const WM_APP_TIMEOUT: u32 = WM_APP + 3;
const WM_APP_SHUTDOWN: u32 = WM_APP + 4;

/// Child control ids (OK/Cancel use the dialog ids so `IsDialogMessageW`
/// provides Enter/Esc handling).
const ID_EDIT: u32 = 100;
const ID_LABEL: u32 = 101;

/// Bound for creating the helper and receiving its window-ready notification.
const READY_WAIT: Duration = Duration::from_millis(15_000);
/// Poll slice while a prompt is up (deadline/cancellation sampling).
const POLL_SLICE: Duration = Duration::from_millis(50);
/// Bounded wait for prompt teardown after an abort request.
const TEARDOWN_WAIT: Duration = Duration::from_millis(1_000);

/// A prompt result that wipes its bytes on every drop path: delivered to
/// the caller ([`WipedBytes::into_inner`]), queued for a reader that already
/// gave up, or returned inside a failed send.
struct WipedBytes(Vec<u8>);

impl WipedBytes {
    /// Hands the bytes to the caller; the emptied carrier wipes nothing.
    fn into_inner(mut self) -> Vec<u8> {
        mem::take(&mut self.0)
    }
}

impl Drop for WipedBytes {
    fn drop(&mut self) {
        wipe_bytes(&mut self.0);
    }
}

type Outcome = Result<WipedBytes, PromptError>;
type Reply = Sender<Outcome>;
type PendingJob = Arc<Mutex<Option<PromptJob>>>;

/// A queued prompt request: label text, content cap and the reply channel.
struct PromptJob {
    prompt: String,
    max_bytes: usize,
    reply: Reply,
}

/// The prompt currently on screen.
struct ActivePrompt {
    reply: Reply,
    max_bytes: usize,
}

/// UI-thread state. The window procedure runs only on the window's own
/// thread, so a thread-local suffices; every borrow is dropped before any
/// `USER` call that could re-enter the window procedure.
struct UiState {
    pending: Option<PendingJob>,
    active: Option<ActivePrompt>,
    label: HWND,
    edit: HWND,
}

impl UiState {
    const fn new() -> UiState {
        UiState {
            pending: None,
            active: None,
            label: ptr::null_mut(),
            edit: ptr::null_mut(),
        }
    }
}

thread_local! {
    static UI: RefCell<UiState> = RefCell::new(UiState::new());
}

/// One exclusively borrowed result pipe per request, including its abort
/// drain. Neither concurrent nor reentrant callers can consume its result.
pub struct BrokerConsole {
    commands: File,
    replies: RefCell<File>,
    child: launch::Child,
}

impl BrokerConsole {
    /// Launch the protected helper and require its hidden window to be ready.
    pub fn open() -> Result<BrokerConsole, PromptError> {
        let deadline = Instant::now() + READY_WAIT;
        let (commands, replies, child) = launch::spawn().map_err(PromptError::io)?;
        let console = Self { commands, replies: RefCell::new(replies), child };
        let ready = console.wait_reply(
            &mut console.replies.borrow_mut(), wire::READY, 0, deadline, &|| false,
        ).map_err(PromptError::io)?;
        match ready {
            WaitReply::Done(Ok(_)) => Ok(console),
            WaitReply::Done(Err(error)) => Err(error),
            WaitReply::Abort(_) => Err(PromptError::status(WireStatus::NoConsole)),
        }
    }

    /// Passphrase prompt (masked). Empty input or cancellation aborts with
    /// [`WireStatus::Cancelled`] (upstream `s_exit(0)`); the deadline is
    /// [`WireStatus::Timeout`].
    pub fn read_passphrase(
        &self,
        prompt: &str,
        deadline: Instant,
        cancel: &dyn Fn() -> bool,
    ) -> Result<Vec<u8>, PromptError> {
        let bytes = self.read_line(prompt, PASSPHRASE_MAX_BYTES, deadline, cancel)?;
        if bytes.is_empty() {
            Err(PromptError::status(WireStatus::Cancelled))
        } else {
            Ok(bytes)
        }
    }

    /// Secret-value prompt (masked). `Ok` carries the typed bytes, empty for
    /// an EMPTY LINE (the caller applies upstream `s_do` policy);
    /// cancellation is [`WireStatus::Cancelled`] (upstream `s_exit(0)`), the
    /// deadline [`WireStatus::Timeout`].
    pub fn read_secret(
        &self,
        prompt: &str,
        deadline: Instant,
        cancel: &dyn Fn() -> bool,
    ) -> Result<Vec<u8>, PromptError> {
        self.read_line(prompt, SECRET_MAX_BYTES, deadline, cancel)
    }

    /// Stop-and-wait: one prompt gets exactly one result, even if an abort
    /// races OK. An abort is not itself a request for a second result.
    fn read_line(
        &self,
        prompt: &str,
        max_bytes: usize,
        deadline: Instant,
        cancel: &dyn Fn() -> bool,
    ) -> Result<Vec<u8>, PromptError> {
        let mut rd = self.replies.try_borrow_mut()
            .map_err(|_| PromptError::status(WireStatus::Busy))?;
        if let Some(status) = interrupted(deadline, cancel) {
            return Err(PromptError::status(status));
        }
        if self.child.stopped() {
            return Err(PromptError::status(WireStatus::NoConsole));
        }
        if !wire::valid_label(prompt) {
            return Err(PromptError::status(WireStatus::InputInvalid));
        }
        let result = wire::send_prompt(&self.commands, prompt, max_bytes)
            .and_then(|()| self.wait_reply(&mut rd, wire::RESULT, max_bytes, deadline, cancel));
        match result {
            Ok(WaitReply::Done(reply)) => match interrupted(deadline, cancel) {
                // The complete result can be discarded without a wire abort:
                // its window has already been cleared and hidden.
                Some(status) => Err(PromptError::status(status)),
                None => reply.map(WipedBytes::into_inner),
            },
            Ok(WaitReply::Abort(status)) => {
                let kind = if status == WireStatus::Cancelled { wire::CANCEL } else { wire::TIMEOUT };
                let drained = wire::send_header(&self.commands, kind, 0).and_then(|()| {
                    self.wait_reply(&mut rd, wire::RESULT, max_bytes,
                        Instant::now() + TEARDOWN_WAIT, &|| false)
                });
                // A completed result (including typed bytes) drops here.
                // A partial/missing result must never become the next reply.
                if !matches!(drained, Ok(WaitReply::Done(_))) {
                    self.child.stop();
                }
                Err(PromptError::status(status))
            }
            Err(error) => {
                self.child.stop();
                Err(PromptError::io(error))
            }
        }
    }

    fn wait_reply(
        &self,
        rd: &mut File,
        kind: u8,
        max_bytes: usize,
        deadline: Instant,
        cancel: &dyn Fn() -> bool,
    ) -> io::Result<WaitReply> {
        loop {
            if let Some(status) = interrupted(deadline, cancel) {
                return Ok(WaitReply::Abort(status));
            }
            if let Some(reply) = wire::try_reply(rd, kind, max_bytes)? {
                return Ok(WaitReply::Done(reply));
            }
            let slice = deadline.saturating_duration_since(Instant::now()).min(POLL_SLICE);
            if self.child.wait(slice)? {
                // A startup failure can send a diagnostic just before exit.
                return wire::try_reply(rd, kind, max_bytes)?
                    .map(WaitReply::Done)
                    .ok_or_else(|| io::Error::from(io::ErrorKind::BrokenPipe));
            }
        }
    }
}

impl Drop for BrokerConsole {
    fn drop(&mut self) {
        if self.child.stopped() { return; }
        let _ = wire::send_header(&self.commands, wire::SHUTDOWN, 0);
        if !self.child.wait(TEARDOWN_WAIT).unwrap_or(false) {
            self.child.stop();
        }
    }
}

enum WaitReply {
    Done(Outcome),
    Abort(WireStatus),
}

fn interrupted(deadline: Instant, cancel: &dyn Fn() -> bool) -> Option<WireStatus> {
    if cancel() { Some(WireStatus::Cancelled) }
    else if Instant::now() >= deadline { Some(WireStatus::Timeout) }
    else { None }
}

/// Win32 launch boundary. The vault channel launcher retains only a wait
/// handle; here we also need to destroy a nonresponsive UI, even if the
/// broker itself dies. Job membership is assigned atomically at creation.
mod launch {
    use super::*;
    use std::mem::{size_of, size_of_val};
    use std::os::windows::ffi::OsStrExt;
    use std::os::windows::io::OwnedHandle;
    use windows_sys::Win32::Foundation::{
        DuplicateHandle, GetHandleInformation, HANDLE, HANDLE_FLAG_INHERIT,
        SetHandleInformation, WAIT_OBJECT_0, WAIT_TIMEOUT,
    };
    use windows_sys::Win32::Security::{
        DACL_SECURITY_INFORMATION, GetKernelObjectSecurity, SECURITY_ATTRIBUTES,
    };
    use windows_sys::Win32::Storage::FileSystem::{FILE_TYPE_PIPE, GetFileType, SYNCHRONIZE};
    use windows_sys::Win32::System::JobObjects::{
        CreateJobObjectW, JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
        JobObjectExtendedLimitInformation, SetInformationJobObject,
    };
    use windows_sys::Win32::System::Pipes::CreatePipe;
    use windows_sys::Win32::System::SystemInformation::GetSystemWindowsDirectoryW;
    use windows_sys::Win32::System::Threading::{
        CREATE_NO_WINDOW, CREATE_UNICODE_ENVIRONMENT, CreateProcessW, DeleteProcThreadAttributeList,
        EXTENDED_STARTUPINFO_PRESENT, GetCurrentProcess, GetCurrentThread,
        InitializeProcThreadAttributeList, LPPROC_THREAD_ATTRIBUTE_LIST, PROCESS_INFORMATION,
        PROC_THREAD_ATTRIBUTE_HANDLE_LIST, PROC_THREAD_ATTRIBUTE_JOB_LIST, STARTF_USESTDHANDLES,
        STARTUPINFOEXW, UpdateProcThreadAttribute, WaitForSingleObject,
    };

    pub(super) struct Child {
        process: OwnedHandle,
        job: RefCell<Option<OwnedHandle>>,
    }

    impl Child {
        pub(super) fn wait(&self, time: Duration) -> io::Result<bool> {
            let ms = time.as_millis().min(u128::from(u32::MAX - 1)) as u32;
            // SAFETY: owned SYNCHRONIZE handle to the actual child, never a PID lookup.
            match unsafe { WaitForSingleObject(self.process.as_raw_handle(), ms) } {
                WAIT_OBJECT_0 => Ok(true),
                WAIT_TIMEOUT => Ok(false),
                _ => Err(io::Error::last_os_error()),
            }
        }

        pub(super) fn stopped(&self) -> bool {
            self.job.borrow().is_none()
        }

        pub(super) fn stop(&self) {
            // Closing the only job handle kills all members. A closing or
            // wedged UI cannot delay the caller past the bounded final wait.
            drop(self.job.take());
            let _ = self.wait(TEARDOWN_WAIT);
        }
    }

    pub(super) fn pipe() -> io::Result<(File, File)> {
        let (mut rd, mut wr) = (ptr::null_mut(), ptr::null_mut());
        // Non-inheritable at birth. 4 KiB fits the entire stop-and-wait
        // exchange even if one extra abort and shutdown are waiting.
        if unsafe { CreatePipe(&mut rd, &mut wr, ptr::null(), 4096) } == 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: fresh distinct handles, one owning File each.
        Ok(unsafe { (File::from_raw_handle(rd), File::from_raw_handle(wr)) })
    }

    pub(super) fn adopt(rd: usize, wr: usize) -> io::Result<(File, File)> {
        if rd == 0 || wr == 0 || rd == wr { return Err(wire::invalid()); }
        for handle in [rd as HANDLE, wr as HANDLE] {
            let mut flags = 0;
            // Query before adopting arbitrary argument values. The launcher
            // explicitly marked only these two pipe ends inheritable.
            if unsafe { GetFileType(handle) } != FILE_TYPE_PIPE
                || unsafe { GetHandleInformation(handle, &mut flags) } == 0
                || flags & HANDLE_FLAG_INHERIT == 0
            {
                return Err(wire::invalid());
            }
            if unsafe { SetHandleInformation(handle, HANDLE_FLAG_INHERIT, 0) } == 0 {
                return Err(io::Error::last_os_error());
            }
        }
        // SAFETY: the validated, launch-transferred handles have no owner
        // here yet; neither can be inherited onwards.
        Ok(unsafe { (File::from_raw_handle(rd as HANDLE), File::from_raw_handle(wr as HANDLE)) })
    }

    fn kill_job() -> io::Result<OwnedHandle> {
        let handle = unsafe { CreateJobObjectW(ptr::null(), ptr::null()) };
        if handle.is_null() { return Err(io::Error::last_os_error()); }
        // SAFETY: fresh, private and non-inheritable.
        let job = unsafe { OwnedHandle::from_raw_handle(handle) };
        let mut limits = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
        limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        if unsafe {
            SetInformationJobObject(handle, JobObjectExtendedLimitInformation,
                ptr::from_ref(&limits).cast(), size_of_val(&limits) as u32)
        } == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(job)
    }

    /// Use the already verified broker process / calling-thread DACLs at
    /// birth. Waiting until the helper's own startup hardening would leave
    /// already-open same-user process/thread handles unaffected.
    fn birth_dacl(handle: HANDLE) -> io::Result<Vec<usize>> {
        let mut size = 0;
        unsafe {
            GetKernelObjectSecurity(handle, DACL_SECURITY_INFORMATION, ptr::null_mut(), 0, &mut size);
        }
        if size == 0 { return Err(io::Error::last_os_error()); }
        let mut words = vec![0usize; (size as usize).div_ceil(size_of::<usize>())];
        // SAFETY: a pointer-aligned writable buffer of at least `size`
        // bytes; a self-relative descriptor remains valid when returned.
        if unsafe {
            GetKernelObjectSecurity(handle, DACL_SECURITY_INFORMATION,
                words.as_mut_ptr().cast(), size, &mut size)
        } == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(words)
    }

    /// Only SystemRoot for Windows/side-by-side libraries. Do not copy any
    /// parent-provided store, agent, credential or test environment entries.
    const ROOT: &str = "SystemRoot=";
    fn environment() -> io::Result<Vec<u16>> {
        let mut first = 0u16;
        let size = unsafe { GetSystemWindowsDirectoryW(&mut first, 1) };
        if size == 0 { return Err(io::Error::last_os_error()); }
        let mut env = Vec::with_capacity(ROOT.len() + size as usize + 1);
        env.extend(ROOT.encode_utf16());
        env.resize(ROOT.len() + size as usize + 1, 0);
        let n = unsafe { GetSystemWindowsDirectoryW(env[ROOT.len()..].as_mut_ptr(), size) };
        if n == 0 || n >= size { return Err(io::Error::last_os_error()); }
        Ok(env)
    }

    pub(super) fn spawn() -> io::Result<(File, File, Child)> {
        // Explicit fully qualified application name, independent of argv[0],
        // the shell, PATH and the working directory.
        let app: Vec<u16> = std::env::current_exe()?.as_os_str().encode_wide()
            .chain(std::iter::once(0)).collect();
        let env = environment()?;
        let mut proc_dacl = birth_dacl(unsafe { GetCurrentProcess() })?;
        let mut thread_dacl = birth_dacl(unsafe { GetCurrentThread() })?;
        let attributes = |buf: &mut [usize]| SECURITY_ATTRIBUTES {
            nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: buf.as_mut_ptr().cast(),
            bInheritHandle: 0,
        };
        let job = kill_job()?;
        let (rd, commands) = pipe()?;
        let (replies, wr) = pipe()?;
        let handles = [rd.as_raw_handle(), wr.as_raw_handle()];
        for handle in handles {
            if unsafe { SetHandleInformation(handle, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT) } == 0 {
                return Err(io::Error::last_os_error());
            }
        }
        let mut argv: Vec<u16> = format!(
            "wsecret-broker.exe --native-prompt --rd-handle {} --wr-handle {}\0",
            handles[0] as usize, handles[1] as usize,
        ).encode_utf16().collect();
        let jobs = [job.as_raw_handle()];
        let mut pi = PROCESS_INFORMATION::default();
        {
            let mut size = 0;
            unsafe { InitializeProcThreadAttributeList(ptr::null_mut(), 2, 0, &mut size); }
            if size == 0 { return Err(io::Error::last_os_error()); }
            let mut storage = Vec::<usize>::with_capacity(size.div_ceil(size_of::<usize>()));
            let raw = storage.as_mut_ptr().cast();
            if unsafe { InitializeProcThreadAttributeList(raw, 2, 0, &mut size) } == 0 {
                return Err(io::Error::last_os_error());
            }
            struct List(LPPROC_THREAD_ATTRIBUTE_LIST);
            impl Drop for List {
                fn drop(&mut self) {
                    unsafe { DeleteProcThreadAttributeList(self.0); }
                }
            }
            let list = List(raw); // dropped before storage, handles and jobs
            for (key, values) in [(PROC_THREAD_ATTRIBUTE_HANDLE_LIST, handles.as_slice()),
                                  (PROC_THREAD_ATTRIBUTE_JOB_LIST, jobs.as_slice())] {
                if unsafe {
                    UpdateProcThreadAttribute(list.0, 0, key as usize, values.as_ptr().cast(),
                        size_of_val(values), ptr::null_mut(), ptr::null_mut())
                } == 0 {
                    return Err(io::Error::last_os_error());
                }
            }
            let mut si = STARTUPINFOEXW::default();
            si.StartupInfo.cb = size_of::<STARTUPINFOEXW>() as u32;
            si.StartupInfo.dwFlags = STARTF_USESTDHANDLES; // all three slots remain NULL
            si.lpAttributeList = list.0;
            // SAFETY: all buffers, attribute values and security descriptors
            // outlive the call. No elevation, shell or inherited console.
            if unsafe {
                CreateProcessW(app.as_ptr(), argv.as_mut_ptr(), &attributes(&mut proc_dacl),
                    &attributes(&mut thread_dacl), 1,
                    EXTENDED_STARTUPINFO_PRESENT | CREATE_NO_WINDOW | CREATE_UNICODE_ENVIRONMENT,
                    env.as_ptr().cast(), env[ROOT.len()..].as_ptr(), ptr::from_ref(&si).cast(), &mut pi)
            } == 0 {
                return Err(io::Error::last_os_error());
            }
        }
        drop((rd, wr)); // only the helper may own the other sides from now on
        // SAFETY: CreateProcessW created both of these non-inheritable handles.
        drop(unsafe { OwnedHandle::from_raw_handle(pi.hThread) });
        let mut child = Child {
            process: unsafe { OwnedHandle::from_raw_handle(pi.hProcess) },
            job: RefCell::new(Some(job)),
        };
        let mut wait = ptr::null_mut();
        // Retain only SYNCHRONIZE; termination authority is the private job.
        if unsafe {
            DuplicateHandle(GetCurrentProcess(), pi.hProcess, GetCurrentProcess(), &mut wait,
                SYNCHRONIZE, 0, 0)
        } == 0 {
            let error = io::Error::last_os_error();
            child.stop();
            return Err(error);
        }
        child.process = unsafe { OwnedHandle::from_raw_handle(wait) };
        Ok((commands, replies, child))
    }
}

/// WSP1 (not WSB1): magic[4], version:u8, kind:u8, payload length:u16 LE.
/// Prompt = cap:u16 LE + UTF-8 label. Ready/result = status:u16 LE, aux:u16
/// LE, then optional typed bytes. Other frames have no payload. There is no
/// vault opcode, name, store path, session ID, or discovery endpoint here.
mod wire {
    use super::*;

    const MAGIC: &[u8; 4] = b"WSP1";
    const VERSION: u8 = 1;
    const HEADER: usize = 8;
    const PREFIX: usize = 4;
    const MAX_LABEL: usize = 256;

    pub(super) const READY: u8 = 1;
    const PROMPT: u8 = 2;
    pub(super) const RESULT: u8 = 3;
    pub(super) const CANCEL: u8 = 4;
    pub(super) const TIMEOUT: u8 = 5;
    pub(super) const SHUTDOWN: u8 = 6;

    pub(super) enum Command {
        Prompt(String, usize),
        Abort(u32),
        Shutdown,
    }

    pub(super) fn invalid() -> io::Error {
        io::Error::new(io::ErrorKind::InvalidData, "invalid native prompt frame")
    }

    pub(super) fn valid_label(label: &str) -> bool {
        (1..=MAX_LABEL).contains(&label.len()) && !label.as_bytes().contains(&0)
    }

    fn header(kind: u8, len: u16) -> [u8; HEADER] {
        let [lo, hi] = len.to_le_bytes();
        [MAGIC[0], MAGIC[1], MAGIC[2], MAGIC[3], VERSION, kind, lo, hi]
    }

    fn parse_header(bytes: [u8; HEADER]) -> io::Result<(u8, usize)> {
        if &bytes[..4] != MAGIC || bytes[4] != VERSION {
            return Err(invalid());
        }
        let kind = bytes[5];
        let len = u16::from_le_bytes([bytes[6], bytes[7]]) as usize;
        let valid = match kind {
            READY => len == PREFIX,
            PROMPT => (3..=2 + MAX_LABEL).contains(&len),
            RESULT => (PREFIX..=PREFIX + SECRET_MAX_BYTES).contains(&len),
            CANCEL | TIMEOUT | SHUTDOWN => len == 0,
            _ => false,
        };
        if !valid { return Err(invalid()); }
        Ok((kind, len))
    }

    pub(super) fn send_header(mut wr: &File, kind: u8, len: u16) -> io::Result<()> {
        wr.write_all(&header(kind, len))
    }

    pub(super) fn send_prompt(mut wr: &File, label: &str, cap: usize) -> io::Result<()> {
        if !valid_label(label) || !(1..=SECRET_MAX_BYTES).contains(&cap) {
            return Err(invalid());
        }
        let mut prefix = [0; HEADER + 2];
        prefix[..HEADER].copy_from_slice(&header(PROMPT, (2 + label.len()) as u16));
        prefix[HEADER..].copy_from_slice(&(cap as u16).to_le_bytes());
        wr.write_all(&prefix)?;
        wr.write_all(label.as_bytes())
    }

    pub(super) fn send_reply(mut wr: &File, kind: u8, result: Outcome) -> io::Result<()> {
        let (status, aux, bytes) = match &result {
            Ok(bytes) => (WireStatus::Ok, 0, bytes.0.as_slice()),
            Err(error) => (error.status, error.aux, &[][..]),
        };
        if bytes.len() > SECRET_MAX_BYTES { return Err(invalid()); }
        let mut prefix = [0; HEADER + PREFIX];
        prefix[..HEADER].copy_from_slice(&header(kind, (PREFIX + bytes.len()) as u16));
        prefix[HEADER..HEADER + 2].copy_from_slice(&(status as u16).to_le_bytes());
        prefix[HEADER + 2..].copy_from_slice(&aux.to_le_bytes());
        wr.write_all(&prefix)?;
        // Write directly from WipedBytes; no second plaintext frame buffer.
        wr.write_all(bytes)
    }

    fn peek(rd: &File, buf: &mut [u8]) -> io::Result<(usize, usize)> {
        let (mut copied, mut available) = (0, 0);
        let out = if buf.is_empty() { ptr::null_mut() } else { buf.as_mut_ptr().cast() };
        // SAFETY: single reader, live synchronous anonymous pipe; peek never
        // consumes data. Only a header (never secret bytes) is requested.
        if unsafe {
            PeekNamedPipe(rd.as_raw_handle(), out, buf.len() as u32, &mut copied,
                &mut available, ptr::null_mut())
        } == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok((copied as usize, available as usize))
    }

    pub(super) fn available(rd: &File) -> io::Result<usize> {
        peek(rd, &mut []).map(|(_, n)| n)
    }

    // Block only for the FIRST byte of an idle command. An incomplete frame
    // cannot keep a live prompt pinned indefinitely. No body is allocated
    // until its direction, kind and advertised length have been validated.
    fn read_tail(rd: &mut File, buf: &mut [u8], deadline: Instant) -> io::Result<()> {
        while available(rd)? < buf.len() {
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() { return Err(invalid()); }
            std::thread::sleep(left.min(Duration::from_millis(5)));
        }
        rd.read_exact(buf)
    }

    pub(super) fn read_command(rd: &mut File) -> io::Result<Command> {
        let mut head = [0; HEADER];
        rd.read_exact(&mut head[..1])?;
        let deadline = Instant::now() + TEARDOWN_WAIT;
        read_tail(rd, &mut head[1..], deadline)?;
        let (kind, len) = parse_header(head)?;
        match kind {
            PROMPT => {
                let mut cap = [0; 2];
                read_tail(rd, &mut cap, deadline)?;
                let cap = u16::from_le_bytes(cap) as usize;
                if !(1..=SECRET_MAX_BYTES).contains(&cap) { return Err(invalid()); }
                let mut label = vec![0; len - 2];
                read_tail(rd, &mut label, deadline)?;
                let label = String::from_utf8(label).map_err(|_| invalid())?;
                if !valid_label(&label) { return Err(invalid()); }
                Ok(Command::Prompt(label, cap))
            }
            CANCEL => Ok(Command::Abort(WM_APP_CANCEL)),
            TIMEOUT => Ok(Command::Abort(WM_APP_TIMEOUT)),
            SHUTDOWN => Ok(Command::Shutdown),
            _ => Err(invalid()),
        }
    }

    /// Consume nothing until a whole validated-length frame is available.
    /// Cancellation/deadline expiry can therefore switch to a bounded drain
    /// even between header and body, without ever losing frame alignment.
    pub(super) fn try_reply(rd: &mut File, expected: u8, cap: usize) -> io::Result<Option<Outcome>> {
        let mut head = [0; HEADER];
        let (copied, available) = peek(rd, &mut head)?;
        if copied < HEADER { return Ok(None); }
        let (kind, len) = parse_header(head)?;
        if kind != expected || len < PREFIX || len - PREFIX > cap {
            return Err(invalid());
        }
        if available < HEADER + len { return Ok(None); }
        let mut prefix = [0; HEADER + PREFIX];
        rd.read_exact(&mut prefix)?;
        let code = u16::from_le_bytes([prefix[HEADER], prefix[HEADER + 1]]);
        let aux = u16::from_le_bytes([prefix[HEADER + 2], prefix[HEADER + 3]]);
        let status = [WireStatus::Ok, WireStatus::Cancelled, WireStatus::Timeout,
            WireStatus::NoConsole, WireStatus::InputInvalid]
            .into_iter().find(|&s| s as u16 == code).ok_or_else(invalid)?;
        if (aux != 0 && status != WireStatus::NoConsole)
            || (kind == READY && !matches!(status, WireStatus::Ok | WireStatus::NoConsole))
            || (status != WireStatus::Ok && len != PREFIX)
        {
            return Err(invalid());
        }
        if status != WireStatus::Ok {
            return Ok(Some(Err(PromptError { status, aux })));
        }
        let mut bytes = WipedBytes(vec![0; len - PREFIX]);
        rd.read_exact(&mut bytes.0)?;
        if bytes.0.iter().any(|&b| b < b' ') || std::str::from_utf8(&bytes.0).is_err() {
            return Err(invalid());
        }
        Ok(Some(Ok(bytes)))
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn commands_are_bounded_and_separate_from_vault_frames() -> io::Result<()> {
            let (mut rd, mut wr) = launch::pipe()?;
            send_prompt(&wr, PROMPT_CONFIRM, PASSPHRASE_MAX_BYTES)?;
            assert!(matches!(read_command(&mut rd)?, Command::Prompt(label, PASSPHRASE_MAX_BYTES)
                if label == PROMPT_CONFIRM));
            for (kind, message) in [(CANCEL, WM_APP_CANCEL), (TIMEOUT, WM_APP_TIMEOUT)] {
                send_header(&wr, kind, 0)?;
                assert!(matches!(read_command(&mut rd)?, Command::Abort(m) if m == message));
            }
            send_header(&wr, SHUTDOWN, 0)?;
            assert!(matches!(read_command(&mut rd)?, Command::Shutdown));
            for mut bad in [header(PROMPT, u16::MAX), header(CANCEL, 1), header(0xff, 0)] {
                wr.write_all(&bad)?;
                assert!(read_command(&mut rd).is_err());
                bad[4] = VERSION + 1;
                assert!(parse_header(bad).is_err());
            }
            let mut bad_magic = header(SHUTDOWN, 0);
            bad_magic[..4].copy_from_slice(b"WSB1");
            assert!(parse_header(bad_magic).is_err());
            Ok(())
        }

        #[test]
        fn partial_result_is_left_for_abort_drain() -> io::Result<()> {
            let (mut rd, mut wr) = launch::pipe()?;
            send_header(&wr, RESULT, (PREFIX + 2) as u16)?;
            wr.write_all(&[0; PREFIX])?;
            wr.write_all(b"a")?;
            assert!(try_reply(&mut rd, RESULT, 2)?.is_none());
            wr.write_all(b"b")?;
            assert!(matches!(try_reply(&mut rd, RESULT, 2)?, Some(Ok(bytes)) if bytes.0.as_slice() == b"ab"));
            // Exactly one result was drained; an empty typed line stays empty.
            send_reply(&wr, RESULT, Ok(WipedBytes(Vec::new())))?;
            assert!(matches!(try_reply(&mut rd, RESULT, 2)?, Some(Ok(bytes)) if bytes.0.is_empty()));
            send_reply(&wr, RESULT, Err(PromptError { status: WireStatus::NoConsole, aux: 5 }))?;
            assert!(matches!(try_reply(&mut rd, RESULT, 2)?, Some(Err(e))
                if e.status == WireStatus::NoConsole && e.aux == 5));
            Ok(())
        }

        #[test]
        fn rejects_bad_status_or_excess_bytes_before_accepting_a_result() -> io::Result<()> {
            for (code, data, cap) in [
                (0xffffu16, &[][..], SECRET_MAX_BYTES),
                (WireStatus::Timeout as u16, &b"x"[..], SECRET_MAX_BYTES),
                (0, &b"ab"[..], 1),
                (0, &b"\0"[..], SECRET_MAX_BYTES),
            ] {
                let (mut rd, mut wr) = launch::pipe()?;
                send_header(&wr, RESULT, (PREFIX + data.len()) as u16)?;
                wr.write_all(&code.to_le_bytes())?;
                wr.write_all(&[0, 0])?;
                wr.write_all(data)?;
                assert!(try_reply(&mut rd, RESULT, cap).is_err());
            }
            Ok(())
        }
    }
}

/// Entry after `init_process_protection`, before any vault initialization.
/// The helper's hardened primary thread is its only pipe reader/writer; the
/// other wsecret-owned thread owns the window and pumps messages.
pub(crate) fn run_helper(rd: usize, wr: usize) -> io::Result<()> {
    let (mut commands, replies) = launch::adopt(rd, wr)?;
    let window = match PromptWindow::open() {
        Ok(window) => window,
        Err(error) => return wire::send_reply(&replies, wire::READY, Err(error)),
    };
    wire::send_reply(&replies, wire::READY, Ok(WipedBytes(Vec::new())))?;
    let result = window.serve(&mut commands, &replies);
    if result.as_ref().is_err_and(|e| e.kind() == io::ErrorKind::InvalidData) {
        // Never try to resynchronize after malformed input or trust its length.
        let _ = wire::send_reply(&replies, wire::RESULT, Err(PromptError::status(WireStatus::InputInvalid)));
    }
    result
}

struct PromptWindow {
    hwnd: HWND,
    pending: PendingJob,
    ui: Option<HardenedThread>,
}

impl PromptWindow {
    fn open() -> Result<Self, PromptError> {
        let pending = Arc::new(Mutex::new(None));
        let (ready, ready_rx) = mpsc::channel();
        let ui = security::spawn_hardened_thread({
            let pending = Arc::clone(&pending);
            move || ui_thread(pending, ready)
        }).map_err(|_| PromptError::status(WireStatus::NoConsole))?;
        // The owning broker enforces READY_WAIT and can kill a stuck creation
        // even if the UI thread never creates its message queue.
        match ready_rx.recv() {
            Ok(Ok(hwnd)) => Ok(Self { hwnd: hwnd as HWND, pending, ui: Some(ui) }),
            failure => {
                let _ = ui.join();
                Err(failure.ok().and_then(Result::err)
                    .unwrap_or_else(|| PromptError::status(WireStatus::NoConsole)))
            }
        }
    }

    fn post(&self, message: u32) -> io::Result<()> {
        // SAFETY: only posts a notification; no pointers travel in a message.
        if unsafe { PostMessageW(self.hwnd, message, 0, 0) } == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    fn serve(&self, commands: &mut File, replies: &File) -> io::Result<()> {
        let mut active: Option<Receiver<Outcome>> = None;
        loop {
            if let Some(rx) = &active {
                let has_command = wire::available(commands)? != 0;
                let wait = if has_command { Duration::ZERO } else { POLL_SLICE };
                match rx.recv_timeout(wait) {
                    Ok(result) => {
                        wire::send_reply(replies, wire::RESULT, result)?;
                        active = None;
                        continue;
                    }
                    Err(RecvTimeoutError::Disconnected) => return Err(io::Error::from(io::ErrorKind::BrokenPipe)),
                    Err(RecvTimeoutError::Timeout) if !has_command => continue,
                    Err(RecvTimeoutError::Timeout) => {}
                }
            }
            // No prompt up: block for the first byte rather than waking an
            // idle desktop process. During a prompt the peek above gates this.
            match wire::read_command(commands)? {
                wire::Command::Prompt(prompt, max_bytes) if active.is_none() => {
                    let (reply, rx) = mpsc::channel();
                    *self.pending.lock().unwrap_or_else(|e| e.into_inner()) =
                        Some(PromptJob { prompt, max_bytes, reply });
                    self.post(WM_APP_PROMPT)?;
                    active = Some(rx);
                }
                wire::Command::Prompt(..) => return Err(wire::invalid()),
                wire::Command::Abort(message) => {
                    // If OK already won, the broker drains that one result.
                    // Never acknowledge a late abort as a new response.
                    if active.is_some() { self.post(message)?; }
                }
                wire::Command::Shutdown => return Ok(()),
            }
        }
    }
}

impl Drop for PromptWindow {
    fn drop(&mut self) {
        let _ = self.post(WM_APP_SHUTDOWN);
        if let Some(ui) = self.ui.take() { let _ = ui.join(); }
    }
}

// ---- UI thread ------------------------------------------------------------

/// Build the hidden window once. No show/hide, dummy input or UIA warm-up
/// is needed: provider threads belong to this helper, never to the broker.
fn ui_thread(pending: PendingJob, ready: Sender<Result<usize, PromptError>>) {
    UI.with(|state| state.borrow_mut().pending = Some(pending));
    let module: HINSTANCE = unsafe { GetModuleHandleW(ptr::null()) };
    let hwnd = match build_prompt_window(module) {
        Ok(hwnd) => hwnd,
        Err(error) => {
            let _ = ready.send(Err(PromptError::io(error)));
            return;
        }
    };
    let _ = ready.send(Ok(hwnd as usize));
    message_loop(hwnd);
    // SAFETY: release the window on its own thread if the loop quit without
    // a shutdown message (WM_APP_SHUTDOWN normally destroys it).
    if unsafe { IsWindow(hwnd) } != 0 {
        unsafe { DestroyWindow(hwnd); }
    }
    UI.with(|state| *state.borrow_mut() = UiState::new());
}


/// The window's message loop. `IsDialogMessageW` gives native dialog
/// keyboard behavior (Enter = default OK, Esc = Cancel, Tab = focus).
fn message_loop(hwnd: HWND) {
    let mut msg = MSG::default();
    loop {
        // SAFETY: `msg` is a valid mutable buffer; the null filter takes
        // every message of this thread. `0` is `WM_QUIT`, `-1` an error.
        let result = unsafe { GetMessageW(&mut msg, ptr::null_mut(), 0, 0) };
        if result <= 0 {
            return;
        }
        if unsafe { IsDialogMessageW(hwnd, &msg) } != 0 {
            continue;
        }
        unsafe {
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }
    }
}

/// Registers the prompt window class. A retry after a failed `open` finds
/// the class already registered and reuses it.
fn register_prompt_class(module: HINSTANCE) -> io::Result<()> {
    let class = WNDCLASSW {
        style: 0,
        lpfnWndProc: Some(prompt_wnd_proc),
        cbClsExtra: 0,
        cbWndExtra: 0,
        hInstance: module,
        hIcon: ptr::null_mut(),
        // SAFETY: null instance requests the shared standard arrow cursor.
        hCursor: unsafe { LoadCursorW(ptr::null_mut(), IDC_ARROW) },
        // System-color brush (index + 1), so high-contrast themes repaint.
        hbrBackground: (COLOR_WINDOW + 1) as HBRUSH,
        lpszMenuName: ptr::null(),
        lpszClassName: PROMPT_CLASS,
    };
    // SAFETY: `class` is fully initialized and outlives the call.
    if unsafe { RegisterClassW(&class) } == 0 {
        let error = io::Error::last_os_error();
        if error.raw_os_error() != Some(ERROR_CLASS_ALREADY_EXISTS as i32) {
            return Err(error);
        }
    }
    Ok(())
}

/// Creates the hidden prompt window and its label, masked edit and
/// OK/Cancel buttons.
fn build_prompt_window(module: HINSTANCE) -> io::Result<HWND> {
    register_prompt_class(module)?;
    let width = 470i32;
    let height = 195i32;
    // SAFETY: screen-metric queries take no pointers.
    let (screen_x, screen_y) = unsafe {
        (
            GetSystemMetrics(SM_CXSCREEN),
            GetSystemMetrics(SM_CYSCREEN),
        )
    };
    // SAFETY: wide-literal class/title; null parent/menu for a top-level
    // overlapped window.
    let hwnd = unsafe {
        CreateWindowExW(
            WS_EX_TOPMOST,
            PROMPT_CLASS,
            w!("wsecret"),
            WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU,
            (screen_x - width) / 2,
            screen_y / 3,
            width,
            height,
            ptr::null_mut(),
            ptr::null_mut(),
            module,
            ptr::null(),
        )
    };
    if hwnd.is_null() {
        return Err(io::Error::last_os_error());
    }
    let built: io::Result<HWND> = (|| {
        let label = create_child(
            module,
            hwnd,
            w!("STATIC"),
            w!(""),
            ID_LABEL,
            WS_CHILD | SS_LEFT,
            0,
            14,
            12,
            428,
            42,
        )?;
        let edit = create_child(
            module,
            hwnd,
            w!("EDIT"),
            w!(""),
            ID_EDIT,
            WS_CHILD | WS_TABSTOP | (ES_PASSWORD as u32),
            WS_EX_CLIENTEDGE,
            14,
            62,
            428,
            24,
        )?;
        let ok = create_child(
            module,
            hwnd,
            w!("BUTTON"),
            w!("&OK"),
            IDOK as u32,
            WS_CHILD | WS_TABSTOP | (BS_DEFPUSHBUTTON as u32),
            0,
            250,
            98,
            92,
            26,
        )?;
        let cancel = create_child(
            module,
            hwnd,
            w!("BUTTON"),
            w!("&Cancel"),
            IDCANCEL as u32,
            WS_CHILD | WS_TABSTOP | (BS_PUSHBUTTON as u32),
            0,
            350,
            98,
            92,
            26,
        )?;
        // SAFETY: stock object request; `WM_SETFONT` goes to our children.
        let font = unsafe { GetStockObject(DEFAULT_GUI_FONT) };
        for child in [label, edit, ok, cancel] {
            // SAFETY: owned child controls.
            unsafe {
                SendMessageW(child, WM_SETFONT, font as usize, 1);
            }
        }
        UI.with(|state| {
            let mut state = state.borrow_mut();
            state.label = label;
            state.edit = edit;
        });
        Ok(hwnd)
    })();
    match built {
        Ok(handles) => Ok(handles),
        Err(error) => {
            // SAFETY: owned window; the children die with the parent.
            unsafe {
                DestroyWindow(hwnd);
            }
            Err(error)
        }
    }
}

/// Creates one child control of the prompt window.
fn create_child(
    module: HINSTANCE,
    parent: HWND,
    class: *const u16,
    text: *const u16,
    id: u32,
    style: WINDOW_STYLE,
    ex_style: WINDOW_EX_STYLE,
    x: i32,
    y: i32,
    width: i32,
    height: i32,
) -> io::Result<HWND> {
    // SAFETY: wide-literal class/text; `parent` is our own window and the
    // child id travels in `hMenu` as for dialog controls.
    let hwnd = unsafe {
        CreateWindowExW(
            ex_style,
            class,
            text,
            style | WS_VISIBLE,
            x,
            y,
            width,
            height,
            parent,
            id as HMENU,
            module,
            ptr::null(),
        )
    };
    if hwnd.is_null() {
        Err(io::Error::last_os_error())
    } else {
        Ok(hwnd)
    }
}

/// The prompt window procedure: button/close/abort messages complete the
/// active prompt; everything else is standard window behavior.
unsafe extern "system" fn prompt_wnd_proc(
    hwnd: HWND,
    message: u32,
    wparam: WPARAM,
    lparam: LPARAM,
) -> LRESULT {
    match message {
        WM_COMMAND => {
            let id = (wparam & 0xFFFF) as u32;
            if id == IDOK as u32 {
                finish_ok(hwnd);
            } else if id == IDCANCEL as u32 {
                finish_cancelled(hwnd, WireStatus::Cancelled);
            }
            0
        }
        // The window is reused, so closing it aborts the prompt.
        WM_CLOSE => {
            finish_cancelled(hwnd, WireStatus::Cancelled);
            0
        }
        WM_APP_PROMPT => {
            start_prompt(hwnd);
            0
        }
        WM_APP_CANCEL => {
            finish_cancelled(hwnd, WireStatus::Cancelled);
            0
        }
        WM_APP_TIMEOUT => {
            finish_cancelled(hwnd, WireStatus::Timeout);
            0
        }
        WM_APP_SHUTDOWN => {
            finish_cancelled(hwnd, WireStatus::Cancelled);
            // SAFETY: owned window on this thread; `WM_DESTROY` quits the
            // message loop.
            unsafe {
                DestroyWindow(hwnd);
            }
            0
        }
        // Default-button answer for `IsDialogMessageW`'s Enter handling.
        DM_GETDEFID => (DC_HASDEFID << 16 | IDOK as u32) as LRESULT,
        WM_DESTROY => {
            // SAFETY: plain thread-queue post that ends `message_loop`.
            unsafe {
                PostQuitMessage(0);
            }
            0
        }
        // SAFETY: default class behavior (painting, sizing, non-client, …).
        _ => unsafe { DefWindowProcW(hwnd, message, wparam, lparam) },
    }
}

/// Starts the next queued prompt: clear the control, set the label and the
/// unit limit, then show the window topmost with keyboard focus.
fn start_prompt(hwnd: HWND) {
    let Some(job) = pop_job() else {
        return;
    };
    let PromptJob {
        prompt,
        max_bytes,
        reply,
    } = job;
    let (label, edit) = (label_handle(), edit_handle());
    clear_edit(edit);
    set_prompt_text(label, &prompt);
    // SAFETY: bounded request to our own child control. The limit is one
    // unit past the cap: input that fills it decodes to at least that many
    // bytes and is rejected by `decode_line`, and truncation at the limit
    // can therefore never turn over-long input into an accepted value.
    unsafe {
        SendMessageW(edit, EM_SETLIMITTEXT, max_bytes + 1, 0);
    }
    UI.with(|state| {
        state.borrow_mut().active = Some(ActivePrompt { reply, max_bytes });
    });
    show_front(hwnd, edit);
}

/// OK: copy the masked text out, clear the control immediately, hide the
/// window and answer with the upstream decode of the typed units.
fn finish_ok(hwnd: HWND) {
    let Some(active) = take_active() else {
        return;
    };
    let edit = edit_handle();
    let (mut units, copied) = read_edit_text(edit, active.max_bytes);
    clear_edit(edit);
    hide_window(hwnd);
    let decoded = decode_line(&units[..copied], active.max_bytes);
    wipe_units(&mut units);
    let outcome = decoded.map(WipedBytes).map_err(PromptError::status);
    // A result whose reader is gone comes back inside `SendError` and is
    // wiped by `WipedBytes` on drop.
    let _ = active.reply.send(outcome);
}

/// Cancel/abort: clear the control, hide the window and answer `status`.
fn finish_cancelled(hwnd: HWND, status: WireStatus) {
    let Some(active) = take_active() else {
        // Stray abort after the prompt completed: keep the window hidden.
        hide_window(hwnd);
        return;
    };
    clear_edit(edit_handle());
    hide_window(hwnd);
    let _ = active.reply.send(Err(PromptError::status(status)));
}

fn take_active() -> Option<ActivePrompt> {
    UI.with(|state| state.borrow_mut().active.take())
}

fn pop_job() -> Option<PromptJob> {
    UI.with(|state| {
        state.borrow().pending.as_ref()?.lock().unwrap_or_else(|e| e.into_inner()).take()
    })
}

fn label_handle() -> HWND {
    UI.with(|state| state.borrow().label)
}

fn edit_handle() -> HWND {
    UI.with(|state| state.borrow().edit)
}

/// Copies the edit control's full single-line contents into a bounded UTF-16
/// scratch buffer. Unlike `GetWindowTextW`, `EM_GETLINE` preserves embedded
/// NUL units so the validator rejects rather than silently truncating them.
/// The control still holds the text until [`clear_edit`].
fn read_edit_text(edit: HWND, max_bytes: usize) -> (Vec<u16>, usize) {
    let mut units = vec![0u16; max_bytes + 2];
    // EM_GETLINE takes the destination capacity in the first unit and returns
    // the copied unit count; the result need not be NUL-terminated.
    units[0] = (units.len() - 1) as u16;
    // SAFETY: `units` is writable for the advertised capacity on our own
    // single-line child control.
    let copied = unsafe { SendMessageW(edit, EM_GETLINE, 0, units.as_mut_ptr() as isize) };
    (units, copied.max(0) as usize)
}

/// Clears the edit control immediately after reading: the text and its undo
/// buffer must not outlive the read.
fn clear_edit(edit: HWND) {
    // SAFETY: `w!("")` is a valid empty wide string; both calls target our
    // own child control.
    unsafe {
        SetWindowTextW(edit, w!(""));
        SendMessageW(edit, EM_EMPTYUNDOBUFFER, 0, 0);
    }
}

fn set_prompt_text(label: HWND, prompt: &str) {
    let wide: Vec<u16> = prompt.encode_utf16().chain(std::iter::once(0)).collect();
    // SAFETY: `wide` is a valid NUL-terminated UTF-16 string.
    unsafe {
        SetWindowTextW(label, wide.as_ptr());
    }
}


/// Shows the window topmost and focused (the foreground lock is bypassed
/// with a paired `AttachThreadInput`, detached on every path).
fn show_front(hwnd: HWND, edit: HWND) {
    // SAFETY: all calls target windows of this process; the input
    // attachment is paired below on every path.
    unsafe {
        ShowWindow(hwnd, SW_SHOW);
        SetWindowPos(hwnd, HWND_TOPMOST, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE);
        let foreground = GetForegroundWindow();
        let target = if foreground.is_null() {
            0
        } else {
            GetWindowThreadProcessId(foreground, ptr::null_mut())
        };
        let ours = GetCurrentThreadId();
        let attached =
            target != 0 && target != ours && AttachThreadInput(target, ours, 1) != 0;
        let _ = SetForegroundWindow(hwnd);
        if attached {
            AttachThreadInput(target, ours, 0);
        }
        SetFocus(edit);
    }
}

fn hide_window(hwnd: HWND) {
    // SAFETY: owned window.
    unsafe {
        ShowWindow(hwnd, SW_HIDE);
    }
}

/// Upstream `decode_console_line` over already-terminator-free units: UTF-16
/// → UTF-8 with the exact cap, no control bytes (`buf[i] < ' '` rejects
/// tabs/CR/NUL/…), invalid surrogates rejected. Scratch buffers are wiped on
/// every path.
fn decode_line(units: &[u16], max_bytes: usize) -> Result<Vec<u8>, WireStatus> {
    let mut bytes: Vec<u8> = Vec::with_capacity(max_bytes + 4);
    let mut scratch = [0u8; 4];
    for unit in char::decode_utf16(units.iter().copied()) {
        match unit {
            Ok(ch) => {
                let n = ch.encode_utf8(&mut scratch).len();
                if bytes.len() + n > max_bytes {
                    wipe_bytes(&mut scratch);
                    wipe_bytes(&mut bytes);
                    return Err(WireStatus::InputInvalid);
                }
                bytes.extend_from_slice(&scratch[..n]);
            }
            Err(_) => {
                wipe_bytes(&mut scratch);
                wipe_bytes(&mut bytes);
                return Err(WireStatus::InputInvalid);
            }
        }
    }
    wipe_bytes(&mut scratch);
    if bytes.iter().any(|&b| b < b' ') {
        wipe_bytes(&mut bytes);
        return Err(WireStatus::InputInvalid);
    }
    Ok(bytes)
}

/// Overwrites `buf` with zeros via `hydro_memzero` (volatile; never
/// optimized away) — the same erasure as the core's scratch wipes, kept
/// local so this module owns no console surface.
fn wipe_bytes(buf: &mut [u8]) {
    libhydrogen_sys::memzero(buf);
}

/// [`wipe_bytes`] for UTF-16 edit-control read buffers (byte view of `buf`).
fn wipe_units(buf: &mut [u16]) {
    if buf.is_empty() {
        return;
    }
    // SAFETY: `buf` is exclusively borrowed; `u16` has no padding bytes, so
    // the byte view covers exactly `len * 2` initialized bytes.
    let bytes =
        unsafe { std::slice::from_raw_parts_mut(buf.as_mut_ptr().cast::<u8>(), buf.len() * 2) };
    libhydrogen_sys::memzero(bytes);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_rejects_control_bytes_and_overflow() {
        // Tab (< 0x20) is upstream "Invalid input!".
        assert_eq!(
            decode_line(&[b'a' as u16, 0x09], 16),
            Err(WireStatus::InputInvalid)
        );
        // Over the byte cap is "Input too long!".
        assert_eq!(
            decode_line(&[b'a' as u16; 5], 4),
            Err(WireStatus::InputInvalid)
        );
        // Plain ASCII passes as exact bytes.
        assert_eq!(
            decode_line(&[b'a' as u16, b'b' as u16], 16),
            Ok(b"ab".to_vec())
        );
        // A 2-unit UTF-8 character counts its encoded bytes.
        assert_eq!(decode_line(&[0x00E9], 1), Err(WireStatus::InputInvalid));
        assert_eq!(decode_line(&[0x00E9], 2), Ok(vec![0xC3, 0xA9]));
    }
}
