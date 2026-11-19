//! Plan §7.4 P4a–P4j acceptance probes (custom harness for process isolation).
//!
//! The default invocation runs the parent suite. Helper roles are separate
//! processes of this same test binary, so watchdog poisoning/ExitProcess and
//! fresh same-user OpenProcess/OpenThread checks never destabilize the parent.
//!
//! The P4d/P4h birth-descriptor scenario drives the MANAGED SSH launch path
//! (`spawn_ssh_child`): the legacy capability transport (`AgentCapability` /
//! `AgentPipe` / `SECRET_AGENT` handle passing) is gone and is NOT recreated
//! here — only the launch-time handle hygiene and the child environment
//! contract (verified `SSH_AUTH_SOCK`, legacy `SECRET_AGENT` stripped) are
//! exercised.

use std::collections::BTreeMap;
use std::ffi::{OsStr, c_void};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::ptr;
use std::time::{Duration, Instant};

use std::os::windows::io::AsRawHandle;
use windows_sys::Win32::Foundation::{CloseHandle, DuplicateHandle, GetLastError, HANDLE};
use windows_sys::Win32::Security::Authorization::{SE_KERNEL_OBJECT, SetSecurityInfo};
use windows_sys::Win32::Security::{
    ACL, ACL_REVISION, AdjustTokenPrivileges, DACL_SECURITY_INFORMATION, GetTokenInformation,
    InitializeAcl, LUID_AND_ATTRIBUTES, LookupPrivilegeValueW, PROTECTED_DACL_SECURITY_INFORMATION,
    SE_PRIVILEGE_ENABLED, TOKEN_ADJUST_PRIVILEGES, TOKEN_ELEVATION, TOKEN_PRIVILEGES, TOKEN_QUERY,
    TokenElevation, TokenPrivileges,
};
use windows_sys::Win32::Storage::FileSystem::{SYNCHRONIZE, WRITE_DAC, WRITE_OWNER};
use windows_sys::Win32::System::Diagnostics::Debug::ReadProcessMemory;
use windows_sys::Win32::System::Threading::*;
use wsecret_core::format::Header;
use wsecret_core::session::{Session, transient_key_address_for_test};
use wsecret_core::windows::agent_bridge::spawn_ssh_child;
use wsecret_core::windows::security;

const PASS: &[u8] = b"p4 acceptance passphrase";
/// The one verified Windows OpenSSH agent endpoint (the managed SSH launch
/// passes it verbatim as the child's `SSH_AUTH_SOCK`).
const SSH_ENDPOINT: &str = r"\\.\pipe\openssh-ssh-agent";
const OPS: u64 = 10_000;
const PREREQUISITE_EXIT: i32 = 77;

fn header() -> Header {
    Header {
        version: 0,
        master: [0x2a; 32],
        ops_limit: OPS,
    }
}

fn expected_key() -> [u8; 32] {
    let mut key = [0u8; 32];
    libhydrogen_sys::pwhash_deterministic(
        &mut key,
        PASS,
        &libhydrogen_sys::CTX_MASTER,
        &[0x2a; 32],
        OPS,
    );
    key
}

fn init() -> Result<(), String> {
    libhydrogen_sys::init();
    security::init_process_protection().map_err(|e| format!("init_process_protection: {e}"))
}

fn unlock() -> Result<Session, String> {
    Session::unlock(&header(), &mut PASS.to_vec()).map_err(|e| format!("unlock: {e}"))
}

fn session_outcome(result: &Result<Session, wsecret_core::Error>) -> String {
    match result {
        Ok(_) => "Ok(Session)".to_owned(),
        Err(error) => format!("Err({error})"),
    }
}

fn write(path: &Path, bytes: &[u8]) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|e| format!("mkdir {}: {e}", parent.display()))?;
    }
    fs::write(path, bytes).map_err(|e| format!("write {}: {e}", path.display()))
}

fn wait_file(path: &Path, timeout: Duration) -> Result<Vec<u8>, String> {
    let start = Instant::now();
    loop {
        match fs::read(path) {
            Ok(bytes) => return Ok(bytes),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(format!("read {}: {e}", path.display())),
        }
        if start.elapsed() > timeout {
            return Err(format!("timed out waiting for {}", path.display()));
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn wait_stop(dir: &Path) -> Result<(), String> {
    wait_file(&dir.join("stop"), Duration::from_secs(30)).map(|_| ())
}

fn ready_map(dir: &Path) -> Result<BTreeMap<String, String>, String> {
    let raw = wait_file(&dir.join("ready"), Duration::from_secs(15))?;
    let text = String::from_utf8(raw).map_err(|e| format!("ready UTF-8: {e}"))?;
    Ok(text
        .lines()
        .filter_map(|line| line.split_once('='))
        .map(|(k, v)| (k.to_owned(), v.to_owned()))
        .collect())
}

fn number(map: &BTreeMap<String, String>, key: &str) -> Result<usize, String> {
    map.get(key)
        .ok_or_else(|| format!("missing ready key {key}"))?
        .parse()
        .map_err(|e| format!("ready {key}: {e}"))
}

fn test_dir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("wsecret-p4-{}-{tag}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).expect("create P4 scenario directory");
    dir
}

fn spawn_role(role: &str, dir: &Path, args: &[String]) -> Result<Child, String> {
    Command::new(std::env::current_exe().map_err(|e| e.to_string())?)
        .arg("--p4-role")
        .arg(role)
        .arg(dir)
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("spawn role {role}: {e}"))
}

fn wait_output(mut child: Child, timeout: Duration) -> Result<Output, String> {
    let start = Instant::now();
    loop {
        if child.try_wait().map_err(|e| e.to_string())?.is_some() {
            return child.wait_with_output().map_err(|e| e.to_string());
        }
        if start.elapsed() > timeout {
            let _ = child.kill();
            let _ = child.wait();
            return Err("helper timed out".to_owned());
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn run_role(role: &str, dir: &Path, args: &[String]) -> Result<Output, String> {
    let child = spawn_role(role, dir, args)?;
    wait_output(child, Duration::from_secs(40))
}

fn output_text(output: &Output) -> String {
    format!(
        "status={}\nstdout:\n{}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

fn assert_success(output: &Output) -> Result<(), String> {
    if output.status.success() {
        Ok(())
    } else {
        Err(output_text(output))
    }
}

struct Running {
    child: Option<Child>,
    dir: PathBuf,
}

impl Running {
    fn start(role: &str, dir: &Path, args: &[String]) -> Result<Self, String> {
        Ok(Self {
            child: Some(spawn_role(role, dir, args)?),
            dir: dir.to_path_buf(),
        })
    }

    fn stop(mut self) -> Result<Output, String> {
        write(&self.dir.join("stop"), b"stop")?;
        wait_output(
            self.child.take().expect("running child"),
            Duration::from_secs(15),
        )
    }
}

impl Drop for Running {
    fn drop(&mut self) {
        if let Some(child) = &mut self.child {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

fn denied_process(pid: u32, access: u32) -> Result<(), String> {
    // SAFETY: fresh same-user open by PID; no inherited target handle is used.
    let handle = unsafe { OpenProcess(access, 0, pid) };
    if handle.is_null() {
        // SAFETY: last-error query for this thread.
        let error = unsafe { GetLastError() };
        if error == 5 {
            Ok(())
        } else {
            Err(format!(
                "OpenProcess({access:#x}) error={error}, want ACCESS_DENIED"
            ))
        }
    } else {
        // SAFETY: unexpected live handle must be closed.
        unsafe {
            CloseHandle(handle);
        }
        Err(format!(
            "OpenProcess({access:#x}) SUCCEEDED, want ACCESS_DENIED"
        ))
    }
}

fn denied_thread(tid: u32, access: u32) -> Result<(), String> {
    // SAFETY: fresh same-user open by thread ID.
    let handle = unsafe { OpenThread(access, 0, tid) };
    if handle.is_null() {
        // SAFETY: last-error query for this thread.
        let error = unsafe { GetLastError() };
        if error == 5 {
            Ok(())
        } else {
            Err(format!(
                "OpenThread({access:#x}) error={error}, want ACCESS_DENIED"
            ))
        }
    } else {
        // SAFETY: unexpected live handle must be closed.
        unsafe {
            CloseHandle(handle);
        }
        Err(format!(
            "OpenThread({access:#x}) SUCCEEDED, want ACCESS_DENIED"
        ))
    }
}

fn role_probe_rights(_dir: &Path, args: &[String]) -> Result<(), String> {
    let pid: u32 = args[0].parse().map_err(|e| format!("pid: {e}"))?;
    for access in [
        PROCESS_VM_READ,
        PROCESS_VM_WRITE,
        PROCESS_VM_OPERATION,
        PROCESS_CREATE_THREAD,
        PROCESS_DUP_HANDLE,
        PROCESS_SET_INFORMATION,
        PROCESS_SET_LIMITED_INFORMATION,
        PROCESS_QUERY_INFORMATION,
        PROCESS_CREATE_PROCESS,
        WRITE_DAC,
        WRITE_OWNER,
    ] {
        denied_process(pid, access)?;
    }
    for arg in &args[1..] {
        let tid: u32 = arg.parse().map_err(|e| format!("tid: {e}"))?;
        for access in [
            THREAD_GET_CONTEXT,
            THREAD_SET_CONTEXT,
            THREAD_SUSPEND_RESUME,
            THREAD_RESUME,
            THREAD_SET_INFORMATION,
            THREAD_SET_LIMITED_INFORMATION,
            THREAD_QUERY_INFORMATION,
            THREAD_SET_THREAD_TOKEN,
            THREAD_IMPERSONATE,
            THREAD_DIRECT_IMPERSONATION,
            THREAD_TERMINATE,
            WRITE_DAC,
            WRITE_OWNER,
        ] {
            denied_thread(tid, access)?;
        }
    }
    Ok(())
}

fn role_hardened_target(dir: &Path, _args: &[String]) -> Result<(), String> {
    init()?;
    let primary = unsafe { GetCurrentThreadId() };
    let worker_dir = dir.to_path_buf();
    let worker = security::spawn_hardened_thread(move || {
        let _ = wait_stop(&worker_dir);
    })
    .map_err(|e| format!("spawn worker: {e}"))?;
    let worker_id = worker.id();
    let mut session = unlock()?;
    let watchdog = security::watchdog_thread_id_for_test()
        .ok_or_else(|| "watchdog did not start".to_owned())?;
    let ready = format!(
        "pid={}\nprimary={}\nworker={}\nwatchdog={}\nkey={}\n",
        std::process::id(),
        primary,
        worker_id,
        watchdog,
        session.key_address_for_test()
    );
    write(&dir.join("ready"), ready.as_bytes())?;
    wait_stop(dir)?;
    session.lock();
    worker.join().map_err(|e| format!("worker join: {e}"))
}

fn role_control_target(dir: &Path, _args: &[String]) -> Result<(), String> {
    security::harden_process_without_owner_rights_for_test()
        .map_err(|e| format!("control hardening: {e}"))?;
    write(
        &dir.join("ready"),
        format!("pid={}\n", std::process::id()).as_bytes(),
    )?;
    wait_stop(dir)
}

fn role_write_dac(_dir: &Path, args: &[String]) -> Result<(), String> {
    let pid: u32 = args[0].parse().map_err(|e| format!("pid: {e}"))?;
    let expect_allow = args[1] == "allow";
    // SAFETY: explicit WRITE_DAC request is the P4b probe.
    let handle = unsafe { OpenProcess(WRITE_DAC, 0, pid) };
    if !expect_allow {
        if handle.is_null() && unsafe { GetLastError() } == 5 {
            return Ok(());
        }
        if !handle.is_null() {
            unsafe {
                CloseHandle(handle);
            }
        }
        return Err("WRITE_DAC unexpectedly succeeded with OWNER_RIGHTS".to_owned());
    }
    if handle.is_null() {
        return Err(format!("control WRITE_DAC failed: {}", unsafe {
            GetLastError()
        }));
    }
    let mut acl = [0u8; 8];
    // SAFETY: exact empty-ACL buffer.
    if unsafe { InitializeAcl(acl.as_mut_ptr() as *mut ACL, 8, ACL_REVISION) } == 0 {
        unsafe {
            CloseHandle(handle);
        }
        return Err("InitializeAcl failed".to_owned());
    }
    // Exercise the DACL update, not merely the open.
    // SAFETY: handle has WRITE_DAC; ACL is a valid empty DACL.
    let status = unsafe {
        SetSecurityInfo(
            handle,
            SE_KERNEL_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            ptr::null_mut(),
            ptr::null_mut(),
            acl.as_mut_ptr() as *const ACL,
            ptr::null_mut(),
        )
    };
    unsafe {
        CloseHandle(handle);
    }
    if status == 0 {
        Ok(())
    } else {
        Err(format!("control SetSecurityInfo failed: {status}"))
    }
}

fn role_privileged_probe(_dir: &Path, args: &[String]) -> Result<(), String> {
    let pid: u32 = args[0].parse().map_err(|e| format!("pid: {e}"))?;
    let mut token = ptr::null_mut();
    // SAFETY: opens this process token for elevation/privilege inspection.
    if unsafe {
        OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES,
            &mut token,
        )
    } == 0
    {
        return Err(format!("OpenProcessToken: {}", unsafe { GetLastError() }));
    }
    let mut elevation = TOKEN_ELEVATION::default();
    let mut returned = 0u32;
    // SAFETY: output buffer has the exact TOKEN_ELEVATION layout.
    let elevated = unsafe {
        GetTokenInformation(
            token,
            TokenElevation,
            &mut elevation as *mut TOKEN_ELEVATION as *mut c_void,
            std::mem::size_of::<TOKEN_ELEVATION>() as u32,
            &mut returned,
        )
    } != 0
        && elevation.TokenIsElevated != 0;
    if !elevated {
        unsafe {
            CloseHandle(token);
        }
        eprintln!("P4c prerequisite: elevated token with SeDebugPrivilege is unavailable");
        std::process::exit(PREREQUISITE_EXIT);
    }
    let name: Vec<u16> = "SeDebugPrivilege\0".encode_utf16().collect();
    let mut luid = Default::default();
    // SAFETY: NUL-terminated privilege name and valid LUID output.
    if unsafe { LookupPrivilegeValueW(ptr::null(), name.as_ptr(), &mut luid) } == 0 {
        unsafe {
            CloseHandle(token);
        }
        std::process::exit(PREREQUISITE_EXIT);
    }
    let mut privileges = TOKEN_PRIVILEGES {
        PrivilegeCount: 1,
        Privileges: [LUID_AND_ATTRIBUTES {
            Luid: luid,
            Attributes: SE_PRIVILEGE_ENABLED,
        }],
    };
    // SAFETY: token has TOKEN_ADJUST_PRIVILEGES; structure is exact.
    if unsafe { AdjustTokenPrivileges(token, 0, &privileges, 0, ptr::null_mut(), ptr::null_mut()) }
        == 0
    {
        unsafe {
            CloseHandle(token);
        }
        std::process::exit(PREREQUISITE_EXIT);
    }
    let mut bytes = [0usize; 32];
    // SAFETY: query the actual token privileges after adjustment.
    if unsafe {
        GetTokenInformation(
            token,
            TokenPrivileges,
            bytes.as_mut_ptr() as *mut c_void,
            std::mem::size_of_val(&bytes) as u32,
            &mut returned,
        )
    } == 0
    {
        unsafe {
            CloseHandle(token);
        }
        return Err("GetTokenInformation(TokenPrivileges) failed".to_owned());
    }
    // SAFETY: the token returned a TOKEN_PRIVILEGES prefix in `bytes`.
    let actual = unsafe { &*(bytes.as_ptr() as *const TOKEN_PRIVILEGES) };
    // SAFETY: TokenPrivileges returned PrivilegeCount variable-length entries.
    let entries = unsafe {
        std::slice::from_raw_parts(actual.Privileges.as_ptr(), actual.PrivilegeCount as usize)
    };
    let enabled = entries.iter().any(|entry| {
        entry.Luid.LowPart == luid.LowPart
            && entry.Luid.HighPart == luid.HighPart
            && entry.Attributes & SE_PRIVILEGE_ENABLED != 0
    });
    if !enabled {
        unsafe {
            CloseHandle(token);
        }
        std::process::exit(PREREQUISITE_EXIT);
    }
    // Positive control: enabled SeDebugPrivilege bypasses the owner deny ACE.
    // SAFETY: fresh open with the verified enabled privilege.
    let handle = unsafe { OpenProcess(PROCESS_VM_READ, 0, pid) };
    if handle.is_null() {
        unsafe {
            CloseHandle(token);
        }
        return Err(format!(
            "SeDebugPrivilege positive control denied: {}",
            unsafe { GetLastError() }
        ));
    }
    unsafe {
        CloseHandle(handle);
    }
    // Negative control: disable the privilege again; elevation alone is not a bypass.
    privileges.Privileges[0].Attributes = 0;
    // SAFETY: same token and valid one-privilege structure.
    if unsafe { AdjustTokenPrivileges(token, 0, &privileges, 0, ptr::null_mut(), ptr::null_mut()) }
        == 0
    {
        unsafe {
            CloseHandle(token);
        }
        return Err("failed to disable SeDebugPrivilege".to_owned());
    }
    unsafe {
        CloseHandle(token);
    }
    denied_process(pid, PROCESS_VM_READ)
}

fn role_unhardened_operation(_dir: &Path, _args: &[String]) -> Result<(), String> {
    init()?;
    let result = std::thread::spawn(|| Session::unlock(&header(), &mut PASS.to_vec()))
        .join()
        .map_err(|_| "unhardened thread panicked".to_owned())?;
    match result {
        Err(wsecret_core::Error::MemoryProtection) => Ok(()),
        other => Err(format!(
            "unhardened operation returned {}, want MEMORY_PROTECTION",
            session_outcome(&other)
        )),
    }
}

fn role_pre_unlock_admission(dir: &Path, _args: &[String]) -> Result<(), String> {
    init()?;
    let stop = dir.join("ordinary-stop");
    let ordinary = std::thread::spawn(move || {
        while !stop.exists() {
            std::thread::sleep(Duration::from_millis(10));
        }
    });
    let result = Session::unlock(&header(), &mut PASS.to_vec());
    write(&dir.join("ordinary-stop"), b"stop")?;
    ordinary
        .join()
        .map_err(|_| "ordinary thread panicked".to_owned())?;
    match result {
        Err(wsecret_core::Error::MemoryProtection) => Ok(()),
        other => Err(format!(
            "pre-unlock admission returned {}",
            session_outcome(&other)
        )),
    }
}

fn role_residency(dir: &Path, _args: &[String]) -> Result<(), String> {
    init()?;
    let session = unlock()?;
    let stop = dir.join("ordinary-stop");
    let (tid_tx, tid_rx) = std::sync::mpsc::channel();
    let ordinary = std::thread::spawn(move || {
        tid_tx
            .send(unsafe { GetCurrentThreadId() })
            .expect("ordinary tid");
        while !stop.exists() {
            std::thread::sleep(Duration::from_millis(10));
        }
    });
    let tid = tid_rx.recv().map_err(|e| e.to_string())?;
    let start = Instant::now();
    while !security::process_is_poisoned() && start.elapsed() < Duration::from_secs(3) {
        std::thread::sleep(Duration::from_millis(10));
    }
    if !security::process_is_poisoned() {
        return Err("watchdog did not poison an unregistered residency thread".to_owned());
    }
    let detection = start.elapsed();
    if detection > Duration::from_millis(600) {
        return Err(format!(
            "watchdog detection took {detection:?}, beyond the 250 ms poll bound plus scheduling tolerance"
        ));
    }
    // Documented residual: the unregistered thread itself remains openable
    // for context hijacking; detection/poison is the bounded mitigation.
    // SAFETY: fresh open of that deliberately unhardened thread.
    let residual = unsafe { OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT, 0, tid) };
    if residual.is_null() {
        return Err(format!(
            "unhardened residual thread open failed: {}",
            unsafe { GetLastError() }
        ));
    }
    unsafe {
        CloseHandle(residual);
    }
    let lock_start = Instant::now();
    while !session.is_locked() && lock_start.elapsed() < Duration::from_secs(3) {
        std::thread::sleep(Duration::from_millis(10));
    }
    if !session.is_locked() {
        return Err("session was not auto-locked after drain".to_owned());
    }
    match session.derive_chain(&[]) {
        Err(wsecret_core::Error::MemoryProtection) => {}
        other => return Err(format!("poisoned operation returned {other:?}")),
    }
    write(&dir.join("ordinary-stop"), b"stop")?;
    ordinary
        .join()
        .map_err(|_| "ordinary thread panicked".to_owned())?;
    Ok(())
}

fn role_registered_host(dir: &Path, _args: &[String]) -> Result<(), String> {
    init()?;
    let ready = dir.join("host-ready");
    let stop = dir.join("host-stop");
    let ready2 = ready.clone();
    let host = std::thread::spawn(move || {
        let _registration = security::register_hardened_thread().expect("register host thread");
        fs::write(ready2, b"ready").expect("host ready");
        while !stop.exists() {
            std::thread::sleep(Duration::from_millis(10));
        }
    });
    wait_file(&ready, Duration::from_secs(5))?;
    let mut session = unlock()?;
    std::thread::sleep(Duration::from_millis(400));
    if security::process_is_poisoned() || session.is_locked() {
        return Err("registered host thread destabilized residency".to_owned());
    }
    session.lock();
    write(&dir.join("host-stop"), b"stop")?;
    host.join().map_err(|_| "host thread panicked".to_owned())
}

fn role_overlapping_unlock(dir: &Path, _args: &[String]) -> Result<(), String> {
    init()?;
    let mut a = unlock()?;
    let (started_tx, started_rx) = std::sync::mpsc::channel();
    let (result_tx, result_rx) = std::sync::mpsc::channel();
    let b = security::spawn_hardened_thread(move || {
        started_tx.send(()).expect("started");
        let mut slow_header = header();
        slow_header.ops_limit = 1_000_000;
        let result = Session::unlock(&slow_header, &mut PASS.to_vec());
        result_tx.send(result).expect("B result");
    })
    .map_err(|e| format!("spawn B: {e}"))?;
    started_rx.recv().map_err(|e| e.to_string())?;
    a.lock();
    let stop = dir.join("ordinary-stop");
    let ordinary = std::thread::spawn(move || {
        while !stop.exists() {
            std::thread::sleep(Duration::from_millis(10));
        }
    });
    let result = result_rx
        .recv_timeout(Duration::from_secs(20))
        .map_err(|e| format!("B did not drain: {e}"))?;
    write(&dir.join("ordinary-stop"), b"stop")?;
    ordinary
        .join()
        .map_err(|_| "ordinary thread panicked".to_owned())?;
    b.join().map_err(|e| format!("B join: {e}"))?;
    match result {
        Err(wsecret_core::Error::MemoryProtection) => Ok(()),
        other => Err(format!(
            "poisoned overlapping unlock published: {}",
            session_outcome(&other)
        )),
    }
}

/// Managed SSH child (`spawn_ssh_child` target): verifies its launch
/// environment contract — `SSH_AUTH_SOCK` names the verified endpoint
/// exactly and the legacy `SECRET_AGENT` variable is absent even though the
/// launcher deliberately set one — then waits for the parent's stop signal.
fn role_ssh_child(dir: &Path, _args: &[String]) -> Result<(), String> {
    if let Some(value) = std::env::var_os("SECRET_AGENT") {
        return Err(format!(
            "legacy SECRET_AGENT leaked into the SSH child: {value:?}"
        ));
    }
    let sock =
        std::env::var_os("SSH_AUTH_SOCK").ok_or("SSH_AUTH_SOCK missing in the SSH child")?;
    if sock != OsStr::new(SSH_ENDPOINT) {
        return Err(format!(
            "SSH_AUTH_SOCK is {sock:?}, want {SSH_ENDPOINT:?}"
        ));
    }
    wait_stop(dir)
}

fn role_handle_table(_dir: &Path, args: &[String]) -> Result<(), String> {
    let launcher = args[0].parse().map_err(|e| format!("launcher: {e}"))?;
    let process = args[1]
        .parse()
        .map_err(|e| format!("process handle: {e}"))?;
    let thread = args[2].parse().map_err(|e| format!("thread handle: {e}"))?;
    let reduced = args[3]
        .parse()
        .map_err(|e| format!("reduced handle: {e}"))?;
    let thread_type = args[4]
        .parse()
        .map_err(|e| format!("thread object type: {e}"))?;
    check_handle_table(launcher, process, thread, reduced, thread_type)
}

/// P4d/P4h launcher: the managed SSH launch (`spawn_ssh_child`) with the
/// birth-descriptor and launcher handle-table probes. No capability
/// transport exists here — the child receives only the duplicated ordinary
/// standard handles and its sanitized environment.
fn role_ssh_launcher(dir: &Path, _args: &[String]) -> Result<(), String> {
    // A legacy capability variable in the launcher's own environment must
    // never reach the managed SSH child: `spawn_ssh_child` strips it
    // unconditionally (checked by the `ssh-child` role).
    // SAFETY: set before `init()`/any worker thread exists in this helper.
    unsafe {
        std::env::set_var("SECRET_AGENT", "404");
    }
    init()?;
    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    let role = OsStr::new("--p4-role");
    let child_role = OsStr::new("ssh-child");
    let argv: Vec<&OsStr> = vec![exe.as_os_str(), role, child_role, dir.as_os_str()];
    let child = spawn_ssh_child(exe.as_os_str(), &argv, OsStr::new(SSH_ENDPOINT))
        .map_err(|e| e.to_string())?;

    let (original_process, original_thread, reduced) = child.handle_evidence_for_test();
    // OWNER_RIGHTS permits this limited fresh open; it identifies the thread
    // kernel object type without retaining any sensitive thread right.
    // SAFETY: fresh limited-right open of the child primary thread.
    let limited = unsafe {
        OpenThread(
            THREAD_QUERY_LIMITED_INFORMATION,
            0,
            child.primary_thread_id(),
        )
    };
    if limited.is_null() {
        return Err(format!("limited child-thread open: {}", unsafe {
            GetLastError()
        }));
    }
    let thread_type = object_type_of(std::process::id() as usize, limited as usize)?;
    unsafe {
        CloseHandle(limited);
    }
    // Inspect immediately, before any subsequent launcher operation can reuse
    // the just-closed original handle values.
    check_handle_table(
        std::process::id() as usize,
        original_process,
        original_thread,
        reduced,
        thread_type,
    )?;

    // P4d: CreateProcessW's creation return is the coordinated birth
    // observation. Fresh opens (not the returned full handles) must already be
    // denied for BOTH the process and its primary thread.
    denied_process(child.id(), PROCESS_VM_READ)?;
    denied_thread(child.primary_thread_id(), THREAD_GET_CONTEXT)?;
    write(
        &dir.join("ready"),
        format!(
            "launcher={}\nchild={}\ntid={}\noriginal_process={}\noriginal_thread={}\nreduced={}\nthread_type={}\n",
            std::process::id(),
            child.id(),
            child.primary_thread_id(),
            original_process,
            original_thread,
            reduced,
            thread_type
        )
        .as_bytes(),
    )?;

    // The PARENT spawns external helpers, so the launcher does not acquire a
    // new full process handle that could reuse an original value.
    wait_file(&dir.join("helpers-done"), Duration::from_secs(20))?;
    // The retained reduced handle cannot be amplified back to VM_READ.
    let mut amplified = ptr::null_mut();
    // SAFETY: source is the retained reduced child handle.
    let amplified_ok = unsafe {
        DuplicateHandle(
            GetCurrentProcess(),
            reduced as HANDLE,
            GetCurrentProcess(),
            &mut amplified,
            PROCESS_VM_READ,
            0,
            0,
        )
    };
    if amplified_ok != 0 {
        unsafe {
            CloseHandle(amplified);
        }
        return Err("reduced child handle was amplified to VM_READ".to_owned());
    }
    // A fresh same-user open of the hardened launcher itself is also denied.
    denied_process(std::process::id(), PROCESS_DUP_HANDLE)?;
    denied_process(child.id(), PROCESS_DUP_HANDLE)?;
    write(&dir.join("local-done"), b"done")?;
    wait_stop(dir)?;
    let code = child.wait_for_exit().map_err(|e| e.to_string())?;
    if code == 0 {
        Ok(())
    } else {
        Err(format!("ssh child exit {code}"))
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
struct HandleEntry {
    object: usize,
    owner_pid: usize,
    value: usize,
    access: u32,
    creator_backtrace: u16,
    object_type: u16,
    attributes: u32,
    reserved: u32,
}

#[link(name = "ntdll")]
unsafe extern "system" {
    fn NtQuerySystemInformation(class: u32, info: *mut c_void, len: u32, needed: *mut u32) -> i32;
}

fn handle_entries() -> Result<Vec<HandleEntry>, String> {
    let mut size = 1024 * 1024u32;
    for _ in 0..6 {
        let mut buffer = vec![0u8; size as usize];
        let mut needed = 0u32;
        // SystemHandleInformation = 64 (SYSTEM_HANDLE_INFORMATION_EX).
        let status = unsafe {
            NtQuerySystemInformation(64, buffer.as_mut_ptr() as *mut c_void, size, &mut needed)
        };
        if status == 0 {
            // SAFETY: successful EX response starts with two usize counts.
            let count = unsafe { (buffer.as_ptr() as *const usize).read_unaligned() };
            let offset = 2 * std::mem::size_of::<usize>();
            let entry_size = std::mem::size_of::<HandleEntry>();
            if offset + count * entry_size > buffer.len() {
                return Err("truncated handle table".to_owned());
            }
            let mut out = Vec::with_capacity(count);
            for index in 0..count {
                // SAFETY: bounds checked above; entries are packed C records.
                out.push(unsafe {
                    (buffer.as_ptr().add(offset + index * entry_size) as *const HandleEntry)
                        .read_unaligned()
                });
            }
            return Ok(out);
        }
        if needed > size {
            size = needed + 4096;
        } else {
            size *= 2;
        }
    }
    Err("NtQuerySystemInformation(handle table) did not converge".to_owned())
}

fn object_type_of(owner: usize, handle: usize) -> Result<u16, String> {
    handle_entries()?
        .iter()
        .find(|entry| entry.owner_pid == owner && entry.value == handle)
        .map(|entry| entry.object_type)
        .ok_or_else(|| format!("handle {handle:#x} is absent from pid {owner}"))
}

fn check_handle_table(
    launcher: usize,
    original_process: usize,
    original_thread: usize,
    reduced: usize,
    thread_type: u16,
) -> Result<(), String> {
    let entries = handle_entries()?;
    let mine: Vec<_> = entries
        .iter()
        .filter(|entry| entry.owner_pid == launcher)
        .collect();
    let reduced_entry = mine
        .iter()
        .find(|entry| entry.value == reduced)
        .ok_or_else(|| "reduced child handle is absent".to_owned())?;
    let process_type = reduced_entry.object_type;
    // Handle VALUES can be reused after close. A residual original must also
    // have the same kernel object type and sensitive access; a reused file or
    // limited-wait handle value is not evidence of a full-access survivor.
    if mine.iter().any(|entry| {
        (entry.value == original_process
            && entry.object_type == process_type
            && entry.access & PROCESS_VM_READ != 0)
            || (entry.value == original_thread
                && entry.object_type == thread_type
                && entry.access & THREAD_GET_CONTEXT != 0)
    }) {
        return Err("an original full-access child handle remains in the launcher".to_owned());
    }
    let wanted = SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION;
    if reduced_entry.access & wanted != wanted || reduced_entry.access & PROCESS_VM_READ != 0 {
        return Err(format!(
            "reduced handle access is {:#x}",
            reduced_entry.access
        ));
    }
    Ok(())
}

fn read_remote(handle: HANDLE, address: usize) -> Option<[u8; 32]> {
    let mut out = [0u8; 32];
    let mut read = 0usize;
    // SAFETY: handle has PROCESS_VM_READ; output points to 32 writable bytes.
    let ok = unsafe {
        ReadProcessMemory(
            handle,
            address as *const c_void,
            out.as_mut_ptr() as *mut c_void,
            32,
            &mut read,
        )
    };
    if ok == 0 || read != 32 {
        None
    } else {
        Some(out)
    }
}

fn role_memory_target(dir: &Path, _args: &[String]) -> Result<(), String> {
    init()?;
    let session = unlock()?;
    write(
        &dir.join("ready"),
        format!("key={}\n", session.key_address_for_test()).as_bytes(),
    )?;
    wait_file(&dir.join("attacker-ready"), Duration::from_secs(15))?;
    session
        .with_key_for_test(|_| {
            let address = transient_key_address_for_test();
            write(&dir.join("window-begin"), address.to_string().as_bytes()).expect("window begin");
            std::thread::sleep(Duration::from_millis(600));
            write(&dir.join("window-end"), b"end").expect("window end");
        })
        .map_err(|e| format!("transient window: {e}"))?;
    wait_stop(dir)
}

fn role_memory_attacker(dir: &Path, args: &[String]) -> Result<(), String> {
    let launcher_pid: u32 = args[0].parse().map_err(|e| format!("launcher pid: {e}"))?;
    let child_handle: usize = args[1].parse().map_err(|e| format!("child handle: {e}"))?;
    let key_address: usize = args[2].parse().map_err(|e| format!("key address: {e}"))?;
    // P4e: the external launcher is unhardened, so its retained full-access
    // child handle can be duplicated AFTER the child hardened itself.
    // SAFETY: fresh open of the unhardened external launcher.
    let launcher = unsafe { OpenProcess(PROCESS_DUP_HANDLE, 0, launcher_pid) };
    if launcher.is_null() {
        return Err(format!("open external launcher: {}", unsafe {
            GetLastError()
        }));
    }
    let mut child = ptr::null_mut();
    // SAFETY: duplicates the launcher's retained child handle into this process.
    let ok = unsafe {
        DuplicateHandle(
            launcher,
            child_handle as HANDLE,
            GetCurrentProcess(),
            &mut child,
            PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_DUP_HANDLE,
            0,
            0,
        )
    };
    unsafe {
        CloseHandle(launcher);
    }
    if ok == 0 {
        return Err(format!("duplicate external child handle: {}", unsafe {
            GetLastError()
        }));
    }
    let expected = expected_key();
    let idle = read_remote(child, key_address).ok_or_else(|| "read at-rest key".to_owned())?;
    if idle == expected {
        return Err("P4i: idle at-rest key was plaintext".to_owned());
    }
    write(&dir.join("attacker-ready"), b"ready")?;
    let begin = wait_file(&dir.join("window-begin"), Duration::from_secs(10))?;
    let transient: usize = String::from_utf8(begin)
        .map_err(|e| e.to_string())?
        .trim()
        .parse()
        .map_err(|e| format!("transient address: {e}"))?;
    let mut saw_plaintext = false;
    while !dir.join("window-end").exists() {
        if read_remote(child, transient).as_ref() == Some(&expected) {
            saw_plaintext = true;
        }
        if read_remote(child, key_address).as_ref() == Some(&expected) {
            return Err("P4j: at-rest buffer became plaintext during operation".to_owned());
        }
    }
    if !saw_plaintext {
        return Err("P4j: continuous polling never observed the transient plaintext".to_owned());
    }
    std::thread::sleep(Duration::from_millis(100));
    if read_remote(child, transient).as_ref() == Some(&expected) {
        return Err("P4j: transient plaintext remained after the operation".to_owned());
    }
    if read_remote(child, key_address).as_ref() == Some(&expected) {
        return Err("P4j: at-rest plaintext after the operation".to_owned());
    }
    unsafe {
        CloseHandle(child);
    }
    Ok(())
}

fn role_watchdog_death(_dir: &Path, _args: &[String]) -> Result<(), String> {
    init()?;
    // SAFETY: no watchdog/other worker exists yet in this helper process.
    unsafe {
        std::env::set_var("WSECRET_TEST_KILL_WATCHDOG", "1");
    }
    let mut slow = header();
    slow.ops_limit = 100_000_000;
    // The main thread blocks in the non-interruptible KDF. The independent
    // monitor must ExitProcess within one heartbeat timeout.
    let _ = Session::unlock(&slow, &mut PASS.to_vec());
    Err("watchdog-death containment returned to secret handling".to_owned())
}

fn run_parent() -> Result<(), String> {
    // P4a/P4b/P4c against one live hardened process with primary, worker, and
    // watchdog threads.
    let dir = test_dir("rights");
    let target = Running::start("hardened-target", &dir, &[])?;
    let ready = ready_map(&dir)?;
    let pid = number(&ready, "pid")? as u32;
    let primary = number(&ready, "primary")?.to_string();
    let worker = number(&ready, "worker")?.to_string();
    let watchdog = number(&ready, "watchdog")?.to_string();
    let output = run_role(
        "probe-rights",
        &dir,
        &[pid.to_string(), primary, worker, watchdog],
    )?;
    assert_success(&output).map_err(|e| format!("P4a/P4f thread rights:\n{e}"))?;
    println!("PASS P4a/P4f: sensitive process/thread rights denied individually");

    let output = run_role("write-dac", &dir, &[pid.to_string(), "deny".to_owned()])?;
    assert_success(&output).map_err(|e| format!("P4b hardened WRITE_DAC:\n{e}"))?;
    let control_dir = test_dir("owner-control");
    let control = Running::start("control-target", &control_dir, &[])?;
    let control_pid = number(&ready_map(&control_dir)?, "pid")? as u32;
    let output = run_role(
        "write-dac",
        &control_dir,
        &[control_pid.to_string(), "allow".to_owned()],
    )?;
    assert_success(&output).map_err(|e| format!("P4b no-OWNER_RIGHTS control:\n{e}"))?;
    assert_success(&control.stop()?).map_err(|e| format!("control stop:\n{e}"))?;
    println!("PASS P4b: OWNER_RIGHTS suppresses implicit owner WRITE_DAC");

    let output = run_role("privileged-probe", &dir, &[pid.to_string()])?;
    if output.status.code() == Some(PREREQUISITE_EXIT) {
        println!(
            "PREREQUISITE P4c: elevated SeDebugPrivilege token unavailable; positive/negative privileged controls not executed"
        );
    } else {
        assert_success(&output).map_err(|e| format!("P4c:\n{e}"))?;
        println!("PASS P4c: verified SeDebugPrivilege bypass + elevated-disabled negative control");
    }
    assert_success(&target.stop()?).map_err(|e| format!("target stop:\n{e}"))?;

    for (role, label) in [
        ("unhardened-operation", "P4f(b) unhardened host operation"),
        ("pre-unlock-admission", "P4f(c) pre-unlock admission"),
        ("residency", "P4f(c') residency poison + drain auto-lock"),
        ("registered-host", "P4f(d) hardened registered host thread"),
        (
            "overlapping-unlock",
            "R2-A overlapping unlock drain/publication",
        ),
    ] {
        let scenario = test_dir(role);
        let output = run_role(role, &scenario, &[])?;
        assert_success(&output).map_err(|e| format!("{label}:\n{e}"))?;
        println!("PASS {label}");
    }

    let scenario = test_dir("watchdog-death");
    let output = run_role("watchdog-death", &scenario, &[])?;
    let code = output.status.code().map(|code| code as u32);
    if code != Some(security::WATCHDOG_DEATH_EXIT_CODE) {
        return Err(format!(
            "P4f(c''') watchdog death:\n{}",
            output_text(&output)
        ));
    }
    println!("PASS P4f(c'''): independent monitor exits while main thread is in KDF");

    let scenario = test_dir("ssh-launcher");
    let launcher = Running::start("ssh-launcher", &scenario, &[])?;
    let ready = ready_map(&scenario)?;
    let child_pid = number(&ready, "child")? as u32;
    let child_tid = number(&ready, "tid")? as u32;
    let output = run_role(
        "probe-rights",
        &scenario,
        &[child_pid.to_string(), child_tid.to_string()],
    )?;
    assert_success(&output).map_err(|e| format!("P4d external birth probe:\n{e}"))?;
    let output = run_role(
        "handle-table",
        &scenario,
        &[
            ready["launcher"].clone(),
            ready["original_process"].clone(),
            ready["original_thread"].clone(),
            ready["reduced"].clone(),
            ready["thread_type"].clone(),
        ],
    )?;
    assert_success(&output).map_err(|e| format!("P4h external handle-table probe:\n{e}"))?;
    write(&scenario.join("helpers-done"), b"done")?;
    wait_file(&scenario.join("local-done"), Duration::from_secs(10))?;
    assert_success(&launcher.stop()?).map_err(|e| format!("P4d/P4h launcher:\n{e}"))?;
    println!("PASS P4d/P4h: managed SSH launch birth protection + launcher handle-table hygiene");

    // P4e/P4i/P4j: this parent deliberately remains an unhardened external
    // launcher and retains its full-access child handle.
    let scenario = test_dir("memory");
    let target = Running::start("memory-target", &scenario, &[])?;
    let ready = ready_map(&scenario)?;
    let key = number(&ready, "key")?;
    let child_ref = target.child.as_ref().expect("memory child");
    let launcher_pid = std::process::id();
    let child_handle = child_ref.as_raw_handle() as usize;
    let output = run_role(
        "memory-attacker",
        &scenario,
        &[
            launcher_pid.to_string(),
            child_handle.to_string(),
            key.to_string(),
        ],
    )?;
    assert_success(&output).map_err(|e| format!("P4e/P4i/P4j:\n{e}"))?;
    assert_success(&target.stop()?).map_err(|e| format!("memory target stop:\n{e}"))?;
    println!(
        "PASS P4e/P4i/P4j: external-handle residual; ciphertext at rest; transient-only plaintext"
    );

    // P4g: real wsecret.exe, forced SetSecurityInfo failure before store open.
    let scenario = test_dir("startup-failure");
    let missing = scenario.join("does-not-exist.secret");
    let output = Command::new(env!("CARGO_BIN_EXE_wsecret"))
        .arg("show")
        .arg("x")
        .env("SECRET_STORE", &missing)
        .env("WSECRET_TEST_FAIL_SET_SECURITY_INFO", "1")
        .output()
        .map_err(|e| format!("run wsecret P4g: {e}"))?;
    if output.status.code() != Some(1)
        || !output.stdout.is_empty()
        || !String::from_utf8_lossy(&output.stderr).contains("memory protection")
        || String::from_utf8_lossy(&output.stderr).contains("doesn't exist")
    {
        return Err(format!("P4g startup failure:\n{}", output_text(&output)));
    }
    println!("PASS P4g: startup hardening failure is fatal before store/prompt/KDF");
    Ok(())
}

fn role_main(role: &str, dir: &Path, args: &[String]) -> Result<(), String> {
    match role {
        "probe-rights" => role_probe_rights(dir, args),
        "hardened-target" => role_hardened_target(dir, args),
        "control-target" => role_control_target(dir, args),
        "write-dac" => role_write_dac(dir, args),
        "privileged-probe" => role_privileged_probe(dir, args),
        "unhardened-operation" => role_unhardened_operation(dir, args),
        "pre-unlock-admission" => role_pre_unlock_admission(dir, args),
        "residency" => role_residency(dir, args),
        "registered-host" => role_registered_host(dir, args),
        "overlapping-unlock" => role_overlapping_unlock(dir, args),
        "ssh-child" => role_ssh_child(dir, args),
        "handle-table" => role_handle_table(dir, args),
        "ssh-launcher" => role_ssh_launcher(dir, args),
        "memory-target" => role_memory_target(dir, args),
        "memory-attacker" => role_memory_attacker(dir, args),
        "watchdog-death" => role_watchdog_death(dir, args),
        other => Err(format!("unknown P4 role {other}")),
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let result = if args.get(1).map(String::as_str) == Some("--p4-role") {
        let role = args.get(2).expect("role").clone();
        let dir = PathBuf::from(args.get(3).expect("role directory"));
        role_main(&role, &dir, &args[4..])
    } else {
        run_parent()
    };
    if let Err(error) = result {
        eprintln!("P4 FAILURE: {error}");
        std::process::exit(1);
    }
}
