//! §7.4 R2-A overlapping-unlock acceptance row (plan §5.8 point 2(b),
//! closure review 14): session A unlocked, unlock B in flight in its KDF,
//! A locks → monitoring stays active through B's KDF (the watchdog window
//! closes only when B drains/erases); a poisoned B rejects publication (no
//! session is created).
//!
//! Custom harness (like `wsecret-cli/tests/p4.rs`): the §5.8 boundary is
//! process-wide — `init_process_protection` hardens this process and the
//! watchdog's poison is sticky — so each scenario runs in a ROLE subprocess
//! of this same binary and the parent asserts the role's report. The
//! watchdog window is observed through
//! [`wsecret_core::windows::security::residency_snapshot_for_test`]
//! (`watchdog_running`); the poison trigger is an ordinary UNREGISTERED
//! thread, the watchdog's exact residual-thread detector (250 ms poll).
//!
//! The pinned C KDF is stretched by parent-side calibration so every
//! assertion provably runs while B is still inside the derivation.

use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::sync::Arc;
use std::time::{Duration, Instant};

use wsecret_core::error::Error;
use wsecret_core::format::{Header, OPS_LIMIT_MIN};
use wsecret_core::session::Session;
use wsecret_core::windows::security;

const PASS: &[u8] = b"r2a acceptance passphrase";

fn header(ops_limit: u64) -> Header {
    Header {
        version: 0,
        master: [0x5a; 32],
        ops_limit,
    }
}

fn init() -> Result<(), String> {
    libhydrogen_sys::init();
    security::init_process_protection().map_err(|e| format!("init_process_protection: {e}"))
}

fn snapshot() -> (usize, usize, usize, bool, bool) {
    security::residency_snapshot_for_test()
}

/// R2-A core + poisoned publication, in one armed role process:
/// (1) A locked while B is mid-KDF → the watchdog window is STILL open;
/// (2) poisoning while B is mid-KDF → B's publication is rejected with
///     `MEMORY_PROTECTION` and NO session is created.
fn role_overlap_poison(stretch_ops: u64) -> Result<(), String> {
    init()?;
    let fast = header(OPS_LIMIT_MIN);
    let slow = header(stretch_ops);

    let mut a = Session::unlock(&fast, &mut PASS.to_vec()).map_err(|e| format!("unlock A: {e}"))?;
    let (a_sessions, _, _, _, watchdog_running) = snapshot();
    if a_sessions != 1 || !watchdog_running {
        return Err(format!(
            "after A unlocked: sessions={a_sessions} watchdog={watchdog_running}, want 1/true"
        ));
    }

    // Unlock B in flight in its (stretched) KDF, on a hardened thread.
    let (started_tx, started_rx) = mpsc::channel();
    let (result_tx, result_rx) = mpsc::channel();
    let b = security::spawn_hardened_thread(move || {
        started_tx.send(()).expect("started");
        let result = Session::unlock(&slow, &mut PASS.to_vec());
        result_tx.send(result).expect("B result");
    })
    .map_err(|e| format!("spawn B: {e}"))?;
    started_rx.recv().map_err(|e| e.to_string())?;
    std::thread::sleep(Duration::from_millis(300)); // B is inside the KDF

    // A locks while B is mid-KDF: the watchdog window must stay open
    // (R2-A: an in-flight unlock B must not lose monitoring when A locks).
    a.lock();
    let (active, pending, _, _, watchdog_running) = snapshot();
    if !watchdog_running {
        return Err(format!(
            "R2-A: monitoring closed while B is mid-KDF (active={active} pending={pending})"
        ));
    }
    if result_rx.try_recv().is_ok() {
        return Err("B already drained: the KDF stretch is too short".to_owned());
    }

    // Poison while B is mid-KDF (the watchdog's residual-thread detector).
    let stop = Arc::new(AtomicBool::new(false));
    let stop2 = stop.clone();
    let ordinary = std::thread::spawn(move || {
        while !stop2.load(Ordering::Relaxed) {
            std::thread::sleep(Duration::from_millis(10));
        }
    });
    let result = result_rx
        .recv_timeout(Duration::from_secs(30))
        .map_err(|e| format!("B never drained: {e}"))?;
    stop.store(true, Ordering::Relaxed);
    ordinary
        .join()
        .map_err(|_| "ordinary thread panicked".to_owned())?;
    b.join().map_err(|e| format!("B join: {e}"))?;

    match result {
        Err(Error::MemoryProtection) => {}
        other => {
            return Err(format!(
                "poisoned B must reject publication, got {}",
                match other {
                    Ok(_) => "a published session".to_owned(),
                    Err(e) => format!("error {e:?}"),
                }
            ))
        }
    }
    if !security::process_is_poisoned() {
        return Err("process must be poisoned after the residual thread".to_owned());
    }
    let (active, pending, operations, _, _) = snapshot();
    if active != 0 || pending != 0 || operations != 0 {
        return Err(format!(
            "no session may exist after rejected publication: active={active} pending={pending} ops={operations}"
        ));
    }
    Ok(())
}

/// The drain rule: the watchdog window closes ONLY when B has drained —
/// open while B is mid-KDF (A locked), open while B's session is live,
/// closed after B locks/erases too.
fn role_window_closes(stretch_ops: u64) -> Result<(), String> {
    init()?;
    let fast = header(OPS_LIMIT_MIN);
    let slow = header(stretch_ops);

    let mut a = Session::unlock(&fast, &mut PASS.to_vec()).map_err(|e| format!("unlock A: {e}"))?;
    if !snapshot().4 {
        return Err("watchdog must run with a live session".to_owned());
    }

    let (started_tx, started_rx) = mpsc::channel();
    let (result_tx, result_rx) = mpsc::channel();
    let b = security::spawn_hardened_thread(move || {
        started_tx.send(()).expect("started");
        let result = Session::unlock(&slow, &mut PASS.to_vec());
        result_tx.send(result).expect("B result");
    })
    .map_err(|e| format!("spawn B: {e}"))?;
    started_rx.recv().map_err(|e| e.to_string())?;
    std::thread::sleep(Duration::from_millis(300));

    // R2-A core: A locks, B mid-KDF → still open.
    a.lock();
    if !snapshot().4 {
        return Err("R2-A: window closed while B is mid-KDF".to_owned());
    }
    drop(a);

    // B drains and publishes: a live session keeps the window open.
    let mut b_session = result_rx
        .recv_timeout(Duration::from_secs(30))
        .map_err(|e| format!("B never drained: {e}"))?
        .map_err(|e| format!("B unlock failed: {e}"))?;
    b.join().map_err(|e| format!("B join: {e}"))?;
    if !snapshot().4 {
        return Err("window must stay open while B's session is live".to_owned());
    }

    // B locks too: nothing live, nothing pending → the window closes now
    // (and only now).
    b_session.lock();
    let deadline = Instant::now() + Duration::from_secs(3);
    while snapshot().4 && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(20));
    }
    let (active, pending, operations, poisoned, watchdog_running) = snapshot();
    if watchdog_running {
        return Err(format!(
            "window must close once B drained: active={active} pending={pending} ops={operations}"
        ));
    }
    if active != 0 || pending != 0 || operations != 0 || poisoned {
        return Err(format!(
            "everything must be drained: active={active} pending={pending} ops={operations} poisoned={poisoned}"
        ));
    }
    Ok(())
}

/// Parent-side KDF calibration: one measured unlock at 1M ops yields the
/// per-op cost; the stretch targets ~2 s (bounded).
fn stretch_ops_limit() -> u64 {
    libhydrogen_sys::init();
    let t0 = Instant::now();
    let _ = Session::unlock(&header(1_000_000), &mut PASS.to_vec()).expect("calibration unlock");
    let ns_per_op = (t0.elapsed().as_nanos() as u64 / 1_000_000).max(1);
    (2_000_000_000 / ns_per_op).clamp(1_000_000, 4_000_000_000)
}

/// Spawns this binary as a role process and returns its outcome.
fn run_role(role: &str, stretch_ops: u64) -> Result<(), String> {
    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    let output = Command::new(exe)
        .arg("--r2a-role")
        .arg(role)
        .arg(stretch_ops.to_string())
        .output()
        .map_err(|e| format!("spawn role {role}: {e}"))?;
    if !output.status.success() {
        return Err(format!(
            "role {role} failed (exit {:?})\n--- stdout ---\n{}\n--- stderr ---\n{}",
            output.status.code(),
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        ));
    }
    Ok(())
}

fn run_parent() -> Result<(), String> {
    let stretch_ops = stretch_ops_limit();
    eprintln!("R2-A: KDF stretch ops_limit = {stretch_ops}");
    run_role("overlap-poison", stretch_ops)?;
    eprintln!("R2-A overlap-poison: PASS");
    run_role("window-closes", stretch_ops)?;
    eprintln!("R2-A window-closes: PASS");
    Ok(())
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let result = if args.get(1).map(String::as_str) == Some("--r2a-role") {
        let role = args.get(2).expect("role").clone();
        let stretch_ops: u64 = args
            .get(3)
            .expect("stretch ops")
            .parse()
            .expect("numeric stretch ops");
        match role.as_str() {
            "overlap-poison" => role_overlap_poison(stretch_ops),
            "window-closes" => role_window_closes(stretch_ops),
            other => Err(format!("unknown role {other}")),
        }
    } else {
        run_parent()
    };
    if let Err(error) = result {
        eprintln!("R2-A FAILURE: {error}");
        std::process::exit(1);
    }
}
