//! Test-only fault-injection seams for the §5.6 mutation checkpoints
//! (plan §5.6 points 4–5, §7.3 C16/C16b, §7.4 U5/E-rows).
//!
//! This module compiles ONLY under the `fault-injection` cargo feature (test
//! tooling: the in-process suites and the `wsecret-crash-probe` helper
//! binary). Production builds contain no injection code at all — the seam
//! call sites in [`crate::store`] are `#[cfg]`-stripped.
//!
//! One-shot seams: [`arm`] registers a fault at exactly one checkpoint; the
//! first [`take`] at that checkpoint consumes it. The checkpoints map onto
//! plan §5.6 point 5's trichotomy:
//!
//! | [`Point`]     | §5.6 position                              |
//! |---------------|--------------------------------------------|
//! | `BeforeWrite` | before checkpoint (i) write initiation     |
//! | `MidWrite`    | between (i) and (ii): 256 of 512 bytes landed |
//! | `AfterWrite`  | between (ii) and (iii): write done, no flush |
//! | `AfterFlush`  | after checkpoint (iii) successful flush    |

use std::sync::atomic::{AtomicU8, Ordering};

/// A mutation checkpoint (plan §5.6 point 5).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u8)]
pub enum Point {
    /// Before checkpoint (i): nothing has been written.
    BeforeWrite = 1,
    /// Between checkpoints (i) and (ii): a 256-byte prefix has landed.
    MidWrite = 2,
    /// Between checkpoints (ii) and (iii): the 512 bytes landed, no flush.
    AfterWrite = 3,
    /// After checkpoint (iii): the mutation IS committed.
    AfterFlush = 4,
}

/// What the armed seam does when it fires (plan §5.6 point 5's failure,
/// cancellation and caught-panic rows, plus the kill probe for E5).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u8)]
pub enum Fault {
    /// Inject an [`std::io::Error`] at the point.
    Io = 1,
    /// Observe cancellation at the point ([`crate::error::Error::Cancelled`]).
    Cancel = 2,
    /// Inject a panic at the point (contained by the mutation's
    /// `catch_unwind` boundary per plan §5.6 point 5 / §6).
    Panic = 3,
    /// Land only a 256-byte prefix and report a short write
    /// ([`Point::MidWrite`] only).
    ShortWrite = 4,
    /// Hard-kill this process at the point (`wsecret-crash-probe` only;
    /// models an external kill: no destructors, no flush, no further I/O).
    Kill = 5,
}

/// Exit code the `wsecret-crash-probe` helper reports when an injected kill
/// terminates it at a §5.6 checkpoint (E5 fault injection).
pub const PROBE_KILL_EXIT: u32 = 0xE5;

static POINT: AtomicU8 = AtomicU8::new(0);
static FAULT: AtomicU8 = AtomicU8::new(0);

/// Arms a one-shot fault at `point`. Test/probe only.
///
/// Rejects combinations with no §5.6 row: `ShortWrite` is defined only at
/// [`Point::MidWrite`], and nothing after checkpoint (iii) can fail the
/// mutation, so [`Point::AfterFlush`] accepts only `Panic`, `Cancel` and
/// `Kill`.
pub fn arm(point: Point, fault: Fault) -> Result<(), &'static str> {
    if fault == Fault::ShortWrite && point != Point::MidWrite {
        return Err("ShortWrite is defined only at Point::MidWrite");
    }
    if point == Point::AfterFlush && matches!(fault, Fault::Io | Fault::ShortWrite) {
        return Err("no failure row exists after checkpoint (iii)");
    }
    FAULT.store(fault as u8, Ordering::SeqCst);
    POINT.store(point as u8, Ordering::SeqCst);
    Ok(())
}

/// Clears any armed fault (teardown hygiene; a fired fault is already gone).
pub fn disarm() {
    POINT.store(0, Ordering::SeqCst);
}

/// Consumes (and returns) the armed fault at `point`, if any. One-shot: the
/// arm is cleared whether or not the caller acts on the result.
pub(crate) fn take(point: Point) -> Option<Fault> {
    if POINT.load(Ordering::SeqCst) != point as u8 {
        return None;
    }
    POINT.store(0, Ordering::SeqCst);
    match FAULT.load(Ordering::SeqCst) {
        x if x == Fault::Io as u8 => Some(Fault::Io),
        x if x == Fault::Cancel as u8 => Some(Fault::Cancel),
        x if x == Fault::Panic as u8 => Some(Fault::Panic),
        x if x == Fault::ShortWrite as u8 => Some(Fault::ShortWrite),
        x if x == Fault::Kill as u8 => Some(Fault::Kill),
        _ => None,
    }
}

/// Test-probe only: hard-kill this process at the injected point (models an
/// external kill: no destructors, no flush, no unlock).
pub(crate) fn kill_now() -> ! {
    // SAFETY: terminating the current process through its pseudo-handle is a
    // documented call; `abort` is the unreachable fallback.
    unsafe {
        let me = windows_sys::Win32::System::Threading::GetCurrentProcess();
        windows_sys::Win32::System::Threading::TerminateProcess(me, PROBE_KILL_EXIT);
    }
    std::process::abort()
}
