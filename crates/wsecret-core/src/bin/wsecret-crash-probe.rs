//! `wsecret-crash-probe`: test-support writer process for the §7.4 E-row
//! concurrency and crash-consistency checks (E1–E5). NOT part of the shipped
//! product; it drives the real `wsecret-core` mutation path from a separate
//! process so tests can observe cross-process writer serialization
//! (`Global\wsecret-store-*`), external-replacement conflicts and hard kills
//! at the §5.6 checkpoints.
//!
//! Usage:
//!
//! ```text
//! wsecret-crash-probe write <store> <pass-hex> <name-hex> <value-hex>
//!     [hold <ready-file> <release-file>]   hold the writer mutex first
//!     [fault <point> <fault>]              arm a one-shot fault seam
//!     [kill <point>]                       arm a hard kill at <point>
//! wsecret-crash-probe hold <store> <ready-file> <release-file>
//!     hold the writer mutex only (no write)
//! ```
//!
//! `<point>`: `before` | `mid` | `after` | `post` (§5.6 checkpoints
//! (i)/(ii)/(iii) and post-(iii)); `<fault>`: `io` | `cancel` | `panic` |
//! `short` | `kill`.
//!
//! Output: `OK <state> <warnings>` (exit 0) or `ERR <status> <state>`
//! (exit 2), one line, machine-readable. A `kill` fault terminates the
//! process at the seam with exit code [`PROBE_KILL_EXIT`] and prints
//! nothing.

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use wsecret_core::session::Session;
use wsecret_core::store::{ScanOutcome, Store};
use wsecret_core::{CommitState, Error};

/// Exit code reported when an injected kill terminates this process at a
/// §5.6 checkpoint (E5).
pub const PROBE_KILL_EXIT: u32 = 0xE5;

fn usage() -> ! {
    eprintln!(
        "usage: wsecret-crash-probe write <store> <pass-hex> <name-hex> <value-hex> \
         [snap] [hold <ready> <release>] [fault <point> <fault>] [kill <point>]\n\
         \x20      wsecret-crash-probe create <store> [fault <point> <fault>] [kill <point>]\n\
         \x20      wsecret-crash-probe hold <store> <ready> <release>"
    );
    std::process::exit(3)
}

fn unhex(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect()
}

fn state_code(state: CommitState) -> u32 {
    state as u32
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let Some(cmd) = args.first().map(String::as_str) else { usage() };

    match cmd {
        "hold" => {
            // hold <store> <ready> <release>
            if args.len() != 4 {
                usage();
            }
            let (mut store, release) = open_hold(&args[1], &args[2], &args[3]);
            wait_release(&release);
            store.unlock_writers();
            println!("OK {} {}", state_code(CommitState::NotCommitted), 0);
        }
        "write" => {
            if args.len() < 5 {
                usage();
            }
            let store_path = PathBuf::from(&args[1]);
            let pass = unhex(&args[2]).unwrap_or_else(|| usage());
            let name = unhex(&args[3]).unwrap_or_else(|| usage());
            let value = unhex(&args[4]).unwrap_or_else(|| usage());

            let mut hold: Option<(PathBuf, PathBuf)> = None;
            let mut snap = false;
            let mut i = 5;
            while i < args.len() {
                match args[i].as_str() {
                    "snap" => {
                        snap = true;
                        i += 1;
                    }
                    "hold" if i + 2 < args.len() => {
                        hold = Some((PathBuf::from(&args[i + 1]), PathBuf::from(&args[i + 2])));
                        i += 3;
                    }
                    "fault" if i + 2 < args.len() => {
                        let point = parse_point(&args[i + 1]);
                        let fault = parse_fault(&args[i + 2]);
                        arm(point, fault);
                        i += 3;
                    }
                    "kill" if i + 1 < args.len() => {
                        arm(parse_point(&args[i + 1]), FaultArg::Kill);
                        i += 2;
                    }
                    _ => usage(),
                }
            }

            let mut store = match Store::open(&store_path) {
                Ok((store, _)) => store,
                Err(e) => {
                    println!("ERR {} {} {:?}", e.status() as u32, state_code(CommitState::NotCommitted), e);
                    std::process::exit(2);
                }
            };
            let header = store.header().clone();
            let mut pass = pass;
            let session = match Session::unlock(&header, &mut pass) {
                Ok(session) => session,
                Err(e) => {
                    println!("ERR {} {} {:?}", e.status() as u32, state_code(CommitState::NotCommitted), e);
                    std::process::exit(2);
                }
            };

            // `snap`: snapshot the write target BEFORE the critical section —
            // models a writer whose scan predates its lock (upstream's
            // scan-before-lock shape, plan §5.6 point 2's stale-slot race).
            let mut snapped: Option<u64> = None;
            if snap {
                snapped = Some(match store.find(&session, &name, false) {
                    Ok(ScanOutcome::Found { slot, .. }) => slot,
                    Ok(ScanOutcome::NotFound { .. }) => {
                        std::fs::metadata(&store_path).expect("stat store").len()
                    }
                    Err(e) => {
                        println!(
                            "ERR {} {} {:?}",
                            e.status() as u32,
                            state_code(CommitState::NotCommitted),
                            e
                        );
                        std::process::exit(2);
                    }
                });
            }

            // §5.6 point 2: a wsecret writer holds `Global\wsecret-store-*`
            // across the WHOLE scan-modify-write critical section. (The
            // Windows byte-range lock of point 3 is mandatory — a scan that
            // ran during another writer's write would fail on the locked
            // slot — which is exactly why the mutex spans the scan.)
            if store.lock_writers().is_err() {
                println!("ERR {} {}", Error::Busy.status() as u32, state_code(CommitState::NotCommitted));
                std::process::exit(2);
            }
            if let Some((ready, release)) = &hold {
                std::fs::write(ready, b"held").expect("probe: ready marker");
                wait_release(release);
            }

            let outcome = match snapped {
                Some(slot) => store.write_slot(slot, &session, &name, &value),
                None => match store.find(&session, &name, false) {
                    Ok(ScanOutcome::Found { slot, .. }) => {
                        store.write_slot(slot, &session, &name, &value)
                    }
                    Ok(ScanOutcome::NotFound { .. }) => {
                        store.append_or_reuse(None, &session, &name, &value)
                    }
                    Err(e) => {
                        store.unlock_writers();
                        println!(
                            "ERR {} {} {:?}",
                            e.status() as u32,
                            state_code(CommitState::NotCommitted),
                            e
                        );
                        std::process::exit(2);
                    }
                },
            };
            store.unlock_writers();
            match outcome {
                Ok(receipt) => {
                    println!("OK {} {}", state_code(receipt.state), receipt.warnings);
                }
                Err(failure) => {
                    println!("ERR {} {} {:?}", failure.status() as u32, state_code(failure.state), failure.error);
                    std::process::exit(2);
                }
            }
        }
        "create" => {
            // create <store> [fault <point> <fault>] [kill <point>]
            if args.len() < 2 {
                usage();
            }
            let store_path = PathBuf::from(&args[1]);
            let mut i = 2;
            while i < args.len() {
                match args[i].as_str() {
                    "fault" if i + 2 < args.len() => {
                        arm(parse_point(&args[i + 1]), parse_fault(&args[i + 2]));
                        i += 3;
                    }
                    "kill" if i + 1 < args.len() => {
                        arm(parse_point(&args[i + 1]), FaultArg::Kill);
                        i += 2;
                    }
                    _ => usage(),
                }
            }
            match Store::create(&store_path, wsecret_core::format::OPS_LIMIT_MIN) {
                Ok((_, _, receipt)) => {
                    println!("OK {} {}", state_code(receipt.state), receipt.warnings);
                }
                Err(failure) => {
                    println!("ERR {} {} {:?}", failure.status() as u32, state_code(failure.state), failure.error);
                    std::process::exit(2);
                }
            }
        }
        _ => usage(),
    }
}

fn open_hold(store: &str, ready: &str, release: &str) -> (Store, PathBuf) {
    let (mut store, _) = match Store::open(Path::new(store)) {
        Ok(opened) => opened,
        Err(e) => {
            eprintln!("probe: open failed: {e}");
            std::process::exit(2);
        }
    };
    if store.lock_writers().is_err() {
        eprintln!("probe: writer mutex busy");
        std::process::exit(2);
    }
    std::fs::write(Path::new(ready), b"held").expect("probe: ready marker");
    (store, PathBuf::from(release))
}

fn wait_release(release: &Path) {
    let deadline = Instant::now() + Duration::from_secs(60);
    while Instant::now() < deadline {
        if release.exists() {
            return;
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    eprintln!("probe: release marker never appeared");
    std::process::exit(3);
}

// ---------------------------------------------------------------------------
// fault seams (compiled only in debug/test builds — see `wsecret_core::fault`)
// ---------------------------------------------------------------------------

/// Which §5.6 checkpoint the seam fires at (parsed form; profile-independent).
enum PointArg {
    Before,
    Mid,
    After,
    Post,
}

/// Which fault the seam injects (parsed form; profile-independent).
enum FaultArg {
    Io,
    Cancel,
    Panic,
    Short,
    Kill,
}

fn parse_point(s: &str) -> PointArg {
    match s {
        "before" => PointArg::Before,
        "mid" => PointArg::Mid,
        "after" => PointArg::After,
        "post" => PointArg::Post,
        _ => usage(),
    }
}

fn parse_fault(s: &str) -> FaultArg {
    match s {
        "io" => FaultArg::Io,
        "cancel" => FaultArg::Cancel,
        "panic" => FaultArg::Panic,
        "short" => FaultArg::Short,
        "kill" => FaultArg::Kill,
        _ => usage(),
    }
}

fn arm(point: PointArg, fault: FaultArg) {
    #[cfg(feature = "fault-injection")]
    {
        use wsecret_core::fault::{arm as arm_seam, Fault, Point};
        let point = match point {
            PointArg::Before => Point::BeforeWrite,
            PointArg::Mid => Point::MidWrite,
            PointArg::After => Point::AfterWrite,
            PointArg::Post => Point::AfterFlush,
        };
        let fault = match fault {
            FaultArg::Io => Fault::Io,
            FaultArg::Cancel => Fault::Cancel,
            FaultArg::Panic => Fault::Panic,
            FaultArg::Short => Fault::ShortWrite,
            FaultArg::Kill => Fault::Kill,
        };
        arm_seam(point, fault).expect("valid seam combination");
    }
    #[cfg(not(feature = "fault-injection"))]
    {
        let _ = (point, fault);
        eprintln!("probe: fault injection is compiled only with the `fault-injection` feature");
        std::process::exit(3);
    }
}
