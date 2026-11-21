//! Private inherited anonymous-pipe channel (plan: "private inherited
//! anonymous-pipe channel; no named endpoint").
//!
//! The broker speaks [`crate::protocol`] frames over exactly two inherited
//! pipe handles created by the parent: the command channel (parent writes,
//! broker reads) and the response channel (broker writes, parent reads).
//! There is NO named pipe, NO socket and NO discovery endpoint: a same-user
//! process that did not create the pipes cannot address the broker at all.
//!
//! This module owns:
//!
//! - handle validation ([`ChannelEnds::from_raw`]): both ends must be
//!   distinct non-null `FILE_TYPE_PIPE` handles — anything else is refused
//!   before a single byte is read;
//! - the bounded reader thread ([`spawn_reader`]): a wsecret hardened thread
//!   that assembles frames under the protocol's handshake/inter-byte
//!   deadlines, enforces [`MAX_PAYLOAD`] BEFORE allocating, and feeds a
//!   bounded request queue. `Cancel` frames are applied immediately in the
//!   reader (cancel registry) so in-flight work stops without waiting for
//!   the queue to drain;
//! - the response writer ([`ChannelWriter`]): serialized frame writes; owns
//!   and closes the response handle;
//! - EOF/disconnect semantics: any read error or EOF (including mid-frame)
//!   sets [`ReaderSignals::disconnected`] and cancels everything, which
//!   drives the broker's lock/wipe/clear teardown.

use std::io;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::mpsc::{sync_channel, Receiver, RecvTimeoutError, SyncSender};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
use windows_sys::Win32::Storage::FileSystem::{GetFileType, ReadFile, WriteFile, FILE_TYPE_PIPE};
use windows_sys::Win32::System::Pipes::PeekNamedPipe;

use wsecret_core::windows::security::{self, HardenedThread};

use crate::protocol::{
    self, FrameError, FrameHeader, WireStatus, FRAME_TIMEOUT_MS, HANDSHAKE_TIMEOUT_MS, HEADER_LEN,
    MAX_PAYLOAD,
};

/// The two broker-side inherited channel ends (`--rd-handle`, `--wr-handle`).
/// Splitting via [`spawn_reader`] transfers ownership: the reader thread
/// closes the command end when it exits and [`ChannelWriter`] closes the
/// response end on drop.
pub struct ChannelEnds {
    rd: HANDLE,
    wr: HANDLE,
}

impl ChannelEnds {
    /// Validates two raw handle values from the command line: distinct,
    /// non-null, and `FILE_TYPE_PIPE`. The values are adopted.
    pub fn from_raw(rd: usize, wr: usize) -> io::Result<ChannelEnds> {
        if rd == 0 || wr == 0 || rd == wr {
            return Err(io::Error::other(
                "channel handles must be distinct non-null pipe ends",
            ));
        }
        let ends = ChannelEnds {
            rd: rd as HANDLE,
            wr: wr as HANDLE,
        };
        for handle in [ends.rd, ends.wr] {
            // SAFETY: raw values supplied at spawn time; GetFileType only
            // queries the handle type and never mutates.
            let kind = unsafe { GetFileType(handle) };
            if kind != FILE_TYPE_PIPE {
                return Err(io::Error::other("channel handle is not a pipe end"));
            }
        }
        Ok(ends)
    }
}

/// One queued reader event.
pub enum ReaderEvent {
    /// A structurally valid request frame (payload bounded and copied).
    Request(FrameHeader, Vec<u8>),
    /// A `Cancel` for `target` arrived and is already applied to the
    /// registry; the main loop owes it exactly one response.
    CancelAck {
        /// The cancel frame's own `request_id`.
        request_id: u32,
        /// The request id it targeted.
        target: u32,
    },
    /// A frame arrived with an unsupported wire version; the main loop must
    /// answer [`WireStatus::VersionMismatch`] (`aux` = received version) and
    /// tear down.
    VersionMismatch {
        /// The offending frame's `request_id`.
        request_id: u32,
        /// The version it carried.
        version: u16,
    },
}

/// Shared reader-side signals (disconnect + cancellation registry).
pub struct ReaderSignals {
    /// Set when the command channel hit EOF or a read error.
    disconnected: AtomicBool,
    /// The in-flight `request_id` being cancelled (0 = none).
    cancel_target: AtomicU32,
    /// Set when a disconnect cancelled everything.
    cancel_all: AtomicBool,
    /// Notifies [`ChannelReader::recv`] waiters.
    wake: (Mutex<()>, Condvar),
}

impl ReaderSignals {
    fn new() -> ReaderSignals {
        ReaderSignals {
            disconnected: AtomicBool::new(false),
            cancel_target: AtomicU32::new(0),
            cancel_all: AtomicBool::new(false),
            wake: (Mutex::new(()), Condvar::new()),
        }
    }

    /// True once the command channel is gone (EOF/read error): teardown.
    pub fn disconnected(&self) -> bool {
        self.disconnected.load(Ordering::Acquire)
    }

    /// Whether `request_id` was cancelled (a `Cancel` frame or disconnect).
    /// Long-running operations poll this at checkpoints.
    pub fn canceled(&self, request_id: u32) -> bool {
        self.cancel_all.load(Ordering::Acquire)
            || self.cancel_target.load(Ordering::Acquire) == request_id
    }

    /// Clears the registry entry of a finished request.
    pub fn clear_cancel(&self, request_id: u32) {
        let _ = self.cancel_target.compare_exchange(
            request_id,
            0,
            Ordering::AcqRel,
            Ordering::Acquire,
        );
    }

    fn request_cancel(&self, target: u32) {
        self.cancel_target.store(target, Ordering::Release);
        self.wake.1.notify_all();
    }

    fn request_disconnect(&self) {
        self.disconnected.store(true, Ordering::Release);
        self.cancel_all.store(true, Ordering::Release);
        self.wake.1.notify_all();
    }
}

/// Outcome of one bounded queue wait.
pub enum RecvOutcome {
    /// A queued event.
    Event(ReaderEvent),
    /// Nothing arrived within the wait; the channel may still be live.
    Timeout,
    /// Disconnected and drained: finish the current work and tear down.
    Closed,
}

/// The reader half: bounded event queue + hardened reader thread.
pub struct ChannelReader {
    events: Receiver<ReaderEvent>,
    signals: Arc<ReaderSignals>,
    #[allow(dead_code)]
    thread: HardenedThread,
}

impl ChannelReader {
    /// Blocking receive with a bounded wait.
    pub fn recv(&self, max_wait: Duration) -> RecvOutcome {
        match self.events.recv_timeout(max_wait) {
            Ok(event) => RecvOutcome::Event(event),
            Err(RecvTimeoutError::Timeout) => RecvOutcome::Timeout,
            Err(RecvTimeoutError::Disconnected) => RecvOutcome::Closed,
        }
    }

    /// Shared disconnect/cancellation signals (also handed to operations).
    pub fn signals(&self) -> Arc<ReaderSignals> {
        Arc::clone(&self.signals)
    }
}

/// The response writer (serialized frame writes). Owns the response handle;
/// closing it signals EOF to the client.
pub struct ChannelWriter {
    wr: HANDLE,
}

impl ChannelWriter {
    /// Writes one full response frame; partial writes complete in a loop.
    pub fn write_frame(&self, frame: &[u8]) -> io::Result<()> {
        let mut written = 0usize;
        while written < frame.len() {
            let mut n: u32 = 0;
            // SAFETY: `wr` is a live pipe handle; the buffer outlives the call.
            let ok = unsafe {
                WriteFile(
                    self.wr,
                    frame[written..].as_ptr(),
                    (frame.len() - written) as u32,
                    &mut n,
                    std::ptr::null_mut(),
                )
            };
            if ok == 0 {
                return Err(io::Error::last_os_error());
            }
            if n == 0 {
                return Err(io::Error::other("response channel stalled"));
            }
            written += n as usize;
        }
        Ok(())
    }

    /// Convenience: encode and send one response.
    pub fn respond(
        &self,
        request_id: u32,
        generation: u32,
        opcode: u16,
        body: &[u8],
    ) -> io::Result<()> {
        self.write_frame(&protocol::response_frame(request_id, generation, opcode, body))
    }

    /// Sends a status-only error response.
    pub fn respond_error(
        &self,
        request_id: u32,
        generation: u32,
        opcode: u16,
        status: WireStatus,
        aux: u16,
    ) -> io::Result<()> {
        self.respond(request_id, generation, opcode, &protocol::error_body(status, aux))
    }
}

impl Drop for ChannelWriter {
    fn drop(&mut self) {
        // SAFETY: live handle owned by this value, closed once.
        unsafe {
            if !self.wr.is_null() {
                CloseHandle(self.wr);
            }
        }
        self.wr = std::ptr::null_mut();
    }
}

/// Spawns the hardened reader thread over the command-channel read end and
/// returns the reader half plus the response writer.
pub fn spawn_reader(
    ends: ChannelEnds,
    handshake: bool,
) -> io::Result<(ChannelReader, ChannelWriter, Arc<ReaderSignals>)> {
    let signals = Arc::new(ReaderSignals::new());
    let (tx, rx) = sync_channel::<ReaderEvent>(4);
    // `ChannelEnds` owns its handles (closes on drop); splitting transfers
    // ownership to the reader thread and the writer WITHOUT closing, so the
    // values are read out through `ManuallyDrop`.
    let ends = std::mem::ManuallyDrop::new(ends);
    let (rd, wr) = (ends.rd, ends.wr);
    // `HANDLE` (`*mut c_void`) is not `Send`; the raw value crosses the
    // thread boundary as `usize` and is reinterpreted inside the closure.
    let rd_value = rd as usize;
    let thread_signals = Arc::clone(&signals);
    let thread = security::spawn_hardened_thread(move || {
        let rd = rd_value as HANDLE;
        reader_loop(rd, tx, thread_signals, handshake);
        // SAFETY: `rd` was adopted by this thread at spawn_reader time and
        // is no longer reachable anywhere else.
        unsafe { CloseHandle(rd) };
    })
    .map_err(|e| io::Error::other(format!("hardened reader thread: {e:?}")))?;
    let writer = ChannelWriter { wr };
    let reader = ChannelReader {
        events: rx,
        signals,
        thread,
    };
    let shared = reader.signals();
    Ok((reader, writer, shared))
}

fn reader_loop(
    rd: HANDLE,
    tx: SyncSender<ReaderEvent>,
    signals: Arc<ReaderSignals>,
    handshake: bool,
) {
    let handshake_deadline = Instant::now() + Duration::from_millis(HANDSHAKE_TIMEOUT_MS);
    let mut first = handshake;
    'outer: loop {
        // 1. Header under the handshake deadline (first frame) or the
        //    inter-byte deadline (every later frame).
        let first_frame = first;
        let mut head = [0u8; HEADER_LEN];
        let mut last_progress = Instant::now();
        if !read_exact_bounded(
            rd,
            &mut head,
            handshake_deadline,
            &signals,
            first,
            false,
            &mut last_progress,
            Duration::from_millis(FRAME_TIMEOUT_MS),
        ) {
            break 'outer;
        }
        first = false;
        let received_id = u32::from_le_bytes([head[12], head[13], head[14], head[15]]);
        let header = match FrameHeader::decode(&head) {
            Ok(header) => header,
            Err(FrameError::Version(v)) => {
                let _ = tx.send(ReaderEvent::VersionMismatch {
                    request_id: received_id,
                    version: v,
                });
                break 'outer;
            }
            // Corrupt/oversize: protocol violation without a usable id.
            Err(_) => break 'outer,
        };

        // 2. Body — bounded by MAX_PAYLOAD BEFORE allocation (decode already
        //    enforced it; the cast is therefore safe and bounded).
        debug_assert!(header.payload_len <= MAX_PAYLOAD);
        let mut body = vec![0u8; header.payload_len as usize];
        if header.payload_len > 0
            && !read_exact_bounded(
                rd,
                &mut body,
                handshake_deadline,
                &signals,
                first_frame,
                true,
                &mut last_progress,
                Duration::from_millis(FRAME_TIMEOUT_MS),
            )
        {
            break 'outer;
        }

        // 3. Cancel frames bypass the queue so in-flight work stops now.
        if header.opcode == protocol::Opcode::Cancel as u16 {
            let target = if body.len() == 4 {
                u32::from_le_bytes([body[0], body[1], body[2], body[3]])
            } else {
                0
            };
            if target != 0 {
                signals.request_cancel(target);
            }
            if tx
                .send(ReaderEvent::CancelAck {
                    request_id: header.request_id,
                    target,
                })
                .is_err()
            {
                break 'outer;
            }
            continue 'outer;
        }

        if tx.send(ReaderEvent::Request(header, body)).is_err() {
            break 'outer;
        }
    }
    // EOF, read error, decode failure or the main loop is gone: announce the
    // disconnect so the broker locks/wipes/exits.
    signals.request_disconnect();
}

/// Reads exactly `buf.len()` bytes. The FIRST frame is bounded outright by
/// `handshake_deadline`; every frame restarts the [`FRAME_TIMEOUT_MS`]
/// inter-byte deadline after each successful read. Waiting for the first byte
/// of a later frame is idle time, not inter-byte time, and has no frame
/// deadline. Returns false on EOF, error, or an applicable deadline expiry.
fn read_exact_bounded(
    rd: HANDLE,
    buf: &mut [u8],
    handshake_deadline: Instant,
    signals: &ReaderSignals,
    is_first: bool,
    frame_started: bool,
    last_progress: &mut Instant,
    frame_timeout: Duration,
) -> bool {
    let mut got = 0usize;
    while got < buf.len() {
        if signals.disconnected() {
            return false;
        }
        // Availability probe: anonymous pipe ends support PeekNamedPipe, so
        // waits stay bounded without overlapped I/O.
        let mut avail: u32 = 0;
        // SAFETY: live pipe handle; query only.
        let peek = unsafe {
            PeekNamedPipe(
                rd,
                std::ptr::null_mut(),
                0,
                std::ptr::null_mut(),
                &mut avail,
                std::ptr::null_mut(),
            )
        };
        if peek == 0 {
            // Broken pipe / closed write end / invalid handle: EOF.
            return false;
        }
        if avail == 0 {
            let now = Instant::now();
            if is_first && now >= handshake_deadline {
                return false;
            }
            if (frame_started || got > 0) && now.duration_since(*last_progress) >= frame_timeout {
                return false;
            }
            std::thread::sleep(Duration::from_millis(10));
            continue;
        }
        let want = (buf.len() - got).min(avail as usize) as u32;
        let mut n: u32 = 0;
        // SAFETY: live pipe handle; buffer outlives the call.
        let ok = unsafe {
            ReadFile(
                rd,
                buf[got..].as_mut_ptr(),
                want,
                &mut n,
                std::ptr::null_mut(),
            )
        };
        if ok == 0 || n == 0 {
            return false;
        }
        got += n as usize;
        *last_progress = Instant::now();
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use windows_sys::Win32::Security::SECURITY_ATTRIBUTES;
    use windows_sys::Win32::System::Pipes::CreatePipe;

    /// Creates one anonymous pipe: (read end, write end).
    fn pipe() -> (HANDLE, HANDLE) {
        let mut rd: HANDLE = std::ptr::null_mut();
        let mut wr: HANDLE = std::ptr::null_mut();
        let sa = SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: std::ptr::null_mut(),
            bInheritHandle: 1,
        };
        // SAFETY: both out-handles receive fresh pipe ends.
        let ok = unsafe { CreatePipe(&mut rd, &mut wr, &sa, 0) };
        assert!(ok != 0);
        (rd, wr)
    }

    #[test]
    fn channel_end_validation_requires_two_distinct_pipes() {
        let (rd, wr) = pipe();
        assert!(ChannelEnds::from_raw(rd as usize, wr as usize).is_ok());
        assert!(ChannelEnds::from_raw(rd as usize, rd as usize).is_err());
        assert!(ChannelEnds::from_raw(0, wr as usize).is_err());
        // A non-pipe handle value is refused by the type check.
        assert!(ChannelEnds::from_raw(usize::MAX, wr as usize).is_err());
    }

    #[test]
    fn idle_wait_does_not_consume_interbyte_deadline() {
        let (rd, wr) = pipe();
        let signals = ReaderSignals::new();
        let wr_value = wr as usize;
        let writer = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(75));
            let wr = wr_value as HANDLE;
            let byte = [0x5au8];
            let mut written = 0u32;
            // SAFETY: the writer owns `wr`; the one-byte buffer outlives the call.
            unsafe {
                WriteFile(wr, byte.as_ptr(), 1, &mut written, std::ptr::null_mut());
                CloseHandle(wr);
            }
        });
        let mut byte = [0u8];
        let mut last_progress = Instant::now();
        let ok = read_exact_bounded(
            rd,
            &mut byte,
            Instant::now() + Duration::from_secs(1),
            &signals,
            false,
            false,
            &mut last_progress,
            Duration::from_millis(20),
        );
        // SAFETY: the reader owns `rd`.
        unsafe { CloseHandle(rd) };
        writer.join().expect("writer");
        assert!(ok, "an idle channel must remain connected");
        assert_eq!(byte, [0x5a]);
    }

    #[test]
    fn partial_frame_retains_interbyte_deadline() {
        let (rd, wr) = pipe();
        let signals = ReaderSignals::new();
        let wr_value = wr as usize;
        let writer = std::thread::spawn(move || {
            let wr = wr_value as HANDLE;
            let bytes = [0x11u8, 0x22];
            let mut written = 0u32;
            // SAFETY: the writer owns `wr`; the buffer outlives each call.
            unsafe {
                WriteFile(wr, bytes.as_ptr(), 1, &mut written, std::ptr::null_mut());
            }
            std::thread::sleep(Duration::from_millis(75));
            // SAFETY: as above; the reader may already have timed out.
            unsafe {
                WriteFile(wr, bytes[1..].as_ptr(), 1, &mut written, std::ptr::null_mut());
                CloseHandle(wr);
            }
        });
        let mut bytes = [0u8; 2];
        let mut last_progress = Instant::now();
        let ok = read_exact_bounded(
            rd,
            &mut bytes,
            Instant::now() + Duration::from_secs(1),
            &signals,
            false,
            false,
            &mut last_progress,
            Duration::from_millis(20),
        );
        // SAFETY: the reader owns `rd`.
        unsafe { CloseHandle(rd) };
        writer.join().expect("writer");
        assert!(!ok, "a stalled partial frame must time out");
    }

    #[test]
    fn started_frame_without_payload_times_out() {
        let (rd, wr) = pipe();
        let signals = ReaderSignals::new();
        let mut body = [0u8; 4];
        let mut last_progress = Instant::now();
        let ok = read_exact_bounded(
            rd,
            &mut body,
            Instant::now() + Duration::from_secs(1),
            &signals,
            false,
            true,
            &mut last_progress,
            Duration::from_millis(20),
        );
        // SAFETY: the test owns both pipe ends.
        unsafe {
            CloseHandle(rd);
            CloseHandle(wr);
        }
        assert!(!ok, "a header without its declared payload must time out");
    }

    #[test]
    fn first_frame_body_uses_handshake_deadline() {
        let (rd, wr) = pipe();
        let signals = ReaderSignals::new();
        let mut body = [0u8; 4];
        let mut last_progress = Instant::now();
        let ok = read_exact_bounded(
            rd,
            &mut body,
            Instant::now() + Duration::from_millis(20),
            &signals,
            true,
            true,
            &mut last_progress,
            Duration::from_secs(10),
        );
        // SAFETY: the test owns both pipe ends.
        unsafe {
            CloseHandle(rd);
            CloseHandle(wr);
        }
        assert!(!ok, "the first frame body must retain the handshake deadline");
    }
}
