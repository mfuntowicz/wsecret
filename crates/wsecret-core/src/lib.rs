//! `wsecret-core`: the reusable store format and operations library.
//!
//! No terminal/process/console code lives in the portable API surface; the
//! Windows platform calls sit behind the safe facades in [`windows`], which
//! is one of the two sanctioned unsafe modules (the other is
//! `libhydrogen-sys`).

pub mod error;
#[cfg(feature = "fault-injection")]
pub mod fault;
pub mod format;
pub mod pass;
pub mod session;
pub mod store;
pub mod totp;
pub mod windows;

pub use error::{
    CommitFailure, CommitOutcome, CommitReceipt, CommitState, Error, FormatError, NameError,
};
pub use format::Header;
pub use session::Session;
pub use store::{Limits, ScanOutcome, Store};
