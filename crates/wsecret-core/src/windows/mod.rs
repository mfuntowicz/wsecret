//! Windows platform layer (plan §3.1): file/ACL/mutex/pipe/process APIs plus
//! the native-only agent-capability bridge. This and `libhydrogen-sys` are the
//! only `unsafe` modules in the workspace (plan §3.1/audit P10).
//!
//! Submodules: [`file`], [`security`], [`agent_bridge`].

pub mod agent_bridge;
pub mod console;
pub mod file;
pub mod security;
