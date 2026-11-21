//! Windows platform layer (plan §3.1): file/ACL/mutex/pipe/process APIs plus
//! the process-launch bridges (the `wsecret ssh agent` child and the
//! `wsecret-broker` private two-pipe channel child) and the ssh-agent
//! client. This and `libhydrogen-sys` are the only `unsafe` modules in the
//! workspace (plan §3.1/audit P10) — plus the broker crate's Win32-bound
//! modules, which document their own narrow unsafe surfaces.
//!
//! Submodules: [`agent_bridge`], [`console`], [`file`], [`security`],
//! [`ssh_agent`].

pub mod agent_bridge;
pub mod console;
pub mod file;
pub mod security;
pub mod ssh_agent;
