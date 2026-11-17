//! `wsecret-cli`: the `wsecret` command-line interface.
//!
//! The library target exists so the argz-exact parser ([`args`]) can be unit
//! tested independently of the binary's command dispatch. The binary wires
//! [`args::run`] to the command implementations.

pub mod args;
pub mod console;
