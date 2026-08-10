//! Library surface for `awg`'s own modules - exists so sibling crates in this workspace (`patches`,
//! generating the config this daemon reads, rather than reading it) can reuse the real config
//! types and `validate()` instead of duplicating them. `main.rs` is a thin binary entry point over
//! this same module tree, not a separate copy.

pub mod config;
pub mod gc;
pub mod handshake;
pub mod interface;
