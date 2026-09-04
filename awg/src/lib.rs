//! Library surface for `awg`'s own modules - exists so sibling crates in this workspace (`taloscfg`,
//! generating the config this daemon reads, rather than reading it) can reuse the real config
//! types and `validate()` instead of duplicating them. `main.rs` is a thin binary entry point over
//! this same module tree, not a separate copy.

pub mod config;
/// The netlink-backed half of the daemon. Gated so `taloscfg` can reuse `config` alone without
/// building rtnetlink, which does not exist off Linux.
#[cfg(feature = "runtime")]
pub mod gc;
#[cfg(feature = "runtime")]
pub mod handshake;
#[cfg(feature = "runtime")]
pub mod interface;
#[cfg(feature = "runtime")]
pub mod metrics;
