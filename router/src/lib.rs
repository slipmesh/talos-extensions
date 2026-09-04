//! Library surface for `router`'s own modules - exists so sibling crates in this workspace
//! (`taloscfg`, generating the config this daemon reads, rather than reading it) can reuse the real
//! config types and `validate()` instead of duplicating them. `main.rs` is a thin binary entry
//! point over this same module tree, not a separate copy.

/// Talks netlink (address bookkeeping around BIRD). Gated so `taloscfg` can reuse `config` alone
/// without building rtnetlink, which does not exist off Linux.
#[cfg(feature = "runtime")]
pub mod bird;
/// Speaks BIRD's control protocol over a unix socket, which is a runtime concern and not portable;
/// `config` does not touch it.
#[cfg(feature = "runtime")]
pub mod birdc;
pub mod cidr;
pub mod config;
pub mod resolver;
