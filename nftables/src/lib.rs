//! Library surface for `nftables`'s own modules - exists so sibling crates in this workspace
//! (`taloscfg`, generating the config this daemon reads, rather than reading it) can reuse the real
//! config types and `validate()` instead of duplicating them. `main.rs` is a thin binary entry
//! point over this same module tree, not a separate copy.

pub mod config;
pub mod ruleset;
pub mod template;
