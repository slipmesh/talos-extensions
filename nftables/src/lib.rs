//! Library surface for `nftables`'s own modules - exists so sibling crates in this workspace
//! (`taloscfg`, generating the config this daemon reads, rather than reading it) can check a
//! ruleset template the way this daemon will instead of duplicating that. `main.rs` is a thin
//! binary entry point over this same module tree, not a separate copy.

pub mod ruleset;
pub mod template;
