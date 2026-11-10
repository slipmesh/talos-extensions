//! The daemon's modules; `main.rs` is a thin binary entry point over them. Its config is
//! `sliplib_config::awg`.

pub mod gc;
pub mod handshake;
pub mod interface;
pub mod metrics;
