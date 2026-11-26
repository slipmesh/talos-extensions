//! The binary as Talos runs it, with no environment and without root: only the start that fails
//! before it touches the node.

use nftables::template::{CONFIG_PATH, TEMPLATE_PATH};
use std::path::Path;
use std::process::Command;

#[test]
fn a_start_without_rust_log_logs_the_version_then_fails_on_a_missing_template() {
    for path in [CONFIG_PATH, TEMPLATE_PATH] {
        assert!(!Path::new(path).exists(), "{path} exists on this host");
    }
    let output = Command::new(env!("CARGO_BIN_EXE_nftables"))
        .env_remove("RUST_LOG")
        .output()
        .unwrap();

    assert!(!output.status.success(), "{:?}", output.status);
    let log = String::from_utf8(output.stdout).unwrap();
    let version_line = concat!("nftables ", env!("CARGO_PKG_VERSION"));
    assert!(log.contains(version_line), "{log}");
    assert!(
        log.contains(&format!(
            "failed to read template {TEMPLATE_PATH}: No such file or directory"
        )),
        "{log}"
    );
}
