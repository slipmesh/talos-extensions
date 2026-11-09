//! The binary as Talos runs it, with no environment and without root: only the start that fails
//! before it touches the node.

use std::path::Path;
use std::process::Command;

const TEMPLATE: &str = "/etc/talos-extensions/nftables.conf.j2";

#[test]
fn a_start_without_rust_log_logs_the_version_then_fails_on_a_missing_template() {
    assert!(
        !Path::new(TEMPLATE).exists(),
        "{TEMPLATE} exists on this host"
    );
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
            "failed to read template {TEMPLATE}: No such file or directory"
        )),
        "{log}"
    );
}
