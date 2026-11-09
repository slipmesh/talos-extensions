//! The binary as Talos runs it, where it can do nothing without root: only the start that fails
//! before it touches the node.

use std::path::Path;
use std::process::Command;

const TEMPLATE: &str = "/etc/talos-extensions/nftables.conf.j2";

#[test]
fn a_missing_template_fails_the_start_and_logs_the_whole_error_chain() {
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
    assert!(
        log.contains(&format!(
            "failed to read template {TEMPLATE}: No such file or directory"
        )),
        "{log}"
    );
}
