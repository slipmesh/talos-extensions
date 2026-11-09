//! The binary as Talos runs it, where it can do nothing without root: only the start that fails
//! before it touches the node.

use std::path::Path;
use std::process::Command;

const CONFIG_FILE: &str = "/etc/talos-extensions/router.yaml";

#[test]
fn a_missing_config_file_fails_the_start_and_logs_the_whole_error_chain() {
    assert!(
        !Path::new(CONFIG_FILE).exists(),
        "{CONFIG_FILE} exists on this host"
    );
    let output = Command::new(env!("CARGO_BIN_EXE_router"))
        .env_remove("RUST_LOG")
        .output()
        .unwrap();

    assert!(!output.status.success(), "{:?}", output.status);
    let log = String::from_utf8(output.stdout).unwrap();
    assert!(
        log.contains(&format!(
            "failed to read config file {CONFIG_FILE}: No such file or directory"
        )),
        "{log}"
    );
}
