//! `slipmesh-taloscfg template`, run the way a caller runs it.

use std::process::Command;
use taloscfg::defaults::{Service, document};

fn template(service: &str) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_slipmesh-taloscfg"))
        .args(["template", service])
        .output()
        .unwrap()
}

#[test]
fn template_prints_the_patch_document_of_the_service_asked_for() {
    for (name, service) in [("router", Service::Router), ("nftables", Service::Nftables)] {
        let output = template(name);
        assert!(output.status.success(), "{name}: {:?}", output.status);
        assert_eq!(
            String::from_utf8(output.stdout).unwrap(),
            document(service),
            "{name}"
        );
    }
}

#[test]
fn template_of_a_service_without_one_is_a_usage_error() {
    let output = template("awg");
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
}
