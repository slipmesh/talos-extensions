//! For the tests that need a network namespace of their own, in this crate and in the daemons'.

use std::process::Command;

/// For the test's thread, which runs its `#[tokio::test]` runtime and the `ip` it starts.
pub fn own_network_namespace() {
    nix::sched::unshare(nix::sched::CloneFlags::CLONE_NEWNET).unwrap();
}

pub fn ip(args: &str) -> String {
    let output = Command::new("ip").args(args.split(' ')).output().unwrap();
    assert!(output.status.success(), "ip {args}: {output:?}");
    String::from_utf8(output.stdout).unwrap()
}
