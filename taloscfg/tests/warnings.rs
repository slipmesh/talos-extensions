//! What `slipmesh-taloscfg generate` warns about, run the way a caller runs it.

use sliplib_secrets::wireguard::PrivateKey;
use std::process::Command;
use taloscfg::defaults::{Service, document};

/// Four nodes and two links, `a`-`b` and `c`-`d`; the first loses data packets to its range of
/// `h1` with `random_trailers` on.
fn network() -> String {
    let key = || PrivateKey::generate().expose().to_owned();
    let nodes: String = ["a", "b", "c", "d"]
        .iter()
        .zip(1..)
        .map(|(name, id)| {
            format!(
                "  - {{name: {name}, node_id: \"198.51.100.{id}\", endpoint: \"192.0.2.{id}\", \
                 mesh_private_key: \"{}\"}}\n",
                key()
            )
        })
        .collect();
    format!(
        r#"slipmesh:
  kind: network
cluster:
  bgp_as: 64512
  loopback_networks: {{ipv4: "198.51.100.0/25", ipv6: "3fff::/32"}}
  interface_prefix: {{mesh: mesh-}}
  route_proto_id: {{egress: 152}}
nodes:
{nodes}mesh:
  links:
    - pair: [a, b]
      port: 51820
      obfuscation: {{jc: 4, jmin: 10, jmax: 50, s1: 40, s2: 41, h1: 100-199, h2: 6, h3: 7, h4: 8, random_trailers: true}}
    - pair: [c, d]
      port: 51821
      obfuscation: {{jc: 4, jmin: 10, jmax: 50, s1: 40, s2: 41, h1: 5, h2: 6, h3: 7, h4: 8}}
---
{}---
{}"#,
        document(Service::Router),
        document(Service::Nftables),
    )
}

/// What a run of `generate` with `args` on `text` gave: its exit status, stdout and stderr. The
/// patch files go to `patches` beside the file.
struct Run {
    success: bool,
    stdout: String,
    stderr: String,
}

fn generate(dir: &std::path::Path, text: &str, args: &[&str]) -> Run {
    let config = dir.join("slipmesh.yaml");
    std::fs::write(&config, text).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_slipmesh-taloscfg"))
        .arg("generate")
        .args(args)
        .arg("--config")
        .arg(&config)
        .arg("--patches-dir")
        .arg(dir.join("patches"))
        .output()
        .unwrap();
    Run {
        success: output.status.success(),
        stdout: String::from_utf8(output.stdout).unwrap(),
        stderr: String::from_utf8(output.stderr).unwrap(),
    }
}

/// The lines `generate --check` writes to stderr for `node`, or for every node.
fn warned(node: Option<&str>) -> Vec<String> {
    let dir = tempfile::tempdir().unwrap();
    let mut args = vec!["--check"];
    if let Some(node) = node {
        args.extend(["--node", node]);
    }
    let run = generate(dir.path(), &network(), &args);
    assert!(run.success, "{}", run.stderr);
    run.stderr.lines().map(str::to_owned).collect()
}

#[test]
fn a_link_that_loses_packets_is_warned_about_once_and_the_run_still_passes() {
    let warned = warned(None);
    assert_eq!(warned.len(), 1, "{warned:?}");
    assert!(
        warned[0].starts_with("warning: mesh link a-b: ") && warned[0].contains("102 packets"),
        "{warned:?}"
    );
}

#[test]
fn a_run_for_one_node_warns_about_that_nodes_links_alone() {
    assert_eq!(warned(Some("b")).len(), 1);
    assert_eq!(warned(Some("c")), [] as [String; 0]);
}

#[test]
fn a_run_that_writes_or_shows_a_diff_warns_too_and_writes_what_it_would_without() {
    let dir = tempfile::tempdir().unwrap();
    let text = network();
    let written = generate(dir.path(), &text, &[]);
    assert!(written.success, "{}", written.stderr);
    assert!(
        written.stderr.starts_with("warning: mesh link a-b: "),
        "{}",
        written.stderr
    );
    for node in ["a", "b", "c", "d"] {
        let patch = dir.path().join("patches").join(format!("{node}.yaml"));
        assert!(
            written
                .stdout
                .contains(&format!("wrote {}", patch.display())),
            "{}",
            written.stdout
        );
    }
    // What was written is what the file gives, warning or not: a diff shows nothing to change.
    let diffed = generate(dir.path(), &text, &["--diff"]);
    assert!(diffed.success, "{}", diffed.stderr);
    assert!(
        diffed.stderr.starts_with("warning: mesh link a-b: "),
        "{}",
        diffed.stderr
    );
    for node in ["a", "b", "c", "d"] {
        assert!(
            diffed.stdout.contains(&format!("{node}: no changes")),
            "{}",
            diffed.stdout
        );
    }
}

#[test]
fn a_refused_file_gets_no_warning() {
    let dir = tempfile::tempdir().unwrap();
    // A key that does not decode refuses the node, and every node linked with it.
    let text = network().replacen("mesh_private_key: \"", "mesh_private_key: \"not a key", 1);
    let refused = generate(dir.path(), &text, &["--check"]);
    assert!(!refused.success);
    assert!(!refused.stderr.contains("warning:"), "{}", refused.stderr);
    assert!(!dir.path().join("patches").exists());
}
