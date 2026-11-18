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

/// The lines `generate --check` writes to stderr for `node`, or for every node.
fn warned(node: Option<&str>) -> Vec<String> {
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("slipmesh.yaml");
    std::fs::write(&config, network()).unwrap();
    let mut command = Command::new(env!("CARGO_BIN_EXE_slipmesh-taloscfg"));
    command
        .args(["generate", "--check", "--config"])
        .arg(&config);
    if let Some(node) = node {
        command.args(["--node", node]);
    }
    let output = command.output().unwrap();
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(output.status.success(), "{stderr}");
    stderr.lines().map(str::to_owned).collect()
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
