//! What the tests of `slipmesh-taloscfg generate` share.

use sliplib_secrets::wireguard::PrivateKey;
use std::process::Command;
use taloscfg::defaults::{Service, document};

/// Four nodes of `talos` and two links, `a`-`b` and `c`-`d`; the first loses data packets to its
/// range of `h1` with `random_trailers` on. Both reference templates, for every node.
pub fn network() -> String {
    let key = || PrivateKey::generate().expose().to_owned();
    let nodes: String = ["a", "b", "c", "d"]
        .iter()
        .zip(1..)
        .map(|(name, id)| {
            format!(
                "  {name}: {{platform: talos, node_id: 0.0.0.{id}, underlay: {{wan: {{endpoint: \
                 {{ipv4: 192.0.2.{id}}}}}}}, wireguard: {{private_key: \"{}\"}}}}\n",
                key()
            )
        })
        .collect();
    format!(
        r#"slipmesh: {{kind: network, version: 2, revision: 1}}
addressing: {{loopback: {{ipv4: 198.51.100.0/25, ipv6: "3fff::/64"}}}}
routing: {{bgp: {{as: 64496}}}}
mesh:
  interface_prefix: mesh-
  links:
    a-b:
      type: amneziawg
      ends: {{a: {{}}, b: {{}}}}
      amneziawg:
        port: 51820
        obfuscation: {{jc: 4, jmin: 10, jmax: 50, s1: 40, s2: 41, h1: 100-199, h2: 6, h3: 7, h4: 8, random_trailers: true}}
    c-d:
      type: amneziawg
      ends: {{c: {{}}, d: {{}}}}
      amneziawg:
        port: 51821
        obfuscation: {{jc: 4, jmin: 10, jmax: 50, s1: 40, s2: 41, h1: 5, h2: 6, h3: 7, h4: 8}}
nodes:
{nodes}---
{}---
{}"#,
        document(Service::Router),
        document(Service::Firewall),
    )
}

/// What a run of `generate` gave: its exit status, stdout and stderr. The patch files go to
/// `patches` beside the files.
pub struct Run {
    pub success: bool,
    pub stdout: String,
    pub stderr: String,
}

/// `files` written by name into `dir`, all given to `--in`.
pub fn generate(dir: &std::path::Path, files: &[(&str, &str)], args: &[&str]) -> Run {
    let mut command = Command::new(env!("CARGO_BIN_EXE_slipmesh-taloscfg"));
    command.arg("generate").args(args).arg("--in");
    for (name, text) in files {
        let path = dir.join(name);
        std::fs::write(&path, text).unwrap();
        command.arg(path);
    }
    let output = command
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
