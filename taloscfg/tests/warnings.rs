//! What `slipmesh-taloscfg generate` warns about, run the way a caller runs it.

use sliplib_secrets::wireguard::PrivateKey;
use std::process::Command;
use taloscfg::defaults::{Service, document};

/// Four nodes of `talos` and two links, `a`-`b` and `c`-`d`; the first loses data packets to its
/// range of `h1` with `random_trailers` on. Both reference templates, for every node.
fn network() -> String {
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
routing: {{bgp: {{as: 64512}}}}
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

/// `network()` with the firewall template for `c` and `d` alone, made from a reference other than
/// the current one and edited by hand.
fn with_an_old_firewall_template() -> String {
    let current = document(Service::Firewall);
    let old = current
        .replace(
            "  platform: talos\n",
            "  platform: talos\n  include: [c, d]\n",
        )
        .replace(
            &Service::Firewall.base(),
            "sha256:0000000000000000000000000000000000000000000000000000000000000000",
        )
        .replace("content: |\n", "content: |\n  # added by hand\n");
    format!("{}---\n{old}", network())
}

#[test]
fn a_template_of_another_base_is_warned_about_with_how_it_differs_from_the_reference() {
    let dir = tempfile::tempdir().unwrap();
    let run = generate(
        dir.path(),
        &with_an_old_firewall_template(),
        &["--check", "--node", "c"],
    );
    assert!(run.success, "{}", run.stderr);
    assert!(
        run.stderr
            .contains("warning: the `kind: template` document at line"),
        "{}",
        run.stderr
    );
    assert!(
        run.stderr.contains(&Service::Firewall.base()),
        "{}",
        run.stderr
    );
    assert!(
        run.stderr.contains("\n-# added by hand\n"),
        "{}",
        run.stderr
    );
}

#[test]
fn a_reference_template_of_another_base_is_told_to_set_its_base_alone() {
    let firewall = document(Service::Firewall);
    let text = network().replace(
        &firewall,
        &firewall.replace(
            &Service::Firewall.base(),
            "sha256:0000000000000000000000000000000000000000000000000000000000000000",
        ),
    );
    let line = text[..text
        .find("  kind: template\n  platform: talos\ndaemon: firewall")
        .unwrap()]
        .lines()
        .count();
    let dir = tempfile::tempdir().unwrap();
    let run = generate(dir.path(), &text, &["--check"]);
    assert!(run.success, "{}", run.stderr);
    let warnings: Vec<&str> = run
        .stderr
        .lines()
        .filter(|line| line.contains("kind: template"))
        .collect();
    assert_eq!(
        warnings,
        [format!(
            "warning: the `kind: template` document at line {line}: its text is the current \
             reference firewall template, and its `base` is not that template's hash - set `base` \
             to {}",
            Service::Firewall.base()
        )],
        "{}",
        run.stderr
    );
}

#[test]
fn a_template_of_another_base_is_not_told_of_to_a_run_for_a_node_it_does_not_reach() {
    let dir = tempfile::tempdir().unwrap();
    let run = generate(
        dir.path(),
        &with_an_old_firewall_template(),
        &["--check", "--node", "a"],
    );
    assert!(run.success, "{}", run.stderr);
    assert!(!run.stderr.contains("kind: template"), "{}", run.stderr);
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
    let text = network().replacen("private_key: \"", "private_key: \"not a key", 1);
    let refused = generate(dir.path(), &text, &["--check"]);
    assert!(!refused.success);
    assert!(!refused.stderr.contains("warning:"), "{}", refused.stderr);
    assert!(!dir.path().join("patches").exists());
}
