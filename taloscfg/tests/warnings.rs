//! What `slipmesh-taloscfg generate` warns about, run the way a caller runs it.

mod common;

use common::{generate, network};
use taloscfg::defaults::{Service, document};

/// The lines `generate --check` writes to stderr for `node`, or for every node.
fn warned(node: Option<&str>) -> Vec<String> {
    let dir = tempfile::tempdir().unwrap();
    let mut args = vec!["--check"];
    if let Some(node) = node {
        args.extend(["--node", node]);
    }
    let run = generate(dir.path(), &[("slipmesh.yaml", &network())], &args);
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
fn a_template_of_another_base_is_warned_about_to_a_run_for_a_node_it_reaches_with_how_it_differs() {
    let dir = tempfile::tempdir().unwrap();
    let run = |node: &str| {
        let run = generate(
            dir.path(),
            &[("slipmesh.yaml", &with_an_old_firewall_template())],
            &["--check", "--node", node],
        );
        assert!(run.success, "{}", run.stderr);
        run.stderr
    };
    let reached = run("c");
    assert!(
        reached.contains("warning: the `kind: template` document at line")
            && reached.contains(&Service::Firewall.base())
            && reached.contains("\n-# added by hand\n"),
        "{reached}"
    );
    let elsewhere = run("a");
    assert!(!elsewhere.contains("kind: template"), "{elsewhere}");
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
    let run = generate(dir.path(), &[("slipmesh.yaml", &text)], &["--check"]);
    assert!(run.success, "{}", run.stderr);
    let warnings: Vec<&str> = run
        .stderr
        .lines()
        .filter(|line| line.contains("kind: template"))
        .collect();
    assert_eq!(
        warnings,
        [format!(
            "warning: the `kind: template` document at line {line} of {}: its text is the \
             current reference firewall template, and its `base` is not that template's hash - \
             set `base` to {}",
            dir.path().join("slipmesh.yaml").display(),
            Service::Firewall.base()
        )],
        "{}",
        run.stderr
    );
}

#[test]
fn a_link_that_loses_packets_is_warned_about_once_to_a_run_for_its_nodes_and_the_run_passes() {
    let all = warned(None);
    assert_eq!(all.len(), 1, "{all:?}");
    assert!(
        all[0].starts_with("warning: mesh link a-b: ") && all[0].contains("102 packets"),
        "{all:?}"
    );
    assert_eq!(warned(Some("b")).len(), 1);
    assert_eq!(warned(Some("c")), [] as [String; 0]);
}

#[test]
fn a_run_that_writes_or_shows_a_diff_warns_too_and_writes_what_it_would_without() {
    let dir = tempfile::tempdir().unwrap();
    let text = network();
    let written = generate(dir.path(), &[("slipmesh.yaml", &text)], &[]);
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
    let diffed = generate(dir.path(), &[("slipmesh.yaml", &text)], &["--diff"]);
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
