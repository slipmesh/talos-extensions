//! Format version 1, pinned: the patch file `slipmesh-taloscfg generate` writes for every node of
//! the fixtures under `golden/`, compared byte for byte with the files beside each fixture, the
//! order of the documents in a file included, with derived public keys named by their owner. A
//! change that moves one of them changes what the nodes of a working network are configured
//! with. `UPDATE_EXPECT=1` rewrites the files; the difference is then reviewed like any other.

use expect_test::expect_file;
use sha2::{Digest, Sha256};
use sliplib_config::mesh_config::MeshConfig;
use sliplib_config::slipmesh_file::SlipmeshFile;
use std::path::Path;
use std::process::Command;

/// A fixture, the nodes it holds and the SHA-256 of its text below the comment that opens it. The
/// library that computes a node's configs pins them on a copy of the same fixture, and holds the
/// same hash: an edit of one copy fails until the other has it too.
struct Fixture {
    directory: &'static str,
    text: &'static str,
    nodes: &'static [&'static str],
    sha256: &'static str,
}

const FULL: Fixture = Fixture {
    directory: "golden/v1",
    text: include_str!("golden/v1/slipmesh.yaml"),
    nodes: &[
        "node-a", "node-b", "node-c", "node-d", "node-e", "node-f", "router1",
    ],
    sha256: "1c9f8be29d87786776aa969d09e1c2009e1897d43d8edbce8aa4eafd3fbeadc6",
};

const ALTERNATE: Fixture = Fixture {
    directory: "golden/v1-alternate",
    text: include_str!("golden/v1-alternate/slipmesh.yaml"),
    nodes: &["east", "west", "south"],
    sha256: "72c4b4a2206dafb2fb8119bf5e92fde3d97407b5bcee0a059189be78bc4b11a3",
};

/// `text` from its first line that is neither a comment nor empty.
fn below_the_opening_comment(text: &str) -> &str {
    let opening: usize = text
        .split_inclusive('\n')
        .take_while(|line| line.starts_with('#') || line.trim().is_empty())
        .map(str::len)
        .sum();
    &text[opening..]
}

fn sha256(text: &str) -> String {
    Sha256::digest(text)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// Every public key derived from a private key of `topology`, with whose it is. The fixtures'
/// private keys are one letter repeated; their public halves read as random text, which the
/// golden files name instead of holding.
fn derived_public_keys(topology: &MeshConfig) -> Vec<(String, String)> {
    let nodes = topology.nodes.iter().filter_map(|node| {
        let key = node.mesh_private_key.as_ref()?.public_key().unwrap();
        Some((key, format!("<public key of {}>", node.name)))
    });
    let clients = topology
        .roadwarriors
        .iter()
        .flat_map(|pool| &pool.clients)
        .filter(|client| client.private_key.is_some())
        .map(|client| {
            (
                client.public_key.clone(),
                format!("<public key of client {}>", client.name),
            )
        });
    nodes.chain(clients).collect()
}

fn generate(config: &Path, patches: &Path) {
    let output = Command::new(env!("CARGO_BIN_EXE_slipmesh-taloscfg"))
        .arg("generate")
        .arg("--config")
        .arg(config)
        .arg("--patches-dir")
        .arg(patches)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

fn every_node_gets_the_patch_file_it_got_before(fixture: &Fixture) {
    // Set there, `UPDATE_EXPECT` would rewrite the golden files and pass whatever the code gives.
    assert!(
        std::env::var_os("CI").is_none() || std::env::var_os("UPDATE_EXPECT").is_none(),
        "UPDATE_EXPECT is set in CI"
    );
    assert_eq!(
        sha256(below_the_opening_comment(fixture.text)),
        fixture.sha256,
        "{}/slipmesh.yaml changed: change its copy in the tests of the library that computes a \
         node's configs alike, and the hash in both tests",
        fixture.directory
    );

    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("slipmesh.yaml");
    std::fs::write(&config, fixture.text).unwrap();
    let patches = dir.path().join("patches");
    generate(&config, &patches);

    // The files are looked for by the names written here, not by what the generator made: a
    // node it lost would leave its golden file unread.
    let mut written: Vec<String> = std::fs::read_dir(&patches)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().into_string().unwrap())
        .collect();
    written.sort();
    let mut expected: Vec<String> = fixture
        .nodes
        .iter()
        .map(|node| format!("{node}.yaml"))
        .collect();
    expected.sort();
    assert_eq!(written, expected);

    let file = SlipmeshFile::parse(fixture.text).unwrap();
    let public_keys = derived_public_keys(file.topology());
    for host in fixture.nodes {
        let written = std::fs::read_to_string(patches.join(format!("{host}.yaml"))).unwrap();
        let named = public_keys
            .iter()
            .fold(written, |text, (key, whose)| text.replace(key, whose));
        expect_file![format!("{}/{host}.yaml", fixture.directory)].assert_eq(&named);
    }
}

#[test]
fn every_node_of_the_full_version_1_file_gets_the_patch_file_it_got_before() {
    every_node_gets_the_patch_file_it_got_before(&FULL);
}

#[test]
fn every_node_of_the_alternate_version_1_file_gets_the_patch_file_it_got_before() {
    every_node_gets_the_patch_file_it_got_before(&ALTERNATE);
}
