//! Format version 1, pinned: the patch file `slipmesh-taloscfg generate` writes for every node of
//! `golden/v1/slipmesh.yaml`, compared byte for byte with the files beside it, the order of the
//! documents in a file included. A change that moves one of them changes what the nodes of a
//! working network are configured with. `UPDATE_EXPECT=1` rewrites the files; the difference is
//! then reviewed like any other.

use expect_test::expect_file;
use sliplib_config::mesh_config::MeshConfig;
use sliplib_config::slipmesh_file::SlipmeshFile;
use std::path::Path;
use std::process::Command;

const FIXTURE: &str = include_str!("golden/v1/slipmesh.yaml");

/// Every public key derived from a private key of `topology`, with whose it is. The fixture's
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

#[test]
fn every_node_of_a_version_1_file_gets_the_patch_file_it_got_before() {
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("slipmesh.yaml");
    std::fs::write(&config, FIXTURE).unwrap();
    let patches = dir.path().join("patches");
    generate(&config, &patches);

    let file = SlipmeshFile::parse(FIXTURE).unwrap();
    let public_keys = derived_public_keys(file.topology());
    for host in file.hosts() {
        let written = std::fs::read_to_string(patches.join(format!("{host}.yaml"))).unwrap();
        let named = public_keys
            .iter()
            .fold(written, |text, (key, whose)| text.replace(key, whose));
        expect_file![format!("golden/v1/{host}.yaml")].assert_eq(&named);
    }
}
