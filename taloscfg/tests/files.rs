//! `slipmesh-taloscfg generate` on the files of one network, however they are split.

#[allow(dead_code, reason = "each test crate reads the part it needs")]
mod common;

use common::{generate, network};
use sliplib_yaml::{Mapping, MultiDoc, Value};
use std::path::Path;

/// The network document's keys and obfuscation moved into a document of their own.
fn split(text: &str) -> (String, String) {
    let mut documents = MultiDoc::parse(text).unwrap().values();
    let mut secrets = Mapping::new();
    secrets.insert("slipmesh".into(), documents[0]["slipmesh"].clone());
    let architecture = &mut documents[0];
    for (name, node) in architecture["nodes"].as_mapping_mut().unwrap() {
        let key = node
            .as_mapping_mut()
            .unwrap()
            .shift_remove("wireguard")
            .unwrap();
        secrets
            .entry("nodes".into())
            .or_insert(Value::Mapping(Mapping::new()))[name] =
            Value::Mapping([("wireguard".into(), key)].into_iter().collect());
    }
    for (name, link) in architecture["mesh"]["links"].as_mapping_mut().unwrap() {
        let block = link["amneziawg"].as_mapping_mut().unwrap();
        let obfuscation = block.shift_remove("obfuscation").unwrap();
        let mut laid = Mapping::new();
        laid.insert("obfuscation".into(), obfuscation);
        let mut owner = Mapping::new();
        owner.insert("amneziawg".into(), Value::Mapping(laid));
        secrets
            .entry("mesh".into())
            .or_insert(Value::Mapping(Mapping::new()))["links"][name] = Value::Mapping(owner);
    }
    let written: Vec<String> = documents
        .iter()
        .map(|document| sliplib_yaml::to_string(document).unwrap())
        .collect();
    let secrets = sliplib_yaml::to_string(&Value::Mapping(secrets)).unwrap();
    (sliplib_yaml::join(&written), secrets)
}

/// By name.
fn patches(dir: &Path) -> Vec<(String, Vec<u8>)> {
    let mut files: Vec<(String, Vec<u8>)> = std::fs::read_dir(dir.join("patches"))
        .unwrap()
        .map(|entry| {
            let entry = entry.unwrap();
            let name = entry.file_name().into_string().unwrap();
            (name, std::fs::read(entry.path()).unwrap())
        })
        .collect();
    files.sort();
    files
}

#[test]
fn one_file_and_the_same_split_into_architecture_and_secrets_give_the_same_patch_files() {
    let text = network();
    let (architecture, secrets) = split(&text);
    for moved in ["private_key", "obfuscation"] {
        assert!(
            !architecture.contains(moved) && secrets.contains(moved),
            "{moved}"
        );
    }
    let (one, two) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let run = generate(one.path(), &[("slipmesh.yaml", &text)], &[]);
    assert!(run.success, "{}", run.stderr);
    let run = generate(
        two.path(),
        &[("mesh.yaml", &architecture), ("secrets.yaml", &secrets)],
        &[],
    );
    assert!(run.success, "{}", run.stderr);
    let (from_one, from_two) = (patches(one.path()), patches(two.path()));
    assert_eq!(from_one.len(), 4);
    assert_eq!(from_one, from_two);
}
