//! Every edit `taloscfg` makes to `slipmesh.yaml`: minted secrets written into the fields they
//! belong to, roadwarrior clients added and removed.
//!
//! Written, a minted value is the operator's like any other: the next run mints nothing, and
//! deleting it mints a new identity for that node, link or pool, and for every peer that refers to
//! it. Only what the run generated is written - a field set on the entry or in the global
//! `obfuscation` is never copied down, and neither are the switches that are never generated.
//!
//! An edit is a list of operations on one document's values; `sliplib-yaml` applies them as the
//! smallest change to the text, so everything else in the file stays as the operator wrote it.

use crate::mesh_config::RoadwarriorClient;
use crate::secrets::Minted;
use crate::slipmesh_file::SlipmeshFile;
use anyhow::{Context, Result};
use common::Obfuscation;
use sliplib_yaml::{Mapping, MultiDoc, Operation, Value};

/// Writes every value of `minted` into its field of `yaml`, the `slipmesh.yaml` `file` was read
/// from.
pub fn record(yaml: &mut MultiDoc, file: &SlipmeshFile, minted: &Minted) -> Result<()> {
    if !minted.node_keys.is_empty() || !minted.link_obfuscation.is_empty() {
        let index = file.network_document();
        let network = document_value(yaml, index)?;
        let mut operations = Vec::new();
        for (node, key) in &minted.node_keys {
            anyhow::ensure!(
                network["nodes"].get(*node).is_some(),
                "a node the network document does not have"
            );
            operations.push(add(
                &["nodes", &node.to_string(), "mesh_private_key"],
                key.expose().into(),
            ));
        }
        for (link, generated) in &minted.link_obfuscation {
            let entry = network["mesh"]["links"]
                .get(*link)
                .context("a link the network document does not have")?;
            let at = ["mesh", "links", &link.to_string()];
            operations.extend(obfuscation(&at, entry, generated)?);
        }
        yaml.patch(index, &operations)?;
    }

    for pool_minted in &minted.pools {
        let name = &pool_minted.name;
        let index = file
            .pool_document(name)
            .with_context(|| format!("pool {name:?} is in no document"))?;
        let pool = document_value(yaml, index)?;
        let mut operations = Vec::new();
        if let Some(key) = &pool_minted.private_key {
            operations.push(add(&["private_key"], key.expose().into()));
        }
        if let Some(generated) = &pool_minted.obfuscation {
            operations.extend(obfuscation(&[], &pool, generated)?);
        }
        yaml.patch(index, &operations)?;
    }
    Ok(())
}

/// Adds `client` to the `clients` of the pool at `document` in `yaml`. Everything outside that one
/// sequence - comments, the rest of the pool, formatting - is untouched.
pub fn add_client(yaml: &mut MultiDoc, document: usize, client: &RoadwarriorClient) -> Result<()> {
    let entry = client_entry(client);
    let operation = if document_value(yaml, document)?.get("clients").is_some() {
        add(&["clients", "-"], entry)
    } else {
        add(&["clients"], Value::Sequence(vec![entry]))
    };
    yaml.patch(document, &[operation])
}

/// Removes `clients[client_index]` from the pool at `document` in `yaml`, line and all - same
/// "everything else untouched" guarantee as `add_client`.
pub fn remove_client(yaml: &mut MultiDoc, document: usize, client_index: usize) -> Result<()> {
    anyhow::ensure!(
        document_value(yaml, document)?.get("clients").is_some(),
        "pool has no clients list"
    );
    yaml.patch(
        document,
        &[Operation::Remove {
            path: vec!["clients".into(), client_index.to_string()],
        }],
    )
}

/// One client entry as `rw-add` writes it: by its private key when that was kept, else by its
/// public key - never both.
fn client_entry(client: &RoadwarriorClient) -> Value {
    let mut entry = Mapping::new();
    entry.insert("name".into(), client.name.clone().into());
    match &client.private_key {
        Some(key) => entry.insert("private_key".into(), key.expose().into()),
        None => entry.insert("public_key".into(), client.public_key.clone().into()),
    };
    entry.insert(
        "allowed_ips".into(),
        Value::Sequence(
            client
                .allowed_ips
                .iter()
                .map(|ip| ip.clone().into())
                .collect(),
        ),
    );
    Value::Mapping(entry)
}

/// The operations that write the fields of `generated` under `at`, whose current value is `owner`:
/// into its `obfuscation` mapping when it has one, else as a new one.
fn obfuscation(at: &[&str], owner: &Value, generated: &Obfuscation) -> Result<Vec<Operation>> {
    let fields = sliplib_yaml::to_value(generated).context("serializing generated obfuscation")?;
    let fields: Mapping = fields
        .as_mapping()
        .into_iter()
        .flatten()
        .filter(|(_, value)| !value.is_null())
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect();
    let path =
        |rest: &[&str]| -> Vec<String> { at.iter().chain(rest).map(|s| s.to_string()).collect() };
    if owner.get("obfuscation").is_some_and(Value::is_mapping) {
        Ok(fields
            .into_iter()
            .map(|(key, value)| Operation::Add {
                path: path(&["obfuscation", key.as_str().unwrap_or_default()]),
                value,
            })
            .collect())
    } else {
        Ok(vec![Operation::Add {
            path: path(&["obfuscation"]),
            value: Value::Mapping(fields),
        }])
    }
}

fn add(path: &[&str], value: Value) -> Operation {
    Operation::Add {
        path: path.iter().map(|s| s.to_string()).collect(),
        value,
    }
}

/// Document `index` of `yaml` as it reads now, edits so far included.
fn document_value(yaml: &MultiDoc, index: usize) -> Result<Value> {
    yaml.documents()?
        .into_iter()
        .find(|document| document.index == index)
        .map(|document| document.value)
        .with_context(|| format!("no document at position {index}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mesh_config::MeshConfig;
    use crate::secrets;

    const NINE: [&str; 9] = ["jc", "jmin", "jmax", "s1", "s2", "h1", "h2", "h3", "h4"];

    const NETWORK: &str = "\
slipmesh:
    kind: network
cluster:
    bgp_as: 64512
    loopback_networks:
        ipv4: 10.62.0.0/16
        ipv6: fd00:62::/32
nodes:
    - name: node-a
      node_id: 10.62.0.1
    - name: node-b
      node_id: 10.62.0.2
    - name: node-c
      node_id: 10.62.0.3
mesh:
    links:
        - pair:
            - node-b
            - node-a
          port: 51820
        - pair:
            - node-a
            - node-c
          port: 51821
          plain: true
";

    const POOLS: &str = "\
---
slipmesh:
    kind: roadwarriors
name: obfuscated
node_hostnames:
    - node-a
address: 10.99.0.1/24
listen_port: 51900
obfuscation:
    jc: 4
    jmin: 10
    jmax: 50
    s1: 1
    s2: 2
    h1: 5
    h2: 6
    h3: 7
    h4: 8
---
slipmesh:
    kind: roadwarriors
name: plain
node_hostnames:
    - node-b
address: 10.98.0.1/24
listen_port: 51901
plain: true
";

    fn slipmesh() -> String {
        format!("{NETWORK}{POOLS}")
    }

    /// One run: resolve, write down what was minted.
    fn run(raw: &str) -> String {
        let mut yaml = MultiDoc::parse(raw).unwrap();
        let file = SlipmeshFile::read(&yaml).unwrap();
        let (_, minted) = secrets::resolve(file.topology());
        record(&mut yaml, &file, &minted).unwrap();
        yaml.text()
    }

    fn topology(raw: &str) -> MeshConfig {
        SlipmeshFile::parse(raw).unwrap().into_topology()
    }

    fn keys_of(obfuscation: &Obfuscation) -> Vec<String> {
        let value = sliplib_yaml::to_value(obfuscation).unwrap();
        value
            .as_mapping()
            .unwrap()
            .keys()
            .map(|k| k.as_str().unwrap().to_owned())
            .collect()
    }

    #[test]
    fn every_node_gets_its_key_written_into_its_entry() {
        let recorded = run(&slipmesh());
        for node in topology(&recorded).nodes {
            let key = node.mesh_private_key.expect(&node.name);
            assert!(
                recorded.contains(&format!(
                    "      node_id: {}\n      mesh_private_key: {}\n",
                    node.node_id,
                    key.expose()
                )),
                "{recorded}"
            );
        }
    }

    #[test]
    fn a_link_gets_the_nine_generated_fields_nested_under_it() {
        let recorded = run(&slipmesh());
        assert!(
            recorded.contains("          port: 51820\n          obfuscation:\n            jc: "),
            "{recorded}"
        );
        let links = topology(&recorded).mesh.links;
        assert_eq!(keys_of(&links[0].obfuscation), NINE);
    }

    #[test]
    fn plain_links_and_pools_get_no_obfuscation() {
        let topology = topology(&run(&slipmesh()));
        assert_eq!(topology.mesh.links[1].obfuscation, Obfuscation::default());
        let plain = &topology.roadwarriors[1];
        assert!(plain.private_key.is_some());
        assert_eq!(plain.obfuscation, Obfuscation::default());
    }

    #[test]
    fn a_pool_with_all_nine_fields_written_gets_only_its_key() {
        let recorded = run(&slipmesh());
        let pool = &topology(&recorded).roadwarriors[0];
        assert!(pool.private_key.is_some());
        assert_eq!(pool.obfuscation.jc, Some(4));
        assert_eq!(recorded.matches("jc:").count(), 2, "{recorded}");
    }

    #[test]
    fn switches_that_are_never_generated_are_never_written() {
        let raw = slipmesh().replace(
            "cluster:\n",
            "obfuscation:\n    random_trailers: true\n    disable_cookies: true\ncluster:\n",
        );
        let links = topology(&run(&raw)).mesh.links;
        let written = keys_of(&links[0].obfuscation);
        assert_eq!(written, NINE, "the link's own fields only");
    }

    #[test]
    fn a_field_set_globally_is_not_written_down() {
        let raw = slipmesh().replace("cluster:\n", "obfuscation:\n    jc: 5\ncluster:\n");
        let recorded = run(&raw);
        let links = topology(&recorded).mesh.links;
        assert!(!keys_of(&links[0].obfuscation).contains(&"jc".to_owned()));
        assert_eq!(keys_of(&links[0].obfuscation).len(), 8);
    }

    #[test]
    fn a_field_set_on_the_link_stays_and_the_rest_join_it() {
        let raw = slipmesh().replace(
            "          port: 51820\n",
            "          port: 51820\n          obfuscation:\n            jc: 9\n",
        );
        let recorded = run(&raw);
        let obfuscation = &topology(&recorded).mesh.links[0].obfuscation;
        assert_eq!(obfuscation.jc, Some(9));
        assert_eq!(keys_of(obfuscation).len(), 9);
        assert!(
            recorded.contains("          obfuscation:\n            jc: 9\n            jmin: "),
            "{recorded}"
        );
    }

    #[test]
    fn nothing_but_the_new_lines_changes() {
        let raw = slipmesh();
        let recorded = run(&raw);
        let deleted = similar::TextDiff::from_lines(&raw, &recorded)
            .iter_all_changes()
            .filter(|c| c.tag() == similar::ChangeTag::Delete)
            .count();
        assert_eq!(deleted, 0, "{recorded}");
    }

    /// A pool as its own `slipmesh.yaml` document.
    const PLAIN_POOL: &str = r#"slipmesh:
  kind: roadwarriors
name: plain
node_hostnames: ["a", "b"]
address: "198.51.100.1/24"
listen_port: 51820
plain: true
clients:
  - {name: alice, public_key: "AAA=", allowed_ips: ["198.51.100.41/32"]}
  - {name: bob, public_key: "BBB=", allowed_ips: ["198.51.100.32/32"]}
"#;

    fn client(name: &str) -> RoadwarriorClient {
        RoadwarriorClient {
            name: name.to_owned(),
            public_key: format!("{name}="),
            private_key: None,
            allowed_ips: vec!["198.51.100.99/32".to_owned()],
            advanced_security: false,
        }
    }

    /// `source` after `edit`, as the text it comes back as.
    fn edited(source: &str, edit: impl FnOnce(&mut MultiDoc)) -> String {
        let mut yaml = MultiDoc::parse(source).unwrap();
        edit(&mut yaml);
        yaml.text()
    }

    fn client_names(source: &str) -> Vec<String> {
        let value: sliplib_yaml::Value = sliplib_yaml::from_str(source).unwrap();
        value["clients"]
            .as_sequence()
            .unwrap()
            .iter()
            .map(|c| c["name"].as_str().unwrap().to_owned())
            .collect()
    }

    #[test]
    fn add_client_appends_and_leaves_the_rest_untouched() {
        let out = edited(PLAIN_POOL, |yaml| {
            add_client(yaml, 0, &client("dave")).unwrap()
        });
        assert!(out.starts_with(PLAIN_POOL), "{out}");
        assert_eq!(client_names(&out), ["alice", "bob", "dave"]);
    }

    #[test]
    fn add_client_starts_the_list_a_pool_lacks() {
        let pool = PLAIN_POOL.split("clients:").next().unwrap();
        let out = edited(pool, |yaml| add_client(yaml, 0, &client("dave")).unwrap());
        assert!(out.starts_with(pool), "{out}");
        assert_eq!(client_names(&out), ["dave"]);
    }

    #[test]
    fn remove_client_deletes_exactly_the_target() {
        let out = edited(PLAIN_POOL, |yaml| {
            remove_client(yaml, 0, 0).unwrap() // alice
        });
        assert_eq!(
            out,
            PLAIN_POOL.replace(
                "  - {name: alice, public_key: \"AAA=\", allowed_ips: [\"198.51.100.41/32\"]}\n",
                ""
            )
        );
    }
}
