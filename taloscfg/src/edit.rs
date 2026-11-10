//! Every edit `taloscfg` makes to `slipmesh.yaml`: minted secrets written into the fields they
//! belong to, roadwarrior clients added and removed.
//!
//! Written, a minted value is the operator's like any other: the next run mints nothing, and
//! deleting it mints a new identity for that node, link or pool, and for every peer that refers to
//! it. Only what the run generated is written - a field set on the entry or in the global
//! `obfuscation` is never copied down, and neither are the switches that are never generated.
//!
//! An edit changes one document's values. The file is written back from the values, so its
//! comments are not kept.

use crate::mesh_config::RoadwarriorClient;
use crate::secrets::Minted;
use crate::slipmesh_file::SlipmeshFile;
use anyhow::{Context, Result};
use sliplib_config::Obfuscation;
use sliplib_yaml::{Mapping, MultiDoc, Value};

/// Writes every value of `minted` into its field of `yaml`, the `slipmesh.yaml` `file` was read
/// from.
pub fn record(yaml: &mut MultiDoc, file: &SlipmeshFile, minted: &Minted) -> Result<()> {
    let network = document(yaml, file.network_document())?;
    for (node, key) in &minted.node_keys {
        let entry = network
            .get_mut("nodes")
            .and_then(|nodes| nodes.get_mut(*node))
            .context("a node the network document does not have")?;
        set(entry, "mesh_private_key", key.expose().into())?;
    }
    for (link, generated) in &minted.link_obfuscation {
        let entry = network
            .get_mut("mesh")
            .and_then(|mesh| mesh.get_mut("links"))
            .and_then(|links| links.get_mut(*link))
            .context("a link the network document does not have")?;
        write_obfuscation(entry, generated)?;
    }

    for pool_minted in &minted.pools {
        let name = &pool_minted.name;
        let index = file
            .pool_document(name)
            .with_context(|| format!("pool {name:?} is in no document"))?;
        let pool = document(yaml, index)?;
        if let Some(key) = &pool_minted.private_key {
            set(pool, "private_key", key.expose().into())?;
        }
        if let Some(generated) = &pool_minted.obfuscation {
            write_obfuscation(pool, generated)?;
        }
    }
    Ok(())
}

/// Adds `client` to the end of the `clients` of the pool at `document` in `yaml`, starting the
/// list when the pool has none.
pub fn add_client(yaml: &mut MultiDoc, document: usize, client: &RoadwarriorClient) -> Result<()> {
    let pool = self::document(yaml, document)?;
    let entry = client_entry(client);
    match pool.get_mut("clients") {
        Some(clients) => clients
            .as_sequence_mut()
            .context("the pool's `clients` is not a list")?
            .push(entry),
        None => set(pool, "clients", Value::Sequence(vec![entry]))?,
    }
    Ok(())
}

/// Removes `clients[client_index]` from the pool at `document` in `yaml`.
pub fn remove_client(yaml: &mut MultiDoc, document: usize, client_index: usize) -> Result<()> {
    let clients = self::document(yaml, document)?
        .get_mut("clients")
        .and_then(Value::as_sequence_mut)
        .context("pool has no clients list")?;
    anyhow::ensure!(
        client_index < clients.len(),
        "pool has no client at position {client_index}"
    );
    clients.remove(client_index);
    Ok(())
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

/// Writes the fields of `generated` into the `obfuscation` mapping of `owner`, starting one when
/// it has none.
fn write_obfuscation(owner: &mut Value, generated: &Obfuscation) -> Result<()> {
    let fields = sliplib_yaml::to_value(generated).context("serializing generated obfuscation")?;
    let fields = fields
        .as_mapping()
        .into_iter()
        .flatten()
        .filter(|(_, value)| !value.is_null())
        .map(|(key, value)| (key.clone(), value.clone()));
    match owner.get_mut("obfuscation").and_then(Value::as_mapping_mut) {
        Some(obfuscation) => obfuscation.extend(fields),
        None => set(owner, "obfuscation", Value::Mapping(fields.collect()))?,
    }
    Ok(())
}

/// Sets `key` of the mapping `entry` to `value`.
fn set(entry: &mut Value, key: &str, value: Value) -> Result<()> {
    entry
        .as_mapping_mut()
        .with_context(|| format!("an entry to set `{key}` on is not a mapping"))?
        .insert(key.into(), value);
    Ok(())
}

/// Document `index` of `yaml`, to edit.
fn document(yaml: &mut MultiDoc, index: usize) -> Result<&mut Value> {
    yaml.document_mut(index)
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
        ipv4: 198.51.100.0/25
        ipv6: 3fff::/32
nodes:
    - name: node-a
      node_id: 198.51.100.1
    - name: node-b
      node_id: 198.51.100.2
    - name: node-c
      node_id: 198.51.100.3
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
address: 203.0.113.1/27
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
address: 203.0.113.33/27
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
        yaml.text().unwrap()
    }

    fn values(raw: &str) -> Vec<Value> {
        MultiDoc::parse(raw)
            .unwrap()
            .documents()
            .iter()
            .map(|d| d.value.clone())
            .collect()
    }

    /// Whether everything `part` holds is in `whole` as well: its keys with their values, its
    /// items in their places.
    fn within(part: &Value, whole: &Value) -> bool {
        match (part, whole) {
            (Value::Mapping(part), Value::Mapping(whole)) => part
                .iter()
                .all(|(key, value)| whole.get(key).is_some_and(|w| within(value, w))),
            (Value::Sequence(part), Value::Sequence(whole)) => {
                part.len() == whole.len() && part.iter().zip(whole).all(|(p, w)| within(p, w))
            }
            _ => part == whole,
        }
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
        for node in topology(&run(&slipmesh())).nodes {
            assert!(node.mesh_private_key.is_some(), "{}", node.name);
        }
    }

    #[test]
    fn a_link_gets_the_nine_generated_fields_nested_under_it() {
        let links = topology(&run(&slipmesh())).mesh.links;
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
    }

    #[test]
    fn every_value_written_before_stays() {
        let raw = slipmesh();
        let (before, after) = (values(&raw), values(&run(&raw)));
        assert_eq!(before.len(), after.len());
        for (before, after) in before.iter().zip(&after) {
            assert!(within(before, after), "{before:?}\n{after:?}");
        }
    }

    /// A pool as its own `slipmesh.yaml` document.
    const PLAIN_POOL: &str = r#"slipmesh:
  kind: roadwarriors
name: plain
node_hostnames: ["a", "b"]
address: "203.0.113.1/27"
listen_port: 51820
plain: true
clients:
  - {name: alice, public_key: "AAA=", allowed_ips: ["203.0.113.21/32"]}
  - {name: bob, public_key: "BBB=", allowed_ips: ["203.0.113.12/32"]}
"#;

    fn client(name: &str) -> RoadwarriorClient {
        RoadwarriorClient {
            name: name.to_owned(),
            public_key: format!("{name}="),
            private_key: None,
            allowed_ips: vec!["203.0.113.29/32".to_owned()],
            advanced_security: false,
        }
    }

    /// `source` after `edit`, as the text it comes back as.
    fn edited(source: &str, edit: impl FnOnce(&mut MultiDoc)) -> String {
        let mut yaml = MultiDoc::parse(source).unwrap();
        edit(&mut yaml);
        yaml.text().unwrap()
    }

    /// The pool in `source` without its clients.
    fn without_clients(source: &str) -> Value {
        let mut pool = values(source).remove(0);
        pool.as_mapping_mut().unwrap().shift_remove("clients");
        pool
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
        assert_eq!(without_clients(&out), without_clients(PLAIN_POOL));
        let (before, after) = (&values(PLAIN_POOL)[0], &values(&out)[0]);
        for kept in 0..2 {
            assert_eq!(after["clients"][kept], before["clients"][kept]);
        }
        assert_eq!(client_names(&out), ["alice", "bob", "dave"]);
    }

    #[test]
    fn add_client_starts_the_list_a_pool_lacks() {
        let pool = PLAIN_POOL.split("clients:").next().unwrap();
        let out = edited(pool, |yaml| add_client(yaml, 0, &client("dave")).unwrap());
        assert_eq!(without_clients(&out), without_clients(pool));
        assert_eq!(client_names(&out), ["dave"]);
    }

    #[test]
    fn remove_client_deletes_exactly_the_target() {
        let out = edited(PLAIN_POOL, |yaml| {
            remove_client(yaml, 0, 0).unwrap() // alice
        });
        assert_eq!(without_clients(&out), without_clients(PLAIN_POOL));
        assert_eq!(
            values(&out)[0]["clients"][0],
            values(PLAIN_POOL)[0]["clients"][1]
        );
        assert_eq!(client_names(&out), ["bob"]);
    }
}
