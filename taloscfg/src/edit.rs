//! Every edit `taloscfg` makes to `slipmesh.yaml`: minted secrets written into the fields they
//! belong to, roadwarrior clients added and removed.
//!
//! Written, a minted value is the operator's like any other: the next run mints nothing, and
//! deleting it mints a new identity for that node, link or pool, and for every peer that refers to
//! it. Only what the run generated is written - a field set on the entry or in the global
//! `obfuscation` is never copied down, and neither are the switches that are never generated.
//!
//! Edits go in through `yaml-rt` overlays: each document is read into a struct that names only the
//! fields written here, and written back as the smallest edit, so everything else in the file stays
//! as the operator wrote it.

use crate::mesh_config::RoadwarriorClient;
use crate::secrets::Minted;
use crate::slipmesh_file::SlipmeshFile;
use anyhow::{Context, Result};
use common::Obfuscation;
use yaml_rt::{YamlDoc, YamlRt};

/// The obfuscation fields the generator mints - `obfuscation_gen` fills these nine and no others.
/// Its own overlay because `common::Obfuscation` cannot take a `YamlRt` derive from this crate.
#[derive(YamlRt, Default, Debug, Clone, PartialEq)]
struct GeneratedObfuscation {
    #[yaml(skip_serializing_if = "Option::is_none")]
    jc: Option<u16>,
    #[yaml(skip_serializing_if = "Option::is_none")]
    jmin: Option<u16>,
    #[yaml(skip_serializing_if = "Option::is_none")]
    jmax: Option<u16>,
    #[yaml(skip_serializing_if = "Option::is_none")]
    s1: Option<u16>,
    #[yaml(skip_serializing_if = "Option::is_none")]
    s2: Option<u16>,
    #[yaml(skip_serializing_if = "Option::is_none")]
    h1: Option<u32>,
    #[yaml(skip_serializing_if = "Option::is_none")]
    h2: Option<u32>,
    #[yaml(skip_serializing_if = "Option::is_none")]
    h3: Option<u32>,
    #[yaml(skip_serializing_if = "Option::is_none")]
    h4: Option<u32>,
}

macro_rules! each_generated_field {
    ($apply:ident) => {
        $apply!(jc);
        $apply!(jmin);
        $apply!(jmax);
        $apply!(s1);
        $apply!(s2);
        $apply!(h1);
        $apply!(h2);
        $apply!(h3);
        $apply!(h4);
    };
}

impl GeneratedObfuscation {
    /// `self` with every field `generated` sets taken from it.
    fn fill(&mut self, generated: &Obfuscation) {
        macro_rules! fill {
            ($f:ident) => {
                if generated.$f.is_some() {
                    self.$f = generated.$f;
                }
            };
        }
        each_generated_field!(fill);
    }
}

#[derive(YamlRt)]
struct NetworkDocument {
    #[yaml(default)]
    nodes: Vec<NodeFields>,
    #[yaml(default, skip_serializing_if = "Option::is_none")]
    mesh: Option<MeshFields>,
}

#[derive(YamlRt)]
struct NodeFields {
    #[yaml(skip_serializing_if = "Option::is_none")]
    mesh_private_key: Option<String>,
}

#[derive(YamlRt)]
struct MeshFields {
    #[yaml(default)]
    links: Vec<LinkFields>,
}

#[derive(YamlRt)]
struct LinkFields {
    #[yaml(skip_serializing_if = "Option::is_none")]
    obfuscation: Option<GeneratedObfuscation>,
}

#[derive(YamlRt)]
struct PoolDocument {
    #[yaml(skip_serializing_if = "Option::is_none")]
    private_key: Option<String>,
    #[yaml(skip_serializing_if = "Option::is_none")]
    obfuscation: Option<GeneratedObfuscation>,
}

/// A pool document as far as its clients go - every other field of it is carried over as written.
#[derive(YamlRt)]
struct PoolClients {
    #[yaml(default)]
    clients: Vec<ClientFields>,
}

/// One client entry as `rw-add` writes it.
#[derive(YamlRt)]
struct ClientFields {
    name: String,
    public_key: String,
    allowed_ips: Vec<String>,
}

/// Writes every value of `minted` into its field of `yaml`, the `slipmesh.yaml` `file` was read
/// from.
pub fn record(yaml: &mut YamlDoc, file: &SlipmeshFile, minted: &Minted) -> Result<()> {
    if !minted.node_keys.is_empty() || !minted.link_obfuscation.is_empty() {
        let index = file.network_document();
        let mut network: NetworkDocument = yaml.read_document(index)?;
        for (node, key) in &minted.node_keys {
            network
                .nodes
                .get_mut(*node)
                .context("a node the network document does not have")?
                .mesh_private_key = Some(key.clone());
        }
        for (link, generated) in &minted.link_obfuscation {
            network
                .mesh
                .as_mut()
                .and_then(|mesh| mesh.links.get_mut(*link))
                .context("a link the network document does not have")?
                .obfuscation
                .get_or_insert_with(Default::default)
                .fill(generated);
        }
        yaml.write_document(index, &network)?;
    }

    for pool_minted in &minted.pools {
        let name = &pool_minted.name;
        let index = file
            .pool_document(name)
            .with_context(|| format!("pool {name:?} is in no document"))?;
        let mut pool: PoolDocument = yaml.read_document(index)?;
        if let Some(key) = &pool_minted.private_key {
            pool.private_key = Some(key.clone());
        }
        if let Some(generated) = &pool_minted.obfuscation {
            pool.obfuscation
                .get_or_insert_with(Default::default)
                .fill(generated);
        }
        yaml.write_document(index, &pool)?;
    }
    Ok(())
}

/// Adds `client` to the `clients` of the pool at `document` in `yaml`. Everything outside that one
/// sequence - comments, the rest of the pool, formatting - is untouched.
pub fn add_client(yaml: &mut YamlDoc, document: usize, client: &RoadwarriorClient) -> Result<()> {
    let mut pool: PoolClients = yaml.read_document(document)?;
    pool.clients.push(ClientFields {
        name: client.name.clone(),
        public_key: client.public_key.clone(),
        allowed_ips: client.allowed_ips.clone(),
    });
    yaml.write_document(document, &pool)?;
    Ok(())
}

/// Removes `clients[client_index]` from the pool at `document` in `yaml`, line and all - same
/// "everything else untouched" guarantee as `add_client`.
pub fn remove_client(yaml: &mut YamlDoc, document: usize, client_index: usize) -> Result<()> {
    let clients = yaml
        .get_path_in_document(document, &["clients"])?
        .context("pool has no clients list")?;
    let mut position = 0;
    yaml.sequence_editor(clients)?.retain(|_, _| {
        let keep = position != client_index;
        position += 1;
        keep
    })?;
    Ok(())
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
        let mut yaml = YamlDoc::parse(raw).unwrap();
        let file = SlipmeshFile::read(raw, &yaml).unwrap();
        let (_, minted) = secrets::resolve(&file.topology().unwrap());
        record(&mut yaml, &file, &minted).unwrap();
        yaml.to_string()
    }

    fn topology(raw: &str) -> MeshConfig {
        SlipmeshFile::parse(raw).unwrap().topology().unwrap()
    }

    fn keys_of(obfuscation: &Obfuscation) -> Vec<String> {
        let value = yaml_serde::to_value(obfuscation).unwrap();
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
                    "      node_id: {}\n      mesh_private_key: {key}\n",
                    node.node_id
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

    #[test]
    fn a_second_run_mints_nothing_and_changes_nothing() {
        let first = run(&slipmesh());
        let file = SlipmeshFile::parse(&first).unwrap();
        let (_, minted) = secrets::resolve(&file.topology().unwrap());
        assert!(minted.is_empty(), "{:?}", minted.routes());
        let mut yaml = YamlDoc::parse(&first).unwrap();
        record(&mut yaml, &file, &minted).unwrap();
        assert_eq!(yaml.to_string(), first);
    }

    #[test]
    fn a_flow_entry_takes_its_value_in_flow_style() {
        let raw = slipmesh().replace(
            "    - name: node-c\n      node_id: 10.62.0.3\n",
            "    - {name: node-c, node_id: 10.62.0.3}\n",
        );
        let recorded = run(&raw);
        let line = recorded
            .lines()
            .find(|l| l.contains("node-c,"))
            .expect(&recorded);
        assert!(line.contains("mesh_private_key"), "{line}");
        assert!(topology(&recorded).nodes[2].mesh_private_key.is_some());
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
            allowed_ips: vec!["198.51.100.99/32".to_owned()],
            advanced_security: false,
        }
    }

    /// `source` after `edit`, as the text it comes back as.
    fn edited(source: &str, edit: impl FnOnce(&mut YamlDoc)) -> String {
        let mut yaml = YamlDoc::parse(source).unwrap();
        edit(&mut yaml);
        yaml.to_string()
    }

    fn client_names(source: &str) -> Vec<String> {
        let value: yaml_serde::Value = yaml_serde::from_str(source).unwrap();
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
    fn add_client_onto_an_empty_flow_clients_list() {
        let src = r#"slipmesh:
  kind: roadwarriors
name: fresh
node_hostnames: ["a"]
address: "198.51.100.250/24"
listen_port: 51830
clients: []
"#;
        let out = edited(src, |yaml| add_client(yaml, 0, &client("eve")).unwrap());
        assert!(
            out.starts_with(&src[..src.find("clients").unwrap()]),
            "{out}"
        );
        assert_eq!(client_names(&out), ["eve"]);
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
