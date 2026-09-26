//! What a run minted, and the field of `slipmesh.yaml` each value is written into: a node's
//! `mesh_private_key`, the obfuscation fields a link or pool left unset, a pool's `private_key`.
//!
//! Written, a value is the operator's like any other: the next run mints nothing, and deleting it
//! mints a new identity for that node, link or pool, and for every peer that refers to it. Only
//! what the run generated is written - a field set on the entry or in the global `obfuscation` is
//! never copied down, and neither are the switches that are never generated.
//!
//! The values go in through `yaml-rt` overlays: each document is read into a struct that names only
//! the fields written here, and written back as the smallest edit, so everything else in the file
//! stays as the operator wrote it.

use crate::mesh_config::MeshConfig;
use crate::render::{ResolvedSecrets, link_key};
use crate::slipmesh_file::SlipmeshFile;
use anyhow::{Context, Result};
use common::Obfuscation;
use yaml_rt::{YamlDoc, YamlRt};

/// The obfuscation fields the generator mints - `obfuscation_gen` fills these nine and no others.
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
    /// The fields of `resolved` none of `layers` set - the ones this run generated.
    fn of(resolved: &Obfuscation, layers: &[&Obfuscation]) -> Option<Self> {
        let mut generated = Self::default();
        macro_rules! take {
            ($f:ident) => {
                if layers.iter().all(|layer| layer.$f.is_none()) {
                    generated.$f = resolved.$f;
                }
            };
        }
        each_generated_field!(take);
        (generated != Self::default()).then_some(generated)
    }

    /// `self` with every field `other` sets taken from it.
    fn fill(&mut self, other: &Self) {
        macro_rules! fill {
            ($f:ident) => {
                if other.$f.is_some() {
                    self.$f = other.$f;
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

/// One pool's minted values.
#[derive(Default)]
struct PoolMinted {
    private_key: Option<String>,
    obfuscation: Option<GeneratedObfuscation>,
}

/// The values a run minted, each with the field it goes in.
#[derive(Default)]
pub struct Minted {
    /// By the node's position in `nodes`.
    node_keys: Vec<(usize, String)>,
    /// By the link's position in `mesh.links`.
    link_obfuscation: Vec<(usize, GeneratedObfuscation)>,
    /// By the pool's name.
    pools: Vec<(String, PoolMinted)>,
    /// How a message names each value.
    names: Vec<String>,
}

/// What `resolved` holds that `topology` leaves unset.
pub fn minted(topology: &MeshConfig, resolved: &ResolvedSecrets) -> Result<Minted> {
    let mut out = Minted::default();

    for (index, node) in topology.nodes.iter().enumerate() {
        if node.mesh_private_key.is_some() {
            continue;
        }
        let key = resolved
            .mesh_private_keys
            .get(&node.name)
            .with_context(|| format!("no key resolved for node {:?}", node.name))?;
        out.node_keys.push((index, key.clone()));
        out.names
            .push(format!("nodes[{}].mesh_private_key", node.name));
    }

    for (index, link) in topology.mesh.links.iter().enumerate() {
        if link.plain {
            continue;
        }
        let pair = link_key(&link.pair);
        let generated = resolved
            .mesh_link_obfuscation
            .get(&pair)
            .and_then(|resolved| {
                GeneratedObfuscation::of(resolved, &[&link.obfuscation, &topology.obfuscation])
            });
        if let Some(generated) = generated {
            out.link_obfuscation.push((index, generated));
            out.names.push(format!("mesh.links[{pair}].obfuscation"));
        }
    }

    for pool in &topology.roadwarriors {
        let mut minted = PoolMinted::default();
        if pool.private_key.is_none() {
            let key = resolved
                .roadwarrior_private_keys
                .get(&pool.name)
                .with_context(|| format!("no key resolved for pool {:?}", pool.name))?;
            minted.private_key = Some(key.clone());
            out.names
                .push(format!("roadwarriors[{}].private_key", pool.name));
        }
        if !pool.plain {
            minted.obfuscation =
                resolved
                    .roadwarrior_obfuscation
                    .get(&pool.name)
                    .and_then(|resolved| {
                        GeneratedObfuscation::of(
                            resolved,
                            &[&pool.obfuscation, &topology.obfuscation],
                        )
                    });
            if minted.obfuscation.is_some() {
                out.names
                    .push(format!("roadwarriors[{}].obfuscation", pool.name));
            }
        }
        if minted.private_key.is_some() || minted.obfuscation.is_some() {
            out.pools.push((pool.name.clone(), minted));
        }
    }

    Ok(out)
}

impl Minted {
    pub fn is_empty(&self) -> bool {
        self.names.is_empty()
    }

    /// Where each value goes, the way a message names it.
    pub fn routes(&self) -> Vec<String> {
        self.names.clone()
    }

    /// Writes every value into its field of `yaml`, the `slipmesh.yaml` `file` was read from.
    pub fn record(&self, yaml: &mut YamlDoc, file: &SlipmeshFile) -> Result<()> {
        if !self.node_keys.is_empty() || !self.link_obfuscation.is_empty() {
            let index = file.network_document();
            let mut network: NetworkDocument = yaml.read_document(index)?;
            for (node, key) in &self.node_keys {
                network
                    .nodes
                    .get_mut(*node)
                    .context("a node the network document does not have")?
                    .mesh_private_key = Some(key.clone());
            }
            for (link, generated) in &self.link_obfuscation {
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

        for (name, minted) in &self.pools {
            let index = file
                .pool_document(name)
                .with_context(|| format!("pool {name:?} is in no document"))?;
            let mut pool: PoolDocument = yaml.read_document(index)?;
            if let Some(key) = &minted.private_key {
                pool.private_key = Some(key.clone());
            }
            if let Some(generated) = &minted.obfuscation {
                pool.obfuscation
                    .get_or_insert_with(Default::default)
                    .fill(generated);
            }
            yaml.write_document(index, &pool)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::render::{NothingStored, resolve_secrets};
    use common::Obfuscation;

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

    /// One run: resolve with nothing stored, write down what was minted.
    fn run(raw: &str) -> String {
        let mut yaml = YamlDoc::parse(raw).unwrap();
        let file = SlipmeshFile::read(raw, &yaml).unwrap();
        let topology = file.topology().unwrap();
        let resolved = resolve_secrets(&topology, &NothingStored);
        minted(&topology, &resolved)
            .unwrap()
            .record(&mut yaml, &file)
            .unwrap();
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
        let topology = file.topology().unwrap();
        let minted = minted(&topology, &resolve_secrets(&topology, &NothingStored)).unwrap();
        assert!(minted.is_empty(), "{:?}", minted.routes());
        let mut yaml = YamlDoc::parse(&first).unwrap();
        minted.record(&mut yaml, &file).unwrap();
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

    #[test]
    fn routes_name_each_value_by_what_it_belongs_to() {
        let raw = slipmesh();
        let topology = topology(&raw);
        let minted = minted(&topology, &resolve_secrets(&topology, &NothingStored)).unwrap();
        assert_eq!(
            minted.routes(),
            [
                "nodes[node-a].mesh_private_key",
                "nodes[node-b].mesh_private_key",
                "nodes[node-c].mesh_private_key",
                "mesh.links[node-a|node-b].obfuscation",
                "roadwarriors[obfuscated].private_key",
                "roadwarriors[plain].private_key",
            ]
        );
    }
}
