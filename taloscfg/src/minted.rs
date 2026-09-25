//! What a run minted, and the field of `slipmesh.yaml` each value is written into: a node's
//! `mesh_private_key`, the obfuscation fields a link or pool left unset, a pool's `private_key`.
//!
//! Written, a value is the operator's like any other: the next run mints nothing, and deleting it
//! mints a new identity for that node, link or pool, and for every peer that refers to it. Only
//! what the run generated is written - a field set on the entry or in the global `obfuscation` is
//! never copied down, and neither are the switches that are never generated.

use crate::document;
use crate::mesh_config::MeshConfig;
use crate::render::{ResolvedSecrets, link_key};
use crate::slipmesh_file::SlipmeshFile;
use anyhow::{Context, Result, bail};
use common::Obfuscation;
use std::ops::Range;
use yaml_serde::{Mapping, Value};
use yamlpath::{Component, Route};

/// The values a run minted, each with the field it goes in.
pub struct Minted {
    entries: Vec<Entry>,
}

/// Which document of `slipmesh.yaml` a value goes in.
#[derive(PartialEq, Clone)]
enum Home {
    Network,
    Pool(String),
}

/// One value, and where it goes: `key` in the mapping at `parent`.
struct Entry {
    home: Home,
    parent: Vec<Component<'static>>,
    key: &'static str,
    value: Value,
    /// How a message names it.
    name: String,
}

/// What `resolved` holds that `topology` leaves unset.
pub fn minted(topology: &MeshConfig, resolved: &ResolvedSecrets) -> Result<Minted> {
    let mut entries = Vec::new();

    for (index, node) in topology.nodes.iter().enumerate() {
        if node.mesh_private_key.is_some() {
            continue;
        }
        let key = resolved
            .mesh_private_keys
            .get(&node.name)
            .with_context(|| format!("no key resolved for node {:?}", node.name))?;
        entries.push(Entry {
            home: Home::Network,
            parent: vec!["nodes".into(), index.into()],
            key: "mesh_private_key",
            value: key.as_str().into(),
            name: format!("nodes[{}].mesh_private_key", node.name),
        });
    }

    for (index, link) in topology.mesh.links.iter().enumerate() {
        if link.plain {
            continue;
        }
        let pair = link_key(&link.pair);
        let generated = generated_fields(
            resolved.mesh_link_obfuscation.get(&pair),
            &[&link.obfuscation, &topology.obfuscation],
        )?;
        if let Some(fields) = generated {
            entries.push(Entry {
                home: Home::Network,
                parent: vec!["mesh".into(), "links".into(), index.into()],
                key: "obfuscation",
                value: Value::Mapping(fields),
                name: format!("mesh.links[{pair}].obfuscation"),
            });
        }
    }

    for pool in &topology.roadwarriors {
        let home = Home::Pool(pool.name.clone());
        if pool.private_key.is_none() {
            let key = resolved
                .roadwarrior_private_keys
                .get(&pool.name)
                .with_context(|| format!("no key resolved for pool {:?}", pool.name))?;
            entries.push(Entry {
                home: home.clone(),
                parent: Vec::new(),
                key: "private_key",
                value: key.as_str().into(),
                name: format!("roadwarriors[{}].private_key", pool.name),
            });
        }
        if pool.plain {
            continue;
        }
        let generated = generated_fields(
            resolved.roadwarrior_obfuscation.get(&pool.name),
            &[&pool.obfuscation, &topology.obfuscation],
        )?;
        if let Some(fields) = generated {
            entries.push(Entry {
                home,
                parent: Vec::new(),
                key: "obfuscation",
                value: Value::Mapping(fields),
                name: format!("roadwarriors[{}].obfuscation", pool.name),
            });
        }
    }

    Ok(Minted { entries })
}

impl Minted {
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Where each value goes, the way a message names it.
    pub fn routes(&self) -> Vec<String> {
        self.entries.iter().map(|e| e.name.clone()).collect()
    }

    /// `raw`, the whole of `slipmesh.yaml`, with every value written into its field and every
    /// other byte as it was.
    pub fn record(&self, raw: &str, file: &SlipmeshFile) -> Result<String> {
        let mut homes: Vec<&Home> = Vec::new();
        for entry in &self.entries {
            if !homes.contains(&&entry.home) {
                homes.push(&entry.home);
            }
        }

        let mut edits: Vec<(Range<usize>, String)> = Vec::new();
        for home in homes {
            let span = match home {
                Home::Network => file.network_span(),
                Home::Pool(name) => file
                    .pool_span(name)
                    .with_context(|| format!("pool {name:?} is in no document"))?,
            };
            let mut text = raw[span.clone()].to_owned();
            for entry in self.entries.iter().filter(|e| &e.home == home) {
                text = entry
                    .write(&text)
                    .with_context(|| format!("writing {}", entry.name))?;
            }
            edits.push((span, text));
        }

        // From the last document back, so that the spans of those before it still hold.
        edits.sort_by_key(|(span, _)| std::cmp::Reverse(span.start));
        Ok(edits.into_iter().fold(raw.to_owned(), |out, (span, text)| {
            document::splice(&out, span, &text)
        }))
    }
}

impl Entry {
    /// `document` with this value written in. Obfuscation fields join an `obfuscation` mapping the
    /// entry already has, beside the fields written there by hand.
    fn write(&self, document: &str) -> Result<String> {
        let doc = yamlpath::Document::new(document).context("parsing the document")?;
        let mut own = self.parent.clone();
        own.push(self.key.into());
        let own = Route::from(own);
        let additions: Vec<(Route, String, Value)> = match &self.value {
            Value::Mapping(fields) if doc.query_exists(&own) => fields
                .iter()
                .map(|(k, v)| {
                    let key = k.as_str().context("a field that is not a string")?;
                    Ok((own.clone(), key.to_owned(), v.clone()))
                })
                .collect::<Result<_>>()?,
            value => vec![(
                Route::from(self.parent.clone()),
                self.key.to_owned(),
                value.clone(),
            )],
        };
        let patches: Vec<yamlpatch::Patch> = additions
            .into_iter()
            .map(|(route, key, value)| yamlpatch::Patch {
                route,
                operation: yamlpatch::Op::Add { key, value },
            })
            .collect();
        let patched = yamlpatch::apply_yaml_patches(&doc, &patches)?;
        Ok(patched.source().to_owned())
    }
}

/// The fields of `resolved` none of `layers` set - the ones this run generated - in declaration
/// order.
pub(crate) fn generated_fields(
    resolved: Option<&Obfuscation>,
    layers: &[&Obfuscation],
) -> Result<Option<Mapping>> {
    let Some(resolved) = resolved else {
        return Ok(None);
    };
    let mut fields = fields_of(resolved)?;
    for layer in layers {
        for key in fields_of(layer)?.keys() {
            fields.shift_remove(key);
        }
    }
    Ok((!fields.is_empty()).then_some(fields))
}

/// The fields an obfuscation sets - unset ones are not serialized.
fn fields_of(obfuscation: &Obfuscation) -> Result<Mapping> {
    match yaml_serde::to_value(obfuscation)? {
        Value::Mapping(fields) => Ok(fields),
        _ => bail!("obfuscation did not serialize to a mapping"),
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
        let file = SlipmeshFile::parse(raw).unwrap();
        let topology = file.topology().unwrap();
        let resolved = resolve_secrets(&topology, &NothingStored);
        minted(&topology, &resolved)
            .unwrap()
            .record(raw, &file)
            .unwrap()
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
        assert_eq!(minted.record(&first, &file).unwrap(), first);
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
