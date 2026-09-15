//! `slipmesh-secrets.yaml`: what the generator minted itself, kept so the next run mints nothing.
//!
//! Only minted values live here - a node's mesh key, the obfuscation fields a link or pool left for
//! the generator to fill, a pool's key. A value the operator wrote in `slipmesh.yaml` is never
//! copied in, so removing it from there really removes it.
//!
//! Its own file rather than a document in `slipmesh.yaml`: sops computes its metadata over a whole
//! physical file and encrypts every value in it, and encrypting `slipmesh.yaml` would turn the
//! topology an operator edits by hand into ciphertext.
//!
//! Writing is pointwise: a run with nothing new to record leaves the file byte for byte as it was,
//! and a run that mints something adds exactly that and touches nothing else.

use crate::mesh_config::MeshConfig;
use crate::render::{ExistingState, ResolvedSecrets, link_key};
use anyhow::{Context, Result, bail, ensure};
use common::Obfuscation;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::Path;
use yaml_serde::{Mapping, Value};

/// What opens a file this module creates.
pub const HEADER: &str = "\
# Maintained by slipmesh-taloscfg. Deleting a value mints a new one on the next run: a new
# identity for that node, link or pool, and for every peer that refers to it.
";

#[derive(Deserialize, Serialize, Default, Debug, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Secrets {
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub nodes: BTreeMap<String, NodeSecrets>,
    /// Keyed by `render::link_key`: the pair's names, sorted, joined with `|`.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub links: BTreeMap<String, LinkSecrets>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub roadwarriors: BTreeMap<String, PoolSecrets>,
}

#[derive(Deserialize, Serialize, Default, Debug, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct NodeSecrets {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mesh_private_key: Option<String>,
}

#[derive(Deserialize, Serialize, Default, Debug, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct LinkSecrets {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub obfuscation: Option<Obfuscation>,
}

#[derive(Deserialize, Serialize, Default, Debug, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct PoolSecrets {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub private_key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub obfuscation: Option<Obfuscation>,
}

impl Secrets {
    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty() && self.links.is_empty() && self.roadwarriors.is_empty()
    }
}

pub struct SecretsFile {
    raw: String,
    secrets: Secrets,
    /// Whether the file holds a mapping to add to, or nothing yet - empty, or only comments.
    holds_mapping: bool,
}

impl SecretsFile {
    pub fn parse(raw: &str) -> Result<Self> {
        let value: Value = yaml_serde::from_str(raw).context("parsing the secrets file")?;
        let holds_mapping = !value.is_null();
        let secrets = if holds_mapping {
            yaml_serde::from_value(value).context("reading the secrets file")?
        } else {
            Secrets::default()
        };
        Ok(Self {
            raw: raw.to_owned(),
            secrets,
            holds_mapping,
        })
    }

    /// A file that does not exist holds nothing yet. One that exists and cannot be read stops the
    /// run: read as "no secrets", it would mint a new identity for every node in it.
    pub fn read(path: &Path) -> Result<Self> {
        match std::fs::read_to_string(path) {
            Ok(raw) => Self::parse(&raw).with_context(|| format!("reading {}", path.display())),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Self::parse(""),
            Err(e) => Err(e).with_context(|| format!("reading {}", path.display())),
        }
    }

    /// What `resolved` holds that was minted in this run: set neither in `topology` nor here.
    ///
    /// Refuses a key written both in `topology` and here with different values - resolution
    /// prefers the topology's, so the stored one would be silently ignored.
    pub fn additions(&self, topology: &MeshConfig, resolved: &ResolvedSecrets) -> Result<Secrets> {
        let mut out = Secrets::default();

        for node in &topology.nodes {
            let stored = self.mesh_private_key(&node.name);
            let key = minted_key(
                node.mesh_private_key.as_deref(),
                stored.as_deref(),
                resolved.mesh_private_keys.get(&node.name),
                || format!("node {:?}: `mesh_private_key`", node.name),
            )?;
            if let Some(key) = key {
                out.nodes.insert(
                    node.name.clone(),
                    NodeSecrets {
                        mesh_private_key: Some(key),
                    },
                );
            }
        }

        for link in topology.mesh.links.iter().filter(|l| !l.plain) {
            let key = link_key(&link.pair);
            let obfuscation = minted_obfuscation(
                resolved.mesh_link_obfuscation.get(&key),
                &[
                    &link.obfuscation,
                    &topology.obfuscation,
                    &self.mesh_link_obfuscation(&link.pair).unwrap_or_default(),
                ],
            )?;
            if obfuscation.is_some() {
                out.links.insert(key, LinkSecrets { obfuscation });
            }
        }

        for pool in &topology.roadwarriors {
            let stored = self.roadwarrior_private_key(&pool.name);
            let private_key = minted_key(
                pool.private_key.as_deref(),
                stored.as_deref(),
                resolved.roadwarrior_private_keys.get(&pool.name),
                || format!("roadwarriors pool {:?}: `private_key`", pool.name),
            )?;
            let obfuscation = if pool.plain {
                None
            } else {
                minted_obfuscation(
                    resolved.roadwarrior_obfuscation.get(&pool.name),
                    &[
                        &pool.obfuscation,
                        &topology.obfuscation,
                        &self.roadwarrior_obfuscation(&pool.name).unwrap_or_default(),
                    ],
                )?
            };
            if private_key.is_some() || obfuscation.is_some() {
                out.roadwarriors.insert(
                    pool.name.clone(),
                    PoolSecrets {
                        private_key,
                        obfuscation,
                    },
                );
            }
        }

        Ok(out)
    }

    /// The file's text with `additions` recorded in it, every other byte as it was.
    pub fn with(&self, additions: &Secrets) -> Result<String> {
        if additions.is_empty() {
            return Ok(self.raw.clone());
        }
        let Value::Mapping(additions) = yaml_serde::to_value(additions)? else {
            bail!("secrets did not serialize to a mapping");
        };
        if !self.holds_mapping {
            let lead = if self.raw.trim().is_empty() {
                HEADER.to_owned()
            } else {
                format!("{}\n", self.raw.trim_end())
            };
            return Ok(lead + &yaml_serde::to_string(&additions)?);
        }

        let document =
            yamlpath::Document::new(self.raw.as_str()).context("parsing the secrets file")?;
        let mut new_keys = Vec::new();
        find_new_keys(&document, &[], &additions, &mut new_keys)?;
        let patches: Vec<yamlpatch::Patch> = new_keys
            .iter()
            .map(|(route, key, value)| yamlpatch::Patch {
                route: yamlpath::Route::from(
                    route
                        .iter()
                        .map(|k| yamlpath::Component::from(k.as_str()))
                        .collect::<Vec<_>>(),
                ),
                operation: yamlpatch::Op::Add {
                    key: key.clone(),
                    value: value.clone(),
                },
            })
            .collect();
        let patched =
            yamlpatch::apply_yaml_patches(&document, &patches).context("recording new secrets")?;
        Ok(patched.source().to_owned())
    }

    /// Routes of entries whose node, link or pool is no longer in `topology`. They are kept, not
    /// pruned: taking a node out of the topology is how it leaves the cluster, and pruning its key
    /// would mean a new identity if it ever came back.
    pub fn orphans(&self, topology: &MeshConfig) -> Vec<String> {
        let nodes = self
            .secrets
            .nodes
            .keys()
            .filter(|name| !topology.nodes.iter().any(|n| &n.name == *name))
            .map(|name| format!("nodes.{name}"));
        let links = self
            .secrets
            .links
            .keys()
            .filter(|key| {
                !topology
                    .mesh
                    .links
                    .iter()
                    .any(|l| &link_key(&l.pair) == *key)
            })
            .map(|key| format!("links.{key}"));
        let pools = self
            .secrets
            .roadwarriors
            .keys()
            .filter(|name| !topology.roadwarriors.iter().any(|p| &p.name == *name))
            .map(|name| format!("roadwarriors.{name}"));
        nodes.chain(links).chain(pools).collect()
    }
}

/// The key to record, if this run minted it: the topology did not set one and the file had none.
fn minted_key(
    written: Option<&str>,
    stored: Option<&str>,
    resolved: Option<&String>,
    what: impl Fn() -> String,
) -> Result<Option<String>> {
    if let (Some(written), Some(stored)) = (written, stored) {
        ensure!(
            written == stored,
            "{} is written in slipmesh.yaml and differs from the one in the secrets file - keep \
             one of them",
            what()
        );
    }
    Ok(match (written, stored) {
        (None, None) => resolved.cloned(),
        _ => None,
    })
}

/// The fields of `resolved` none of `layers` set - the ones this run generated.
fn minted_obfuscation(
    resolved: Option<&Obfuscation>,
    layers: &[&Obfuscation],
) -> Result<Option<Obfuscation>> {
    let Some(resolved) = resolved else {
        return Ok(None);
    };
    let mut fields = fields_of(resolved)?;
    for layer in layers {
        for key in fields_of(layer)?.keys() {
            fields.shift_remove(key);
        }
    }
    if fields.is_empty() {
        return Ok(None);
    }
    Ok(Some(yaml_serde::from_value(Value::Mapping(fields))?))
}

/// The fields an obfuscation sets, in declaration order - unset ones are not serialized.
fn fields_of(obfuscation: &Obfuscation) -> Result<Mapping> {
    match yaml_serde::to_value(obfuscation)? {
        Value::Mapping(fields) => Ok(fields),
        _ => bail!("obfuscation did not serialize to a mapping"),
    }
}

/// Walks `additions` down `document` to where each one stops existing, and records the addition
/// there: a whole new entry under a section, or a field under an entry that already has others.
fn find_new_keys(
    document: &yamlpath::Document,
    route: &[String],
    additions: &Mapping,
    out: &mut Vec<(Vec<String>, String, Value)>,
) -> Result<()> {
    for (key, value) in additions {
        let key = key.as_str().context("a secrets key is not a string")?;
        let child: Vec<String> = route.iter().cloned().chain([key.to_owned()]).collect();
        let child_route = yamlpath::Route::from(
            child
                .iter()
                .map(|k| yamlpath::Component::from(k.as_str()))
                .collect::<Vec<_>>(),
        );
        if !document.query_exists(&child_route) {
            out.push((route.to_vec(), key.to_owned(), value.clone()));
            continue;
        }
        let Value::Mapping(inner) = value else {
            bail!("{} is already recorded", child.join("."));
        };
        find_new_keys(document, &child, inner, out)?;
    }
    Ok(())
}

impl ExistingState for SecretsFile {
    fn mesh_private_key(&self, node_name: &str) -> Option<String> {
        self.secrets.nodes.get(node_name)?.mesh_private_key.clone()
    }

    fn mesh_link_obfuscation(&self, pair: &[String; 2]) -> Option<Obfuscation> {
        self.secrets.links.get(&link_key(pair))?.obfuscation.clone()
    }

    fn roadwarrior_private_key(&self, pool_name: &str) -> Option<String> {
        self.secrets
            .roadwarriors
            .get(pool_name)?
            .private_key
            .clone()
    }

    fn roadwarrior_obfuscation(&self, pool_name: &str) -> Option<Obfuscation> {
        self.secrets
            .roadwarriors
            .get(pool_name)?
            .obfuscation
            .clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::render::resolve_secrets;

    const TOPOLOGY: &str = r#"
cluster:
  bgp_as: 64512
  loopback_networks: {ipv4: "10.62.0.0/16", ipv6: "fd00:62::/32"}
nodes:
  - {name: node-a, node_id: "10.62.0.1"}
  - {name: node-b, node_id: "10.62.0.2"}
  - {name: node-c, node_id: "10.62.0.3"}
mesh:
  links:
    - {pair: [node-b, node-a], port: 51820}
    - {pair: [node-a, node-c], port: 51821, plain: true}
roadwarriors:
  - name: obfuscated
    node_hostnames: [node-a]
    address: "10.99.0.1/24"
    listen_port: 51900
    obfuscation: {jc: 4, jmin: 10, jmax: 50, s1: 1, s2: 2, h1: 5, h2: 6, h3: 7, h4: 8}
  - {name: plain, node_hostnames: [node-b], address: "10.98.0.1/24", listen_port: 51901, plain: true}
"#;

    fn topology(yaml: &str) -> MeshConfig {
        yaml_serde::from_str(yaml).unwrap()
    }

    /// One whole run: resolve against the file, record what was minted.
    fn run(topology: &MeshConfig, file: &SecretsFile) -> String {
        let resolved = resolve_secrets(topology, file);
        let additions = file.additions(topology, &resolved).unwrap();
        file.with(&additions).unwrap()
    }

    fn written(topology: &MeshConfig) -> Secrets {
        let text = run(topology, &SecretsFile::parse("").unwrap());
        yaml_serde::from_str(&text).unwrap()
    }

    fn obfuscation_keys(obfuscation: &Obfuscation) -> Vec<String> {
        let value = yaml_serde::to_value(obfuscation).unwrap();
        value
            .as_mapping()
            .unwrap()
            .keys()
            .map(|k| k.as_str().unwrap().to_owned())
            .collect()
    }

    const NINE: [&str; 9] = ["jc", "jmin", "jmax", "s1", "s2", "h1", "h2", "h3", "h4"];

    // Reading.

    #[test]
    fn a_node_key_reads_back() {
        let file = SecretsFile::parse("nodes:\n  node-a:\n    mesh_private_key: KEY\n").unwrap();
        assert_eq!(file.mesh_private_key("node-a").as_deref(), Some("KEY"));
        assert_eq!(file.mesh_private_key("node-b"), None);
    }

    #[test]
    fn link_obfuscation_reads_back_whichever_way_round_the_pair_is() {
        let file =
            SecretsFile::parse("links:\n  node-a|node-b:\n    obfuscation: {jc: 7}\n").unwrap();
        for pair in [["node-a", "node-b"], ["node-b", "node-a"]] {
            let pair = pair.map(str::to_owned);
            assert_eq!(file.mesh_link_obfuscation(&pair).unwrap().jc, Some(7));
        }
    }

    #[test]
    fn pool_secrets_read_back() {
        let file = SecretsFile::parse(
            "roadwarriors:\n  plain:\n    private_key: KEY\n    obfuscation: {s1: 3}\n",
        )
        .unwrap();
        assert_eq!(
            file.roadwarrior_private_key("plain").as_deref(),
            Some("KEY")
        );
        assert_eq!(file.roadwarrior_obfuscation("plain").unwrap().s1, Some(3));
    }

    #[test]
    fn a_file_that_does_not_parse_stops_the_run() {
        assert!(SecretsFile::parse("nodes:\n  node-a: [unterminated\n").is_err());
        assert!(SecretsFile::parse("nodez: {}\n").is_err());
    }

    #[test]
    fn a_file_that_does_not_exist_holds_nothing() {
        let path = std::env::temp_dir().join("slipmesh-secrets-test-that-never-exists.yaml");
        let file = SecretsFile::read(&path).unwrap();
        assert_eq!(file.mesh_private_key("node-a"), None);
    }

    // Writing.

    #[test]
    fn a_first_run_creates_the_file_with_every_minted_value() {
        let text = run(&topology(TOPOLOGY), &SecretsFile::parse("").unwrap());
        assert!(text.starts_with(HEADER), "{text}");
        let secrets: Secrets = yaml_serde::from_str(&text).unwrap();
        let nodes: Vec<_> = secrets.nodes.keys().collect();
        assert_eq!(nodes, ["node-a", "node-b", "node-c"]);
    }

    #[test]
    fn a_link_records_exactly_the_nine_generated_fields() {
        let secrets = written(&topology(TOPOLOGY));
        let obfuscation = secrets.links["node-a|node-b"].obfuscation.as_ref().unwrap();
        assert_eq!(obfuscation_keys(obfuscation), NINE);
    }

    #[test]
    fn switches_that_skip_the_stored_tier_are_never_recorded() {
        let yaml = TOPOLOGY.replace(
            "cluster:\n",
            "obfuscation: {random_trailers: true, disable_cookies: true}\ncluster:\n",
        );
        let secrets = written(&topology(&yaml));
        let obfuscation = secrets.links["node-a|node-b"].obfuscation.as_ref().unwrap();
        assert_eq!(obfuscation_keys(obfuscation), NINE);
    }

    #[test]
    fn a_field_pinned_in_the_topology_is_not_recorded() {
        let yaml = TOPOLOGY.replace(
            "{pair: [node-b, node-a], port: 51820}",
            "{pair: [node-b, node-a], port: 51820, obfuscation: {jc: 9}}",
        );
        let secrets = written(&topology(&yaml));
        let obfuscation = secrets.links["node-a|node-b"].obfuscation.as_ref().unwrap();
        assert!(!obfuscation_keys(obfuscation).contains(&"jc".to_owned()));
    }

    #[test]
    fn a_pool_with_all_nine_fields_written_records_only_its_key() {
        let secrets = written(&topology(TOPOLOGY));
        assert_eq!(
            secrets.roadwarriors["obfuscated"],
            PoolSecrets {
                private_key: secrets.roadwarriors["obfuscated"].private_key.clone(),
                obfuscation: None,
            }
        );
        assert!(secrets.roadwarriors["obfuscated"].private_key.is_some());
    }

    #[test]
    fn plain_links_and_pools_record_no_obfuscation() {
        let secrets = written(&topology(TOPOLOGY));
        assert!(!secrets.links.contains_key("node-a|node-c"));
        assert_eq!(secrets.roadwarriors["plain"].obfuscation, None);
    }

    #[test]
    fn a_second_run_leaves_the_file_byte_for_byte() {
        let topology = topology(TOPOLOGY);
        let first = run(&topology, &SecretsFile::parse("").unwrap());
        let second = run(&topology, &SecretsFile::parse(&first).unwrap());
        assert_eq!(first, second);
    }

    #[test]
    fn a_new_node_is_added_without_touching_what_is_there() {
        let before = "# an operator's note\nnodes:\n  node-a:\n    mesh_private_key: A   # kept\n  node-b:\n    mesh_private_key: B\nlinks:\n  node-a|node-b:\n    obfuscation: {jc: 4, jmin: 10, jmax: 50, s1: 1, s2: 2, h1: 5, h2: 6, h3: 7, h4: 8}\nroadwarriors:\n  obfuscated:\n    private_key: P\n  plain:\n    private_key: Q\n";
        let after = run(&topology(TOPOLOGY), &SecretsFile::parse(before).unwrap());
        assert!(
            after.starts_with(
                "# an operator's note\nnodes:\n  node-a:\n    mesh_private_key: A   # kept\n  node-b:\n    mesh_private_key: B\n"
            ),
            "{after}"
        );
        let secrets: Secrets = yaml_serde::from_str(&after).unwrap();
        assert!(secrets.nodes["node-c"].mesh_private_key.is_some());
        assert_eq!(
            secrets.roadwarriors["obfuscated"].private_key.as_deref(),
            Some("P")
        );
        assert_eq!(after.matches("node-c:").count(), 1, "{after}");
    }

    #[test]
    fn a_missing_field_is_added_to_an_entry_that_exists() {
        let before = "nodes:\n  node-a:\n    mesh_private_key: A\n  node-b:\n    mesh_private_key: B\n  node-c:\n    mesh_private_key: C\nlinks:\n  node-a|node-b:\n    obfuscation: {jc: 4}\nroadwarriors:\n  obfuscated:\n    private_key: P\n  plain:\n    private_key: Q\n";
        let after = run(&topology(TOPOLOGY), &SecretsFile::parse(before).unwrap());
        let secrets: Secrets = yaml_serde::from_str(&after).unwrap();
        let obfuscation = secrets.links["node-a|node-b"].obfuscation.as_ref().unwrap();
        assert_eq!(obfuscation.jc, Some(4));
        assert_eq!(obfuscation_keys(obfuscation).len(), 9);
    }

    #[test]
    fn a_missing_section_is_added_without_touching_what_is_there() {
        let before = "nodes:\n  node-a:\n    mesh_private_key: A\n  node-b:\n    mesh_private_key: B\n  node-c:\n    mesh_private_key: C\nroadwarriors:\n  obfuscated:\n    private_key: P\n  plain:\n    private_key: Q\n";
        let after = run(&topology(TOPOLOGY), &SecretsFile::parse(before).unwrap());
        assert!(after.starts_with(before), "{after}");
        let secrets: Secrets = yaml_serde::from_str(&after).unwrap();
        assert!(secrets.links.contains_key("node-a|node-b"));
    }

    #[test]
    fn a_key_in_both_places_with_different_values_is_refused() {
        let yaml = TOPOLOGY.replace(
            "{name: node-a, node_id: \"10.62.0.1\"}",
            "{name: node-a, node_id: \"10.62.0.1\", mesh_private_key: WRITTEN}",
        );
        let topology = topology(&yaml);
        let file = SecretsFile::parse("nodes:\n  node-a:\n    mesh_private_key: STORED\n").unwrap();
        let resolved = resolve_secrets(&topology, &file);
        let err = file.additions(&topology, &resolved).unwrap_err();
        assert!(format!("{err:#}").contains("node-a"), "{err:#}");
    }

    #[test]
    fn a_key_in_both_places_with_the_same_value_is_fine() {
        let yaml = TOPOLOGY.replace(
            "{name: node-a, node_id: \"10.62.0.1\"}",
            "{name: node-a, node_id: \"10.62.0.1\", mesh_private_key: SAME}",
        );
        let topology = topology(&yaml);
        let file = SecretsFile::parse("nodes:\n  node-a:\n    mesh_private_key: SAME\n").unwrap();
        let resolved = resolve_secrets(&topology, &file);
        file.additions(&topology, &resolved).unwrap();
    }

    // Leftovers.

    #[test]
    fn an_entry_for_something_gone_is_reported_and_kept() {
        let raw = "nodes:\n  node-gone:\n    mesh_private_key: G\nlinks:\n  node-a|node-gone:\n    obfuscation: {jc: 1}\nroadwarriors:\n  gone:\n    private_key: R\n";
        let topology = topology(TOPOLOGY);
        let file = SecretsFile::parse(raw).unwrap();
        assert_eq!(
            file.orphans(&topology),
            [
                "nodes.node-gone",
                "links.node-a|node-gone",
                "roadwarriors.gone"
            ]
        );
        assert!(run(&topology, &file).contains("node-gone"));
    }

    #[test]
    fn a_stored_entry_for_a_link_now_plain_is_not_an_orphan() {
        let raw = "links:\n  node-a|node-c:\n    obfuscation: {jc: 1}\n";
        let file = SecretsFile::parse(raw).unwrap();
        assert!(file.orphans(&topology(TOPOLOGY)).is_empty());
    }
}
