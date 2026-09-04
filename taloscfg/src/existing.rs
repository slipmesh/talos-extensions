//! Reads back a previous run's owned `awg` segment from `patches/<node>.yaml` to feed
//! `render::ExistingState` - the middle idempotency tier ("already in the existing patch") for
//! mesh private keys/obfuscation and roadwarriors private keys/obfuscation. `router`/`nftables`
//! segments are never read back: both are fully deterministic from `mesh.yaml` alone, no secrets,
//! no idempotency needed.

use crate::mesh_config::MeshConfig;
use crate::render::ExistingState;
use crate::segments;
use anyhow::{Context, Result};
use common::Obfuscation;
use serde::Deserialize;
use std::collections::HashMap;
use std::path::Path;

#[derive(Deserialize)]
struct ConfigFileEntry {
    content: String,
}

#[derive(Deserialize)]
struct ExtensionServiceConfigDoc {
    #[serde(rename = "configFiles", default)]
    config_files: Vec<ConfigFileEntry>,
}

pub struct FileExistingState<'a> {
    pub mesh: &'a MeshConfig,
    awg_by_node: HashMap<String, awg::config::AwgConfig>,
}

impl<'a> FileExistingState<'a> {
    /// Reads every patch file in `patches_dir` once, up front.
    ///
    /// Eagerly, and fallibly, on purpose: the values read back here are secrets - a node's mesh
    /// private key, a pool's roadwarrior key. A file that cannot be read as one is
    /// indistinguishable, to every caller of the trait below, from a node that has no key yet, and
    /// the answer to that is to mint a fresh one. Silently rotating a live node's identity because
    /// its patch file had a stray character is not a failure mode worth keeping, so the parse
    /// happens here, where it can still say what went wrong.
    pub fn new(mesh: &'a MeshConfig, patches_dir: &Path) -> Result<Self> {
        let mut awg_by_node = HashMap::new();

        let entries = match std::fs::read_dir(patches_dir) {
            Ok(entries) => entries,
            // No directory yet is the from-scratch case, not an error.
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Ok(Self { mesh, awg_by_node });
            }
            Err(e) => return Err(e).with_context(|| format!("reading {patches_dir:?}")),
        };

        for entry in entries {
            let path = entry
                .with_context(|| format!("reading {patches_dir:?}"))?
                .path();
            if path.extension().and_then(|e| e.to_str()) != Some("yaml") {
                continue;
            }
            let Some(node) = path.file_stem().and_then(|s| s.to_str()) else {
                continue;
            };
            let raw =
                std::fs::read_to_string(&path).with_context(|| format!("reading {path:?}"))?;
            let Some(segment) = segments::owned_segment(&raw, "awg")
                .with_context(|| format!("reading {path:?}"))?
            else {
                continue;
            };
            let doc: ExtensionServiceConfigDoc = serde_yaml::from_str(&segment)
                .with_context(|| format!("parsing the awg document in {path:?}"))?;
            let Some(file) = doc.config_files.first() else {
                continue;
            };
            let cfg: awg::config::AwgConfig = serde_yaml::from_str(&file.content)
                .with_context(|| format!("parsing the awg config inside {path:?}"))?;
            awg_by_node.insert(node.to_owned(), cfg);
        }

        Ok(Self { mesh, awg_by_node })
    }

    fn awg(&self, node_name: &str) -> Option<&awg::config::AwgConfig> {
        self.awg_by_node.get(node_name)
    }
}

impl ExistingState for FileExistingState<'_> {
    fn mesh_private_key(&self, node_name: &str) -> Option<String> {
        self.awg(node_name)?
            .interfaces
            .iter()
            .find(|i| i.name.starts_with("mesh-"))
            .map(|i| i.private_key.clone())
    }

    fn mesh_link_obfuscation(&self, pair: &[String; 2]) -> Option<Obfuscation> {
        for (this, other) in [(&pair[0], &pair[1]), (&pair[1], &pair[0])] {
            let name = format!("mesh-{other}");
            let Some(cfg) = self.awg(this) else {
                continue;
            };
            if let Some(iface) = cfg.interfaces.iter().find(|i| i.name == name) {
                return Some(iface.obfuscation.clone());
            }
        }
        None
    }

    fn roadwarrior_private_key(&self, pool_name: &str) -> Option<String> {
        let pool = self
            .mesh
            .roadwarriors
            .iter()
            .find(|p| p.name == pool_name)?;
        pool.node_hostnames.iter().find_map(|host| {
            self.awg(host)?
                .interfaces
                .iter()
                .find(|i| i.name == format!("rw-{}", pool.name))
                .map(|i| i.private_key.clone())
        })
    }

    fn roadwarrior_obfuscation(&self, pool_name: &str) -> Option<Obfuscation> {
        let pool = self
            .mesh
            .roadwarriors
            .iter()
            .find(|p| p.name == pool_name)?;
        pool.node_hostnames.iter().find_map(|host| {
            self.awg(host)?
                .interfaces
                .iter()
                .find(|i| i.name == format!("rw-{}", pool.name))
                .map(|i| i.obfuscation.clone())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    fn temp_dir() -> PathBuf {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let id = COUNTER.fetch_add(1, Ordering::Relaxed);
        let dir =
            std::env::temp_dir().join(format!("patches-existing-test-{}-{id}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn write_awg_patch(dir: &Path, node: &str, awg_yaml: &str) {
        let doc = format!(
            "apiVersion: v1alpha1\nkind: ExtensionServiceConfig\nname: awg\nconfigFiles:\n  - mountPath: /etc/talos-extensions/awg.yaml\n    content: |\n{}\n",
            awg_yaml
                .lines()
                .map(|l| format!("      {l}"))
                .collect::<Vec<_>>()
                .join("\n")
        );
        std::fs::write(dir.join(format!("{node}.yaml")), doc).unwrap();
    }

    fn mesh_with_link() -> MeshConfig {
        serde_yaml::from_str(
            r#"
cluster:
  bgp_as: 64512
  loopback_networks: {ipv4: "10.62.0.0/16", ipv6: "fd00:62::/32"}
nodes:
  - {name: a, node_id: "10.62.0.1"}
  - {name: b, node_id: "10.62.0.2"}
mesh:
  links:
    - {pair: [a, b], port: 51820}
roadwarriors:
  - name: eu
    node_hostnames: [a]
    iface: rw-eu
    address: "10.99.0.1/24"
    listen_port: 51900
    clients: []
"#,
        )
        .unwrap()
    }

    #[test]
    fn mesh_private_key_reads_back_from_a_mesh_interface() {
        let dir = temp_dir();
        write_awg_patch(
            &dir,
            "a",
            "interfaces:\n  - name: mesh-b\n    listen_port: 51820\n    private_key: \"existing-a-key\"\n    peers: []\n",
        );
        let mesh = mesh_with_link();
        let state = FileExistingState::new(&mesh, &dir).unwrap();
        assert_eq!(
            state.mesh_private_key("a"),
            Some("existing-a-key".to_string())
        );
    }

    #[test]
    fn mesh_private_key_is_none_when_no_file_exists() {
        let dir = temp_dir();
        let mesh = mesh_with_link();
        let state = FileExistingState::new(&mesh, &dir).unwrap();
        assert_eq!(state.mesh_private_key("a"), None);
    }

    #[test]
    fn mesh_link_obfuscation_reads_back_from_either_end() {
        let dir = temp_dir();
        write_awg_patch(
            &dir,
            "b",
            "interfaces:\n  - name: mesh-a\n    listen_port: 51820\n    private_key: \"existing-b-key\"\n    obfuscation: {h1: 111}\n    peers: []\n",
        );
        let mesh = mesh_with_link();
        let state = FileExistingState::new(&mesh, &dir).unwrap();
        let pair = ["a".to_string(), "b".to_string()];
        assert_eq!(state.mesh_link_obfuscation(&pair).unwrap().h1, Some(111));
    }

    #[test]
    fn roadwarrior_private_key_reads_back_from_a_node_hostname() {
        let dir = temp_dir();
        write_awg_patch(
            &dir,
            "a",
            "interfaces:\n  - name: rw-eu\n    listen_port: 51900\n    private_key: \"existing-rw-key\"\n    peers: []\n",
        );
        let mesh = mesh_with_link();
        let state = FileExistingState::new(&mesh, &dir).unwrap();
        assert_eq!(
            state.roadwarrior_private_key("eu"),
            Some("existing-rw-key".to_string())
        );
    }

    #[test]
    fn roadwarrior_obfuscation_is_none_for_an_unknown_pool() {
        let dir = temp_dir();
        let mesh = mesh_with_link();
        let state = FileExistingState::new(&mesh, &dir).unwrap();
        assert_eq!(state.roadwarrior_obfuscation("nonexistent"), None);
    }
}
