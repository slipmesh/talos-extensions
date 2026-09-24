//! The one-shot move from `mesh.yaml` and hand-edited patch files to `slipmesh.yaml`. Used by the
//! `slipmesh-migrate` binary, and gone with it once no `mesh.yaml` is left to migrate.
//!
//! It carries today's behaviour over and fixes nothing on the way, so that `generate` on its
//! output reproduces the patch files it was given document for document - that is how a
//! migration is checked.

use crate::document;
use crate::existing::FileExistingState;
use crate::mesh_config::{self, MeshConfig};
use crate::minted::{self, generated_fields};
use crate::render::{self, ExistingState, link_key};
use crate::segments;
use crate::slipmesh_file::SlipmeshFile;
use anyhow::{Context, Result};
use std::path::Path;

pub struct Migration {
    pub slipmesh: String,
    /// Routes of secrets found nowhere on disk and minted by the migration - a new identity for a
    /// node or pool that already had one would show up here.
    pub minted: Vec<String>,
}

/// Builds `slipmesh.yaml` from `mesh_yaml` and the patch files in `patches_dir`, one per node in
/// it. The keys and obfuscation the patch files carry are written into the fields they belong to.
pub fn migrate(mesh_yaml: &str, patches_dir: &Path) -> Result<Migration> {
    let mesh: MeshConfig = yaml_serde::from_str(mesh_yaml).context("reading mesh.yaml")?;
    mesh_config::validate(&mesh).context("mesh.yaml failed validation")?;
    let parsed = yamlpath::Document::new(mesh_yaml).context("parsing mesh.yaml")?;

    let network = document::remove_key(mesh_yaml, "roadwarriors")?;
    let network = document::remove_key(&network, "nftables")?;
    let mut documents = vec![format!("slipmesh:\n  kind: network\n{network}")];

    for index in 0..mesh.roadwarriors.len() {
        let pool = block_at(&parsed, &yamlpath::route!["roadwarriors", index])?;
        documents.push(format!("slipmesh:\n  kind: roadwarriors\n{pool}"));
    }
    if mesh.nftables.is_some() {
        let ruleset = block_at(&parsed, &yamlpath::route!["nftables"])?;
        documents.push(format!("slipmesh:\n  kind: nftables\n{ruleset}"));
    }

    for node in &mesh.nodes {
        let path = patches_dir.join(format!("{}.yaml", node.name));
        let raw = match std::fs::read_to_string(&path) {
            Ok(raw) => raw,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(e) => return Err(e).with_context(|| format!("reading {}", path.display())),
        };
        let foreign = segments::foreign_segments(&raw)
            .with_context(|| format!("reading {}", path.display()))?;
        for segment in foreign {
            documents.push(format!(
                "slipmesh:\n  kind: patch\n  include: [{}]\n{segment}",
                node.name
            ));
        }
    }

    let slipmesh = documents
        .iter()
        .map(|d| format!("{}\n", d.trim_end()))
        .collect::<Vec<_>>()
        .join("---\n");
    let file =
        SlipmeshFile::parse(&slipmesh).context("the migrated slipmesh.yaml does not read back")?;
    let topology = file.topology()?;

    let patches = FileExistingState::new(&mesh, patches_dir)?;
    let resolved = render::resolve_secrets(&topology, &patches);
    let recorded = minted::minted(&topology, &resolved)?.record(&slipmesh, &file)?;

    Ok(Migration {
        slipmesh: recorded,
        minted: fresh(&topology, &patches, &resolved)?,
    })
}

/// Routes of what `resolved` had to generate because neither the topology nor the patch files
/// held it.
fn fresh(
    topology: &MeshConfig,
    patches: &FileExistingState,
    resolved: &render::ResolvedSecrets,
) -> Result<Vec<String>> {
    let mut out = Vec::new();
    for node in &topology.nodes {
        if node.mesh_private_key.is_none() && patches.mesh_private_key(&node.name).is_none() {
            out.push(format!("nodes[{}].mesh_private_key", node.name));
        }
    }
    for link in topology.mesh.links.iter().filter(|l| !l.plain) {
        let key = link_key(&link.pair);
        let layers = [
            &link.obfuscation,
            &topology.obfuscation,
            &patches
                .mesh_link_obfuscation(&link.pair)
                .unwrap_or_default(),
        ];
        if generated_fields(resolved.mesh_link_obfuscation.get(&key), &layers)?.is_some() {
            out.push(format!("mesh.links[{key}].obfuscation"));
        }
    }
    for pool in &topology.roadwarriors {
        if pool.private_key.is_none() && patches.roadwarrior_private_key(&pool.name).is_none() {
            out.push(format!("roadwarriors[{}].private_key", pool.name));
        }
        if pool.plain {
            continue;
        }
        let layers = [
            &pool.obfuscation,
            &topology.obfuscation,
            &patches
                .roadwarrior_obfuscation(&pool.name)
                .unwrap_or_default(),
        ];
        if generated_fields(resolved.roadwarrior_obfuscation.get(&pool.name), &layers)?.is_some() {
            out.push(format!("roadwarriors[{}].obfuscation", pool.name));
        }
    }
    Ok(out)
}

/// The block mapping at `route`, as text that stands on its own as a top-level document: its lines
/// moved left by the column it starts at, so relative indentation - a block scalar's included - is
/// what it was. Blank lines and comments it ends with at an outer indentation belong to what
/// follows it and are left out.
fn block_at(parsed: &yamlpath::Document, route: &yamlpath::Route) -> Result<String> {
    let feature = parsed
        .query_exact(route)
        .with_context(|| format!("locating {route:?} in mesh.yaml"))?
        .with_context(|| format!("{route:?} in mesh.yaml is empty"))?;
    let source = parsed.source();
    let (start, end) = feature.location.byte_span;
    let indent = start - source[..start].rfind('\n').map_or(0, |i| i + 1);

    let mut lines: Vec<&str> = source[start..end].lines().collect();
    while lines.len() > 1 {
        let last = lines[lines.len() - 1];
        let leading = last.len() - last.trim_start().len();
        if !last.trim().is_empty() && leading >= indent {
            break;
        }
        lines.pop();
    }

    let mut out = String::new();
    for (i, line) in lines.iter().enumerate() {
        let line = if i == 0 {
            line
        } else {
            let leading = line.len() - line.trim_start_matches(' ').len();
            &line[leading.min(indent)..]
        };
        out.push_str(line);
        out.push('\n');
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys;
    use crate::slipmesh_file::SlipmeshFile;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    fn temp_dir() -> PathBuf {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let id = COUNTER.fetch_add(1, Ordering::Relaxed);
        let dir =
            std::env::temp_dir().join(format!("slipmesh-migrate-test-{}-{id}", std::process::id()));
        // Start from an empty directory: the name is only unique per process id, which the OS
        // hands out again, and a leftover file from an earlier run would be read as this run's.
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    const RULESET: &str =
        "  ruleset: |\n    table inet talos_filter {\n        chain input { \n        }\n    }\n";

    fn mesh_yaml(pool_key: &str) -> String {
        let obfuscated_pool_key = keys::generate_private_key();
        format!(
            r#"cluster:
  bgp_as: 64512
  # a note inside the cluster block
  loopback_networks: {{ipv4: "10.62.0.0/16", ipv6: "fd00:62::/32"}}

nodes:
  - {{name: node-a, node_id: "10.62.0.1", endpoint: "192.0.2.10"}}
  - {{name: node-b, node_id: "10.62.0.2", endpoint: "192.0.2.11"}}

mesh:
  links:
    - pair: [node-a, node-b]
      port: 51820

roadwarriors:
  - name: plain
    node_hostnames: [node-a]
    address: "198.51.100.1/24"
    listen_port: 51900
    private_key: "{pool_key}"
    plain: true
    # clients get added by rw-add
    clients:
      - {{name: client-a, public_key: "AAA=", allowed_ips: ["198.51.100.2/32"]}}
  - name: obfuscated
    node_hostnames: [node-b]
    address: "203.0.113.1/24"
    listen_port: 51901
    private_key: "{obfuscated_pool_key}"
    obfuscation: {{jc: 4, jmin: 10, jmax: 50, s1: 1, s2: 2, h1: 5, h2: 6, h3: 7, h4: 8}}
    clients: []

# where traffic bypasses the mesh
bypass: []

nftables:
{RULESET}"#
        )
    }

    /// A patch file as `generate` wrote it before: a hand-written document, then the awg one.
    fn write_patch(dir: &Path, node: &str, foreign: &str, awg_yaml: &str) {
        let content: String = awg_yaml.lines().map(|l| format!("      {l}\n")).collect();
        let awg = format!(
            "apiVersion: v1alpha1\nkind: ExtensionServiceConfig\nname: awg\nconfigFiles:\n  - mountPath: /etc/talos-extensions/awg.yaml\n    content: |\n{content}"
        );
        let file = if foreign.is_empty() {
            format!("{awg}\n")
        } else {
            format!("{foreign}\n---\n{awg}\n")
        };
        std::fs::write(dir.join(format!("{node}.yaml")), file).unwrap();
    }

    struct Fixture {
        pool_key: String,
        node_a_key: String,
        node_b_key: String,
        migration: Migration,
    }

    fn fixture() -> Fixture {
        let dir = temp_dir();
        let pool_key = keys::generate_private_key();
        let node_a_key = keys::generate_private_key();
        let node_b_key = keys::generate_private_key();
        write_patch(
            &dir,
            "node-a",
            "# this node boots from a different disk\napiVersion: v1alpha1\nkind: UnattendedInstallConfig\ninstaller:\n    disk: /dev/vda",
            &format!(
                "interfaces:\n  - name: mesh-node-b\n    listen_port: 51820\n    private_key: \"{node_a_key}\"\n    obfuscation: {{jc: 9, jmin: 11, jmax: 51, s1: 3, s2: 4, h1: 15, h2: 16, h3: 17, h4: 18}}\n    peers: []\n"
            ),
        );
        write_patch(
            &dir,
            "node-b",
            "",
            &format!(
                "interfaces:\n  - name: mesh-node-a\n    listen_port: 51820\n    private_key: \"{node_b_key}\"\n    obfuscation: {{jc: 9, jmin: 11, jmax: 51, s1: 3, s2: 4, h1: 15, h2: 16, h3: 17, h4: 18}}\n    peers: []\n"
            ),
        );
        let migration = migrate(&mesh_yaml(&pool_key), &dir).unwrap();
        Fixture {
            pool_key,
            node_a_key,
            node_b_key,
            migration,
        }
    }

    fn documents(slipmesh: &str) -> Vec<String> {
        crate::document::split(slipmesh).unwrap()
    }

    fn topology(slipmesh: &str) -> MeshConfig {
        SlipmeshFile::parse(slipmesh).unwrap().topology().unwrap()
    }

    #[test]
    fn the_output_reads_as_slipmesh_yaml() {
        let migration = fixture().migration;
        let file = SlipmeshFile::parse(&migration.slipmesh).unwrap();
        assert_eq!(file.hosts(), ["node-a", "node-b"]);
    }

    #[test]
    fn the_network_document_is_the_topology_as_written_without_pools_or_ruleset() {
        let slipmesh = fixture().migration.slipmesh;
        let network = &documents(&slipmesh)[0];
        assert!(
            network.starts_with("slipmesh:\n  kind: network\n"),
            "{network}"
        );
        assert!(
            network.contains("  # a note inside the cluster block\n"),
            "{network}"
        );
        assert!(
            network.contains("\n\n# where traffic bypasses the mesh\nbypass: []"),
            "{network}"
        );
        assert!(!network.contains("roadwarriors"), "{network}");
        assert!(!network.contains("nftables"), "{network}");
    }

    #[test]
    fn each_pool_is_its_own_document_as_written() {
        let fixture = fixture();
        let slipmesh = &fixture.migration.slipmesh;
        let pools: Vec<_> = documents(slipmesh)
            .into_iter()
            .filter(|d| d.contains("kind: roadwarriors"))
            .collect();
        assert_eq!(pools.len(), 2, "{slipmesh}");
        assert!(pools[0].contains("\nname: plain\n"), "{}", pools[0]);
        assert!(
            pools[0].contains(&format!(
                "private_key: \"{}\"\nplain: true\n# clients get added by rw-add\nclients:\n  - {{name: client-a",
                fixture.pool_key
            )),
            "{}",
            pools[0]
        );
        assert!(!pools[1].contains("bypasses"), "{}", pools[1]);
    }

    #[test]
    fn the_ruleset_is_one_document_reaching_every_host_with_its_text_unchanged() {
        let slipmesh = fixture().migration.slipmesh;
        let file = SlipmeshFile::parse(&slipmesh).unwrap();
        let expected = "table inet talos_filter {\n    chain input { \n    }\n}\n";
        for host in ["node-a", "node-b"] {
            let ruleset = file.effective_for(host).unwrap().nftables.unwrap().ruleset;
            assert_eq!(ruleset, expected, "{host}");
        }
    }

    #[test]
    fn a_hand_written_patch_document_is_aimed_at_its_host_as_written() {
        let slipmesh = fixture().migration.slipmesh;
        let file = SlipmeshFile::parse(&slipmesh).unwrap();
        let patches = file.patches_for("node-a").unwrap();
        assert_eq!(patches.len(), 1);
        assert_eq!(
            patches[0].text,
            "# this node boots from a different disk\napiVersion: v1alpha1\nkind: UnattendedInstallConfig\ninstaller:\n    disk: /dev/vda"
        );
        assert!(file.patches_for("node-b").unwrap().is_empty());
    }

    #[test]
    fn keys_and_obfuscation_from_the_patch_files_are_written_into_their_fields() {
        let fixture = fixture();
        let topology = topology(&fixture.migration.slipmesh);
        assert_eq!(
            topology.nodes[0].mesh_private_key.as_deref(),
            Some(fixture.node_a_key.as_str())
        );
        assert_eq!(
            topology.nodes[1].mesh_private_key.as_deref(),
            Some(fixture.node_b_key.as_str())
        );
        assert_eq!(topology.mesh.links[0].obfuscation.jc, Some(9));
        assert!(
            fixture.migration.minted.is_empty(),
            "{:?}",
            fixture.migration.minted
        );
    }

    #[test]
    fn a_pool_with_its_obfuscation_written_out_gets_nothing_added() {
        let slipmesh = fixture().migration.slipmesh;
        let pool = documents(&slipmesh)
            .into_iter()
            .find(|d| d.contains("\nname: obfuscated\n"))
            .unwrap();
        assert_eq!(pool.matches("obfuscation").count(), 1, "{pool}");
        assert_eq!(topology(&slipmesh).roadwarriors[1].obfuscation.jc, Some(4));
    }

    #[test]
    fn a_secret_found_nowhere_is_reported_as_minted() {
        let dir = temp_dir();
        let migration = migrate(&mesh_yaml(&keys::generate_private_key()), &dir).unwrap();
        assert!(
            migration
                .minted
                .contains(&"nodes[node-a].mesh_private_key".to_owned()),
            "{:?}",
            migration.minted
        );
        assert!(
            topology(&migration.slipmesh).nodes[0]
                .mesh_private_key
                .is_some()
        );
    }
}
