//! `generate`: reads `slipmesh.yaml`, writes whatever secrets the topology lacks into the fields of
//! `slipmesh.yaml` they belong to, and the reference templates of the ones it does not set (see
//! `defaults`) as documents of their own, computes every target node's `awg`/`router` config,
//! validates each through the real daemon's own `validate()` (not a re-implementation - see the
//! lib-target refactor this crate depends on), and writes `patches/<node>.yaml`: the `patch`
//! documents aimed at that node, then the generated `ExtensionServiceConfig` documents. A patch
//! file is output only - nothing in it is read back. `--check`/`--diff` both stop short of
//! writing; `--diff` also prints what would change.
//!
//! `validate`/`diff`/`apply` are deliberately not separate subcommands: `generate`'s own
//! `--check`/`--diff` flags already cover them.

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use sliplib_config::slipmesh_file::SlipmeshFile;
use sliplib_yaml::MultiDoc;
use std::path::{Path, PathBuf};
use taloscfg::{defaults, edit, patch_file, secrets};

#[derive(Parser)]
#[command(
    name = env!("CARGO_BIN_NAME"),
    bin_name = env!("CARGO_BIN_NAME"),
    version,
    about = "Generates Talos machine-config patches for awg/router/nftables from slipmesh.yaml"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Compute and write patches/<node>.yaml for one or every node in slipmesh.yaml.
    Generate {
        /// Only this node's patch file, instead of every node's. Secrets are still minted for the
        /// whole topology: a link's two ends need the same ones.
        #[arg(long)]
        node: Option<String>,
        /// Validate only, don't write anything to disk.
        #[arg(long)]
        check: bool,
        /// Validate and print a unified diff of what would change, don't write.
        #[arg(long)]
        diff: bool,
        #[arg(long, default_value = "slipmesh.yaml")]
        config: PathBuf,
        #[arg(long, default_value = "patches")]
        patches_dir: PathBuf,
    },
    /// Print the `patch` document holding a service's reference template, to add to
    /// slipmesh.yaml.
    Template { service: defaults::Service },
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Generate {
            node,
            check,
            diff,
            config,
            patches_dir,
        } => generate(node.as_deref(), check, diff, &config, &patches_dir),
        Command::Template { service } => {
            print!("{}", defaults::document(service));
            Ok(())
        }
    }
}

/// `slipmesh.yaml`, parsed for editing, and read.
fn read_slipmesh(config_path: &Path) -> Result<(MultiDoc, SlipmeshFile)> {
    let yaml = MultiDoc::read(config_path)?;
    let file =
        SlipmeshFile::read(&yaml).with_context(|| format!("reading {}", config_path.display()))?;
    Ok((yaml, file))
}

/// Writes `updated` to `config_path` - once it still reads as a valid `slipmesh.yaml`, so a bad
/// edit is refused instead of written.
fn write_text(config_path: &Path, updated: &str) -> Result<()> {
    SlipmeshFile::parse(updated)
        .context("the edited slipmesh.yaml does not read back - not written")?;
    sliplib_yaml::replace_file(config_path, updated)
}

/// One host's patch file: what is on disk now, and what it would become.
struct HostFile {
    host: String,
    path: PathBuf,
    before: String,
    after: String,
}

fn generate(
    node: Option<&str>,
    check: bool,
    diff: bool,
    config_path: &Path,
    patches_dir: &Path,
) -> Result<()> {
    let (mut yaml, file) = read_slipmesh(config_path)?;
    if let Some(n) = node {
        anyhow::ensure!(file.hosts().contains(&n), "unknown node {n:?}");
    }

    let (resolved, minted) = settle_secrets(config_path, &mut yaml, &file, check || diff)?;
    let unset = edit::missing_defaults(file.topology());
    let unset_keys = unset
        .iter()
        .map(|(key, _)| *key)
        .collect::<Vec<_>>()
        .join(", ");
    anyhow::ensure!(
        !check || unset.is_empty(),
        "{} lacks {unset_keys} - run `slipmesh-taloscfg generate` to write their defaults",
        config_path.display()
    );
    edit::write_defaults(&mut yaml, &file, &unset)?;
    let added = defaults::missing(&file);
    let services: Vec<&str> = added.iter().map(|d| d.service).collect();
    anyhow::ensure!(
        !check || added.is_empty(),
        "{} lacks the default templates of {services:?} - run `slipmesh-taloscfg generate` to \
         write them",
        config_path.display()
    );
    let updated = defaults::append(&yaml.text()?, &added);
    let file = if added.is_empty() {
        file
    } else {
        SlipmeshFile::parse(&updated).context("slipmesh.yaml with the default templates")?
    };
    let targets = match node {
        Some(n) => vec![n],
        None => file.hosts(),
    };

    // Every host is rendered and validated before anything is written, so a host that fails
    // leaves slipmesh.yaml and the patch files as they were rather than half of them new.
    let hosts = render_hosts(&file, &resolved, &targets, patches_dir)?;
    if !diff && (!minted.is_empty() || !added.is_empty() || !unset.is_empty()) {
        write_text(config_path, &updated)?;
        report_minted(&minted, config_path);
    }
    report_defaults(config_path, diff, &services, &unset_keys);

    for host in &hosts {
        if diff {
            print_diff(&host.host, &host.before, &host.after);
        } else if check {
            println!("{}: ok", host.host);
        }
    }
    if check || diff {
        return Ok(());
    }

    for host in &hosts {
        if sliplib_yaml::write_if_changed(&host.path, &host.after)? {
            println!("wrote {}", host.path.display());
        } else {
            println!("{}: no changes", host.host);
        }
    }
    Ok(())
}

/// The whole topology's secrets, with whatever they had to mint recorded in `yaml`, in the fields
/// it belongs to, and named in the second value - empty when nothing was minted. On a dry run,
/// needing to mint anything is an error instead: a value that is never written down would differ
/// on the next run.
fn settle_secrets(
    config_path: &Path,
    yaml: &mut MultiDoc,
    file: &SlipmeshFile,
    dry_run: bool,
) -> Result<(sliplib_mesh::secrets::ResolvedSecrets, String)> {
    let (resolved, minted) = secrets::resolve(file.topology());
    let routes = minted.routes().join(", ");
    if minted.is_empty() {
        return Ok((resolved, routes));
    }
    anyhow::ensure!(
        !dry_run,
        "{} lacks {routes} - run `slipmesh-taloscfg generate` to mint and write them",
        config_path.display()
    );
    edit::record(yaml, file, &minted)?;
    Ok((resolved, routes))
}

/// The default templates and keys this run wrote into `slipmesh.yaml`, or with `diff` would write.
fn report_defaults(config_path: &Path, diff: bool, services: &[&str], unset_keys: &str) {
    let path = config_path.display();
    if !services.is_empty() {
        if diff {
            println!("{path}: the default templates of {services:?} would be added");
        } else {
            println!("added the default templates of {services:?} to {path}");
        }
    }
    if !unset_keys.is_empty() {
        if diff {
            println!("{path}: {unset_keys} would be written with their defaults");
        } else {
            println!("wrote the defaults of {unset_keys} into {path}");
        }
    }
}

fn report_minted(routes: &str, config_path: &Path) {
    if !routes.is_empty() {
        println!("minted {routes} into {}", config_path.display());
    }
}

/// Every target host's patch file, rendered and validated in memory.
fn render_hosts(
    file: &SlipmeshFile,
    resolved: &sliplib_mesh::secrets::ResolvedSecrets,
    targets: &[&str],
    patches_dir: &Path,
) -> Result<Vec<HostFile>> {
    targets
        .iter()
        .map(|&host| {
            let after = patch_file::render(file, resolved, host)?;
            let path = patches_dir.join(format!("{host}.yaml"));
            // A missing file is the from-scratch case; anything else must not read as "there was
            // nothing here", or the diff would show a whole file where one line changed.
            let before = sliplib_yaml::read_or_empty(&path)?;
            Ok(HostFile {
                host: host.to_owned(),
                path,
                before,
                after,
            })
        })
        .collect()
}

/// A unified diff of one host's patch file with its secrets masked, `None` when nothing would
/// change. A file whose only change is a secret still has a diff: the masked line says it changed.
fn diff_text(host: &str, before: &str, after: &str) -> Option<String> {
    if before == after {
        return None;
    }
    let (before, after) = taloscfg::redact::mask_pair(before, after);
    Some(
        similar::TextDiff::from_lines(&before, &after)
            .unified_diff()
            .header(&format!("{host} (current)"), &format!("{host} (generated)"))
            .to_string(),
    )
}

/// Prints `diff_text` in colour where the output takes it - `anstream` leaves the colour out when
/// stdout is not a terminal or `NO_COLOR` is set.
fn print_diff(host: &str, before: &str, after: &str) {
    let Some(text) = diff_text(host, before, after) else {
        println!("{host}: no changes");
        return;
    };
    for line in text.lines() {
        let style = match line.as_bytes().first() {
            Some(b'-') => anstyle::AnsiColor::Red.on_default(),
            Some(b'+') => anstyle::AnsiColor::Green.on_default(),
            Some(b'@') => anstyle::AnsiColor::Cyan.on_default(),
            _ => anstyle::Style::new(),
        };
        anstream::println!("{style}{line}{style:#}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    #[test]
    fn a_diff_shows_that_a_key_changed_and_never_a_key() {
        let (old, new, kept) = (
            "b2xkLWtleS1vbGQta2V5LW9sZC1rZXktb2xkLWtleQ==",
            "bmV3LWtleS1uZXcta2V5LW5ldy1rZXktbmV3LWtleQ==",
            "a2VwdC1rZXkta2VwdC1rZXkta2VwdC1rZXkta2VwdA==",
        );
        let before =
            format!("- name: mesh-b\n  private_key: {old}\n- name: rw-a\n  private_key: {kept}\n");
        let after =
            format!("- name: mesh-b\n  private_key: {new}\n- name: rw-a\n  private_key: {kept}\n");
        let text = diff_text("node-a", &before, &after).unwrap();
        for key in [old, new, kept] {
            assert!(!text.contains(key), "{text}");
        }
        assert!(text.contains("-  private_key: <redacted, old>"), "{text}");
        assert!(text.contains("+  private_key: <redacted, new>"), "{text}");
        assert!(text.contains("   private_key: <redacted>"), "{text}");
    }

    #[test]
    fn an_unchanged_file_has_no_diff() {
        assert_eq!(
            diff_text(
                "node-a", "same
", "same
"
            ),
            None
        );
    }

    fn temp_dir() -> PathBuf {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let id = COUNTER.fetch_add(1, Ordering::Relaxed);
        let dir =
            std::env::temp_dir().join(format!("patches-main-test-{}-{id}", std::process::id()));
        // Start from an empty directory: the name is only unique per process id, which the OS
        // hands out again, and a leftover file from an earlier run would be read as this run's.
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    const SLIPMESH: &str = r#"slipmesh:
  kind: network
cluster:
  bgp_as: 64512
  loopback_networks: {ipv4: "198.51.100.0/25", ipv6: "3fff::/32"}
nodes:
  - {name: a, node_id: "198.51.100.1", endpoint: "192.0.2.10"}
  - {name: b, node_id: "198.51.100.2", endpoint: "192.0.2.11"}
  - {name: c, node_id: "198.51.100.3"}
  - {name: d, node_id: "198.51.100.4"}
mesh:
  links:
    - {pair: [a, b], port: 51820}
---
slipmesh:
  kind: patch
  include: [a]
apiVersion: v1alpha1
kind: UnattendedInstallConfig
installer:
    disk: /dev/vda
"#;

    struct Paths {
        config: PathBuf,
        patches: PathBuf,
    }

    impl Paths {
        fn generate(&self, node: Option<&str>, check: bool, diff: bool) -> Result<()> {
            generate(node, check, diff, &self.config, &self.patches)
        }

        fn patch(&self, host: &str) -> Option<String> {
            std::fs::read_to_string(self.patches.join(format!("{host}.yaml"))).ok()
        }

        fn config(&self) -> String {
            std::fs::read_to_string(&self.config).unwrap()
        }

        fn topology(&self) -> sliplib_config::mesh_config::MeshConfig {
            SlipmeshFile::parse(&self.config()).unwrap().into_topology()
        }

        /// Every file a run could have written, with what it holds.
        fn snapshot(&self) -> Vec<(PathBuf, Option<String>)> {
            let mut paths = vec![self.config.clone()];
            paths.extend(["a", "b", "c", "d"].map(|h| self.patches.join(format!("{h}.yaml"))));
            paths
                .into_iter()
                .map(|p| {
                    let content = std::fs::read_to_string(&p).ok();
                    (p, content)
                })
                .collect()
        }
    }

    fn setup(extra_documents: &str) -> Paths {
        let dir = temp_dir();
        let config = dir.join("slipmesh.yaml");
        std::fs::write(&config, format!("{SLIPMESH}{extra_documents}")).unwrap();
        Paths {
            config,
            patches: dir.join("patches"),
        }
    }

    #[cfg(unix)]
    #[test]
    fn an_edit_through_a_symlink_edits_its_target() {
        let paths = setup("");
        let target = paths.config.with_file_name("target.yaml");
        std::fs::rename(&paths.config, &target).unwrap();
        std::os::unix::fs::symlink(&target, &paths.config).unwrap();
        paths.generate(None, false, false).unwrap();
        assert!(
            std::fs::symlink_metadata(&paths.config)
                .unwrap()
                .file_type()
                .is_symlink()
        );
        assert!(
            std::fs::read_to_string(&target)
                .unwrap()
                .contains("mesh_private_key")
        );
    }

    #[test]
    fn generate_writes_what_it_minted_into_slipmesh_yaml() {
        let paths = setup("");
        paths.generate(None, false, false).unwrap();
        let topology = paths.topology();
        for node in &topology.nodes {
            assert!(node.mesh_private_key.is_some(), "{}", node.name);
        }
        assert!(topology.mesh.links[0].obfuscation.h1.is_some());
    }

    #[test]
    fn every_written_file_opens_with_the_header() {
        let paths = setup("");
        paths.generate(None, false, false).unwrap();
        for host in ["a", "b", "c", "d"] {
            assert!(
                paths.patch(host).unwrap().starts_with(patch_file::HEADER),
                "{host}"
            );
        }
    }

    #[test]
    fn a_dry_run_that_would_mint_a_secret_fails_and_writes_nothing() {
        for (check, diff) in [(true, false), (false, true)] {
            let paths = setup("");
            let before = paths.config();
            let err = paths.generate(None, check, diff).unwrap_err();
            assert!(format!("{err:#}").contains("generate"), "{err:#}");
            assert_eq!(paths.config(), before);
            assert!(!paths.patches.exists());
        }
    }

    #[test]
    fn a_check_after_a_full_run_passes_and_writes_nothing() {
        let paths = setup("");
        paths.generate(None, false, false).unwrap();
        let before = paths.snapshot();
        paths.generate(None, true, false).unwrap();
        paths.generate(None, false, true).unwrap();
        assert_eq!(paths.snapshot(), before);
    }

    #[test]
    fn generate_writes_the_default_templates_into_slipmesh_yaml() {
        let paths = setup("");
        paths.generate(None, false, false).unwrap();
        let file = SlipmeshFile::parse(&paths.config()).unwrap();
        assert!(defaults::missing(&file).is_empty());
        for host in ["a", "b", "c", "d"] {
            let patch = paths.patch(host).unwrap();
            for default in &defaults::DEFAULT_FILES {
                assert!(patch.contains(default.mount_path), "{host}: {patch}");
            }
        }
    }

    /// The topology with its secrets written down and the default templates not.
    fn setup_without_defaults() -> Paths {
        let paths = setup("");
        paths.generate(None, false, false).unwrap();
        let config = paths.config();
        let first_default = config
            .find("---\nslipmesh:\n  kind: patch\napiVersion: v1alpha1\nkind: ExtensionServiceConfig\nname: router\n")
            .expect(&config);
        std::fs::write(&paths.config, &config[..first_default]).unwrap();
        std::fs::remove_dir_all(&paths.patches).unwrap();
        paths
    }

    #[test]
    fn a_check_without_the_default_templates_fails_and_writes_nothing() {
        let paths = setup_without_defaults();
        let before = paths.snapshot();
        let err = paths.generate(None, true, false).unwrap_err();
        assert!(format!("{err:#}").contains("generate"), "{err:#}");
        assert_eq!(paths.snapshot(), before);
    }

    #[test]
    fn a_diff_without_the_default_templates_shows_them_and_writes_nothing() {
        let paths = setup_without_defaults();
        let before = paths.snapshot();
        paths.generate(None, false, true).unwrap();
        assert_eq!(paths.snapshot(), before);
    }

    /// A full run with the prefix and protocol keys taken back out of `slipmesh.yaml`.
    fn setup_without_default_keys() -> Paths {
        let paths = setup("");
        paths.generate(None, false, false).unwrap();
        let mut yaml = MultiDoc::parse(&paths.config()).unwrap();
        let cluster = yaml.document_mut(0).unwrap()["cluster"]
            .as_mapping_mut()
            .unwrap();
        cluster.shift_remove("interface_prefix");
        cluster.shift_remove("route_proto_id");
        std::fs::write(&paths.config, yaml.text().unwrap()).unwrap();
        paths
    }

    #[test]
    fn a_check_without_the_prefix_and_protocol_keys_fails_naming_them_and_writes_nothing() {
        let paths = setup_without_default_keys();
        let before = paths.snapshot();
        let err = format!("{:#}", paths.generate(None, true, false).unwrap_err());
        assert!(err.contains("cluster.interface_prefix.mesh"), "{err}");
        assert!(err.contains("cluster.route_proto_id.egress"), "{err}");
        assert_eq!(paths.snapshot(), before);
    }

    #[test]
    fn a_diff_without_the_prefix_and_protocol_keys_writes_nothing() {
        let paths = setup_without_default_keys();
        let before = paths.snapshot();
        paths.generate(None, false, true).unwrap();
        assert_eq!(paths.snapshot(), before);
    }

    #[test]
    fn a_run_that_mints_nothing_still_writes_the_keys_it_lacks() {
        let paths = setup_without_default_keys();
        paths.generate(None, false, false).unwrap();
        let cluster = paths.topology().cluster;
        assert_eq!(cluster.interface_prefix.mesh.as_deref(), Some("mesh-"));
        assert_eq!(cluster.route_proto_id.egress, Some(152));
    }

    #[test]
    fn a_run_that_mints_nothing_still_writes_the_templates_it_lacks() {
        let paths = setup_without_defaults();
        paths.generate(None, false, false).unwrap();
        let file = SlipmeshFile::parse(&paths.config()).unwrap();
        assert!(defaults::missing(&file).is_empty());
    }

    #[test]
    fn two_dry_runs_render_the_same() {
        let paths = setup("");
        paths.generate(None, false, false).unwrap();
        let render = || {
            let (mut yaml, file) = read_slipmesh(&paths.config).unwrap();
            let (resolved, _) = settle_secrets(&paths.config, &mut yaml, &file, true).unwrap();
            render_hosts(&file, &resolved, &["a", "b", "c", "d"], &paths.patches)
                .unwrap()
                .into_iter()
                .map(|h| h.after)
                .collect::<Vec<_>>()
        };
        assert_eq!(render(), render());
    }

    #[test]
    fn a_second_run_changes_nothing() {
        let paths = setup("");
        paths.generate(None, false, false).unwrap();
        let first = paths.snapshot();
        paths.generate(None, false, false).unwrap();
        assert_eq!(paths.snapshot(), first);
    }

    #[test]
    fn regenerating_one_host_from_scratch_twice_changes_nothing() {
        // Secrets are settled for the whole topology whichever host is rendered, so rendering a
        // host before its peers mints their keys once rather than on every run.
        let paths = setup("");
        paths.generate(Some("a"), false, false).unwrap();
        let first = paths.snapshot();
        paths.generate(Some("a"), false, false).unwrap();
        assert_eq!(paths.snapshot(), first);
        assert!(paths.patch("b").is_none());
    }

    #[test]
    fn a_host_that_fails_validation_leaves_every_file_unwritten() {
        let paths = setup(
            "---\nslipmesh:\n  kind: patch\n  include: [d]\napiVersion: v1alpha1\nkind: ExtensionServiceConfig\nname: nftables\nconfigFiles:\n  - mountPath: /etc/talos-extensions/nftables.conf.j2\n    content: |\n      table inet t { {{ bogus }} }\n",
        );
        let before = paths.config();
        let err = paths.generate(None, false, false).unwrap_err();
        assert!(format!("{err:#}").contains("\"d\""), "{err:#}");
        for host in ["a", "b", "c", "d"] {
            assert!(paths.patch(host).is_none(), "{host} was written");
        }
        assert_eq!(paths.config(), before, "the minted secrets were written");
    }

    #[test]
    fn generate_rejects_an_unknown_node() {
        let paths = setup("");
        assert!(paths.generate(Some("nonexistent"), false, false).is_err());
    }
}
