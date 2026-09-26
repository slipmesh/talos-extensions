//! `generate`: reads `slipmesh.yaml`, writes whatever secrets the topology lacks into the fields of
//! `slipmesh.yaml` they belong to, computes every target node's `awg`/`router`/`nftables` config,
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
use std::io::Write;
use std::path::{Path, PathBuf};
use taloscfg::slipmesh_file::SlipmeshFile;
use taloscfg::{edit, mesh_config, patch_file, roadwarrior, secrets};
use yaml_rt::YamlDoc;

#[derive(Parser)]
#[command(
    name = "patches",
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
    /// Add a client to a roadwarriors pool in slipmesh.yaml.
    RwAdd {
        /// Which roadwarriors pool (its document's `name`, e.g. `plain`).
        #[arg(long = "if")]
        if_: String,
        /// Client name (must not already exist in the pool).
        #[arg(long)]
        name: String,
        /// Comma-separated CIDRs (v4/v6 mixed OK). A bare address gets /32 (v4) or /128 (v6).
        #[arg(long = "allowed-ips")]
        allowed_ips: String,
        /// Client already has its own keypair - only its public half is ever given to us.
        #[arg(long = "public-key")]
        public_key: Option<String>,
        /// Which of the pool's node_hostnames to put first as the live Endpoint (default: the
        /// first one in the pool's own order) - the rest still appear as commented #Endpoint =.
        #[arg(long)]
        endpoint: Option<String>,
        /// Print a ready-to-import client config to stdout.
        #[arg(long)]
        export: bool,
        /// Print the client config as an in-terminal QR code too.
        #[arg(long)]
        qr: bool,
        /// Swap dark/light QR modules. A dark-themed terminal renders "dark" modules as the
        /// foreground text color and "light" ones as the background - visually the opposite of
        /// standard (dark-on-light) QR polarity. Confirmed: the official WireGuard app's own
        /// scanner rejects that, while AmneziaWG's and a plain camera don't care either way.
        #[arg(long)]
        invert: bool,
        #[arg(long, default_value = "slipmesh.yaml")]
        config: PathBuf,
    },
    /// Remove a client from a roadwarriors pool in slipmesh.yaml.
    RwDel {
        #[arg(long = "if")]
        if_: String,
        #[arg(long)]
        name: String,
        #[arg(long, default_value = "slipmesh.yaml")]
        config: PathBuf,
    },
    /// Re-render an existing client's config/QR without changing slipmesh.yaml.
    RwInspect {
        #[arg(long = "if")]
        if_: String,
        #[arg(long)]
        name: String,
        /// This client's private key, if you happen to have it (never persisted by rw-add, so
        /// normally unknown) - fills in the config in full instead of a placeholder.
        #[arg(long = "private-key")]
        private_key: Option<String>,
        /// Which of the pool's node_hostnames to put first as the live Endpoint (default: the
        /// first one in the pool's own order) - the rest still appear as commented #Endpoint =.
        #[arg(long)]
        endpoint: Option<String>,
        #[arg(long)]
        export: bool,
        #[arg(long)]
        qr: bool,
        /// Swap dark/light QR modules. A dark-themed terminal renders "dark" modules as the
        /// foreground text color and "light" ones as the background - visually the opposite of
        /// standard (dark-on-light) QR polarity. Confirmed: the official WireGuard app's own
        /// scanner rejects that, while AmneziaWG's and a plain camera don't care either way.
        #[arg(long)]
        invert: bool,
        #[arg(long, default_value = "slipmesh.yaml")]
        config: PathBuf,
    },
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
        Command::RwAdd {
            if_,
            name,
            allowed_ips,
            public_key,
            endpoint,
            export,
            qr,
            invert,
            config,
        } => rw_add(
            &if_,
            &name,
            &allowed_ips,
            public_key.as_deref(),
            endpoint.as_deref(),
            export,
            qr,
            invert,
            &config,
        ),
        Command::RwDel { if_, name, config } => rw_del(&if_, &name, &config),
        Command::RwInspect {
            if_,
            name,
            private_key,
            endpoint,
            export,
            qr,
            invert,
            config,
        } => rw_inspect(
            &if_,
            &name,
            private_key.as_deref(),
            endpoint.as_deref(),
            export,
            qr,
            invert,
            &config,
        ),
    }
}

#[allow(clippy::too_many_arguments)]
fn rw_add(
    if_: &str,
    name: &str,
    allowed_ips: &str,
    public_key: Option<&str>,
    endpoint: Option<&str>,
    export: bool,
    qr: bool,
    invert: bool,
    config_path: &Path,
) -> Result<()> {
    let (_, mut yaml, file) = read_slipmesh(config_path)?;
    let topology = file.topology();
    let document = pool_document(&file, topology, if_)?;
    // Minted and written in along with the client: a pool key minted for the exported config has
    // to be the one `generate` puts on the wire, not a key that dies with this process.
    let (secrets, minted) = settle_secrets(config_path, &mut yaml, &file, false)?;
    yaml.commit_edits()?;

    let added = roadwarrior::add(
        topology,
        &secrets,
        if_,
        name,
        allowed_ips,
        public_key,
        endpoint,
        export,
        qr,
    )?;
    edit::add_client(&mut yaml, document, &added.client)?;
    write_edits(config_path, &yaml)?;
    report_minted(&minted, config_path);
    println!(
        "added {name:?} to roadwarriors pool {if_:?} in {}",
        config_path.display()
    );

    if let Some((_, text)) = added.config {
        if export {
            println!("\n{text}");
        }
        if qr {
            println!("\n{}", roadwarrior::render_qr(&text, invert)?);
        }
    }
    Ok(())
}

fn rw_del(if_: &str, name: &str, config_path: &Path) -> Result<()> {
    let (_, mut yaml, file) = read_slipmesh(config_path)?;
    let topology = file.topology();
    let document = pool_document(&file, topology, if_)?;

    let (index, client) = roadwarrior::find_client(topology, if_, name)?;
    edit::remove_client(&mut yaml, document, index)?;
    write_edits(config_path, &yaml)?;
    println!(
        "removed {name:?} (public_key {:?}) from roadwarriors pool {if_:?} in {}",
        client.public_key,
        config_path.display()
    );
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn rw_inspect(
    if_: &str,
    name: &str,
    private_key: Option<&str>,
    endpoint: Option<&str>,
    export: bool,
    qr: bool,
    invert: bool,
    config_path: &Path,
) -> Result<()> {
    let (_, _, file) = read_slipmesh(config_path)?;
    let topology = file.topology();
    let (secrets, minted) = secrets::resolve(topology);
    // Only this pool's: a config rendered with a key that is never written down would not connect.
    anyhow::ensure!(
        !minted.pools.iter().any(|pool| pool.name == if_),
        "{} lacks the secrets of pool {if_:?} - run `slipmesh-taloscfg generate` to mint and \
         write them",
        config_path.display()
    );

    let text = roadwarrior::inspect(topology, &secrets, if_, name, private_key, endpoint)?;

    // Inspecting is pointless with no output at all - default to --export if neither flag was
    // given, unlike rw-add (where registering a client without ever displaying it is legitimate).
    let export = export || !qr;
    if export {
        println!("{text}");
    }
    if qr {
        println!("\n{}", roadwarrior::render_qr(&text, invert)?);
    }
    Ok(())
}

/// `slipmesh.yaml` as its text, parsed for editing, and read.
fn read_slipmesh(config_path: &Path) -> Result<(String, YamlDoc, SlipmeshFile)> {
    let raw = std::fs::read_to_string(config_path)
        .with_context(|| format!("reading {}", config_path.display()))?;
    let yaml =
        YamlDoc::parse(&raw).with_context(|| format!("reading {}", config_path.display()))?;
    let file = SlipmeshFile::read(&raw, &yaml)
        .with_context(|| format!("reading {}", config_path.display()))?;
    Ok((raw, yaml, file))
}

/// The position of pool `name`'s document, erring with the pools there are.
fn pool_document(
    file: &SlipmeshFile,
    topology: &mesh_config::MeshConfig,
    name: &str,
) -> Result<usize> {
    roadwarrior::find_pool(topology, name)?;
    file.pool_document(name)
        .with_context(|| format!("pool {name:?} is in the topology but in no document"))
}

/// Writes `yaml` with its edits to `config_path` - once the result still reads as a valid
/// `slipmesh.yaml`, so a bad edit is refused instead of written.
fn write_edits(config_path: &Path, yaml: &YamlDoc) -> Result<()> {
    let updated = yaml.to_string();
    SlipmeshFile::parse(&updated)
        .context("the edited slipmesh.yaml does not read back - not written")?;
    write_replacing(config_path, &updated)
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
    let (_, mut yaml, file) = read_slipmesh(config_path)?;
    let targets = match node {
        Some(n) => {
            anyhow::ensure!(file.hosts().contains(&n), "unknown node {n:?}");
            vec![n]
        }
        None => file.hosts(),
    };

    let (resolved, minted) = settle_secrets(config_path, &mut yaml, &file, check || diff)?;
    // Every host is rendered and validated before anything is written, so a host that fails
    // leaves slipmesh.yaml and the patch files as they were rather than half of them new.
    let hosts = render_hosts(&file, &resolved, &targets, patches_dir)?;
    if !minted.is_empty() {
        write_edits(config_path, &yaml)?;
        report_minted(&minted, config_path);
    }

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

    std::fs::create_dir_all(patches_dir)
        .with_context(|| format!("creating {}", patches_dir.display()))?;
    for host in &hosts {
        if host.before == host.after {
            println!("{}: no changes", host.host);
            continue;
        }
        std::fs::write(&host.path, &host.after)
            .with_context(|| format!("writing {}", host.path.display()))?;
        println!("wrote {}", host.path.display());
    }
    Ok(())
}

/// The whole topology's secrets, with whatever they had to mint recorded in `yaml`, in the fields
/// it belongs to, and named in the second value - empty when nothing was minted. On a dry run,
/// needing to mint anything is an error instead: a value that is never written down would differ
/// on the next run.
fn settle_secrets(
    config_path: &Path,
    yaml: &mut YamlDoc,
    file: &SlipmeshFile,
    dry_run: bool,
) -> Result<(secrets::ResolvedSecrets, String)> {
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

fn report_minted(routes: &str, config_path: &Path) {
    if !routes.is_empty() {
        println!("minted {routes} into {}", config_path.display());
    }
}

/// Replaces `path` with `content` atomically, so an interrupted write cannot leave the file
/// half-written - a key lost that way is an identity rotated. Its permissions carry over, and a
/// symlink is followed rather than replaced.
fn write_replacing(path: &Path, content: &str) -> Result<()> {
    let target =
        std::fs::canonicalize(path).with_context(|| format!("resolving {}", path.display()))?;
    let mut file = atomic_write_file::AtomicWriteFile::open(&target)
        .with_context(|| format!("opening {} for writing", target.display()))?;
    file.write_all(content.as_bytes())
        .and_then(|()| file.commit())
        .with_context(|| format!("writing {}", target.display()))
}

/// Every target host's patch file, rendered and validated in memory.
fn render_hosts(
    file: &SlipmeshFile,
    resolved: &secrets::ResolvedSecrets,
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
            let before = match std::fs::read_to_string(&path) {
                Ok(raw) => raw,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => String::new(),
                Err(e) => return Err(e).with_context(|| format!("reading {}", path.display())),
            };
            Ok(HostFile {
                host: host.to_owned(),
                path,
                before,
                after,
            })
        })
        .collect()
}

/// A unified diff of one host's patch file, `None` when nothing would change.
fn diff_text(host: &str, before: &str, after: &str) -> Option<String> {
    if before == after {
        return None;
    }
    Some(
        similar::TextDiff::from_lines(before, after)
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
  loopback_networks: {ipv4: "10.62.0.0/16", ipv6: "fd00:62::/32"}
nodes:
  - {name: a, node_id: "10.62.0.1", endpoint: "192.0.2.10"}
  - {name: b, node_id: "10.62.0.2", endpoint: "192.0.2.11"}
  - {name: c, node_id: "10.62.0.3"}
  - {name: d, node_id: "10.62.0.4"}
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

        fn topology(&self) -> mesh_config::MeshConfig {
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
    fn two_dry_runs_render_the_same() {
        let paths = setup("");
        paths.generate(None, false, false).unwrap();
        let render = || {
            let (_, mut yaml, file) = read_slipmesh(&paths.config).unwrap();
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
            "---\nslipmesh:\n  kind: nftables\n  include: [d]\nruleset: |\n  table inet t { {{ bogus }} }\n",
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

    const POOLS: &str = r#"---
slipmesh:
  kind: roadwarriors
name: first
node_hostnames: [a]
address: "198.51.100.1/24"
listen_port: 51900
clients: []
---
slipmesh:
  kind: roadwarriors
name: second
node_hostnames: [b]
address: "203.0.113.1/24"
listen_port: 51901
clients:
  - {name: carol, public_key: "CCC=", allowed_ips: ["203.0.113.22/32"]}
"#;

    /// The bytes of pool `name`'s document in `raw`, from its `---` to the next one.
    fn pool_bounds(raw: &str, name: &str) -> std::ops::Range<usize> {
        let named = raw
            .find(&format!("kind: roadwarriors\nname: {name}\n"))
            .unwrap();
        let start = raw[..named].rfind("---").unwrap();
        let end = raw[named..]
            .find("\n---")
            .map_or(raw.len(), |i| named + i + 1);
        start..end
    }

    #[test]
    fn rw_add_edits_only_the_pools_own_document() {
        let paths = setup(POOLS);
        // Minted first, so that the only change the client makes is its own.
        paths.generate(None, false, false).unwrap();
        let before = paths.config();
        let bounds = pool_bounds(&before, "first");
        rw_add(
            "first",
            "dave",
            "198.51.100.99",
            Some("DDD="),
            None,
            false,
            false,
            false,
            &paths.config,
        )
        .unwrap();

        let after = paths.config();
        assert!(after.starts_with(&before[..bounds.start]), "{after}");
        assert!(after.ends_with(&before[bounds.end..]), "{after}");
        assert!(
            after[pool_bounds(&after, "first")].contains("name: dave"),
            "{after}"
        );
    }

    #[test]
    fn rw_del_edits_only_the_pools_own_document() {
        let paths = setup(POOLS);
        let before = paths.config();
        let bounds = pool_bounds(&before, "second");

        rw_del("second", "carol", &paths.config).unwrap();

        let after = paths.config();
        assert!(after.starts_with(&before[..bounds.start]), "{after}");
        assert!(!after.contains("carol"), "{after}");
    }

    #[test]
    fn rw_add_to_an_unknown_pool_names_the_pools_there_are() {
        let paths = setup(POOLS);
        let err = rw_add(
            "third",
            "dave",
            "198.51.100.99",
            Some("DDD="),
            None,
            false,
            false,
            false,
            &paths.config,
        )
        .unwrap_err();
        let err = format!("{err:#}");
        assert!(err.contains("first") && err.contains("second"), "{err}");
    }

    #[test]
    fn rw_add_writes_down_the_pool_key_its_exported_config_was_built_with() {
        // A pool key that went into the exported config but not into slipmesh.yaml would be minted
        // anew by the next `generate`, and the exported config would never connect.
        let paths = setup(POOLS);
        rw_add(
            "first",
            "dave",
            "198.51.100.99",
            None,
            None,
            true,
            false,
            false,
            &paths.config,
        )
        .unwrap();

        let topology = paths.topology();
        assert!(topology.roadwarriors[0].private_key.is_some());
        assert_eq!(topology.roadwarriors[0].clients[0].name, "dave");
        paths.generate(None, true, false).unwrap();
    }

    #[test]
    fn rw_inspect_needs_the_pool_key_to_be_written_down_already() {
        let paths = setup(POOLS);
        let inspect = || {
            rw_inspect(
                "second",
                "carol",
                None,
                None,
                true,
                false,
                false,
                &paths.config,
            )
        };
        let before = paths.config();
        let err = inspect().unwrap_err();
        assert!(format!("{err:#}").contains("generate"), "{err:#}");
        assert_eq!(paths.config(), before);

        paths.generate(None, false, false).unwrap();
        inspect().unwrap();
    }

    #[test]
    fn rw_inspect_needs_no_secret_but_its_pools() {
        let paths = setup(POOLS);
        paths.generate(None, false, false).unwrap();
        let unkeyed = paths.config().replacen(
            "nodes:\n",
            "nodes:\n  - {name: e, node_id: \"10.62.0.5\"}\n",
            1,
        );
        std::fs::write(&paths.config, &unkeyed).unwrap();
        rw_inspect(
            "second",
            "carol",
            None,
            None,
            true,
            false,
            false,
            &paths.config,
        )
        .unwrap();
    }
}
