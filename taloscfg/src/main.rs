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
use std::io::IsTerminal;
use std::path::{Path, PathBuf};
use taloscfg::slipmesh_file::SlipmeshFile;
use taloscfg::{document, mesh_config, minted, render, roadwarrior, segments};

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
    let (raw, file) = read_slipmesh(config_path)?;
    // Minted and written in along with the client: a pool key minted for the exported config has
    // to be the one `generate` puts on the wire, not a key that dies with this process.
    let (secrets, raw) = settle_secrets(config_path, &raw, &file, false)?;
    let file = SlipmeshFile::parse(&raw)?;
    let topology = file.topology()?;
    let span = pool_document(&file, &topology, if_)?;

    let (updated_pool, client_config) = roadwarrior::add(
        &topology,
        &raw[span.clone()],
        &secrets,
        if_,
        name,
        allowed_ips,
        public_key,
        endpoint,
        export,
        qr,
    )?;
    write_edited(config_path, &raw, span, &updated_pool)?;
    println!(
        "added {name:?} to roadwarriors pool {if_:?} in {}",
        config_path.display()
    );

    if let Some((_, text)) = client_config {
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
    let (raw, file) = read_slipmesh(config_path)?;
    let topology = file.topology()?;
    let span = pool_document(&file, &topology, if_)?;

    let (updated_pool, public_key) = roadwarrior::del(&topology, &raw[span.clone()], if_, name)?;
    write_edited(config_path, &raw, span, &updated_pool)?;
    println!(
        "removed {name:?} (public_key {public_key:?}) from roadwarriors pool {if_:?} in {}",
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
    let (raw, file) = read_slipmesh(config_path)?;
    let topology = file.topology()?;
    let (secrets, _) = settle_secrets(config_path, &raw, &file, true)?;

    let text = roadwarrior::inspect(&topology, &secrets, if_, name, private_key, endpoint)?;

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

fn read_slipmesh(config_path: &Path) -> Result<(String, SlipmeshFile)> {
    let raw = std::fs::read_to_string(config_path)
        .with_context(|| format!("reading {}", config_path.display()))?;
    let file =
        SlipmeshFile::parse(&raw).with_context(|| format!("reading {}", config_path.display()))?;
    Ok((raw, file))
}

/// The bytes of pool `name`'s document, erring with the pools there are.
fn pool_document(
    file: &SlipmeshFile,
    topology: &mesh_config::MeshConfig,
    name: &str,
) -> Result<std::ops::Range<usize>> {
    roadwarrior::find_pool(topology, name)?;
    file.pool_span(name)
        .with_context(|| format!("pool {name:?} is in the topology but in no document"))
}

/// Writes `raw` with the document at `span` replaced by `edited` - once the result still reads as
/// a valid `slipmesh.yaml`, so a bad edit is refused instead of written.
fn write_edited(
    config_path: &Path,
    raw: &str,
    span: std::ops::Range<usize>,
    edited: &str,
) -> Result<()> {
    let updated = document::splice(raw, span, edited);
    SlipmeshFile::parse(&updated)
        .context("the edited slipmesh.yaml does not read back - not written")?;
    write_replacing(config_path, &updated)
}

#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct ExtensionServiceConfig<'a> {
    api_version: &'a str,
    kind: &'a str,
    name: &'a str,
    config_files: [ConfigFile<'a>; 1],
}

#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct ConfigFile<'a> {
    mount_path: &'a str,
    content: &'a str,
}

/// Renders one owned `ExtensionServiceConfig` document: `name`/`mountPath` fixed by convention,
/// `inner_yaml` - the daemon's own already-serialized config - as the file's content.
fn render_extension_service_document(
    name: &str,
    mount_path: &str,
    inner_yaml: &str,
) -> Result<String> {
    let document = ExtensionServiceConfig {
        api_version: "v1alpha1",
        kind: "ExtensionServiceConfig",
        name,
        config_files: [ConfigFile {
            mount_path,
            content: inner_yaml,
        }],
    };
    yaml_serde::to_string(&document).context("serializing an ExtensionServiceConfig document")
}

/// What opens every patch file this tool writes.
const HEADER: &str =
    "# Generated by slipmesh-taloscfg from slipmesh.yaml - edit that file, not this one.\n";

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
    let (raw, file) = read_slipmesh(config_path)?;
    let targets = match node {
        Some(n) => {
            anyhow::ensure!(file.hosts().contains(&n), "unknown node {n:?}");
            vec![n]
        }
        None => file.hosts(),
    };

    let (resolved, recorded) = settle_secrets(config_path, &raw, &file, check || diff)?;
    if recorded != raw {
        write_replacing(config_path, &recorded)?;
    }
    // Every host is rendered and validated before any is written, so a host that fails leaves
    // the patch files as a set rather than half of them new.
    let hosts = render_hosts(&file, &resolved, &targets, patches_dir)?;

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

/// The whole topology's secrets, and `raw` with whatever they had to mint written into the fields
/// it belongs to. On a dry run, needing to mint anything is an error instead: a value that is never
/// written down would differ on the next run.
fn settle_secrets(
    config_path: &Path,
    raw: &str,
    file: &SlipmeshFile,
    dry_run: bool,
) -> Result<(render::ResolvedSecrets, String)> {
    let topology = file.topology()?;
    let resolved = render::resolve_secrets(&topology, &render::NothingStored);
    let minted = minted::minted(&topology, &resolved)?;
    if minted.is_empty() {
        return Ok((resolved, raw.to_owned()));
    }
    let routes = minted.routes().join(", ");
    anyhow::ensure!(
        !dry_run,
        "{} lacks {routes} - run `slipmesh-taloscfg generate` to mint and write them",
        config_path.display()
    );

    let recorded = minted.record(raw, file)?;
    SlipmeshFile::parse(&recorded)
        .context("slipmesh.yaml with the minted values written in does not read back")?;
    println!("minted {routes} into {}", config_path.display());
    Ok((resolved, recorded))
}

/// Writes `content` to a sibling file and renames it over `path`, so an interrupted write cannot
/// leave the file half-written - a key lost that way is an identity rotated.
fn write_replacing(path: &Path, content: &str) -> Result<()> {
    let mut temporary = path.as_os_str().to_owned();
    temporary.push(".tmp");
    let temporary = PathBuf::from(temporary);
    std::fs::write(&temporary, content)
        .with_context(|| format!("writing {}", temporary.display()))?;
    std::fs::rename(&temporary, path).with_context(|| format!("replacing {}", path.display()))
}

/// Every target host's patch file, rendered and validated in memory.
fn render_hosts(
    file: &SlipmeshFile,
    resolved: &render::ResolvedSecrets,
    targets: &[&str],
    patches_dir: &Path,
) -> Result<Vec<HostFile>> {
    targets
        .iter()
        .map(|&host| {
            let model = file.effective_for(host)?;
            let awg_cfg = render::render_awg_config(&model, host, resolved)
                .with_context(|| format!("rendering awg config for node {host:?}"))?;
            awg::config::validate(&awg_cfg)
                .with_context(|| format!("rendered awg config for node {host:?} is invalid"))?;
            let router_cfg = render::render_router_config(&model, host)
                .with_context(|| format!("rendering router config for node {host:?}"))?;
            router::config::validate(&router_cfg)
                .with_context(|| format!("rendered router config for node {host:?} is invalid"))?;
            let nftables_cfg = render::render_nftables_config(&model);
            if let Some(cfg) = &nftables_cfg {
                nftables::config::validate(cfg).with_context(|| {
                    format!("rendered nftables config for node {host:?} is invalid")
                })?;
            }

            let mut patches = Vec::new();
            for patch in file.patches_for(host)? {
                if patch.sources > 1 {
                    eprintln!(
                        "{host}: {} is merged from {} documents and written re-serialized - \
                         their comments do not carry over",
                        patch.identity, patch.sources
                    );
                }
                patches.push(patch.text);
            }

            let mut generated = vec![
                render_extension_service_document(
                    "awg",
                    "/etc/talos-extensions/awg.yaml",
                    &yaml_serde::to_string(&awg_cfg)?,
                )?,
                render_extension_service_document(
                    "router",
                    "/etc/talos-extensions/router.yaml",
                    &yaml_serde::to_string(&router_cfg)?,
                )?,
            ];
            if let Some(cfg) = &nftables_cfg {
                generated.push(render_extension_service_document(
                    "nftables",
                    "/etc/talos-extensions/nftables.yaml",
                    &yaml_serde::to_string(cfg)?,
                )?);
            }

            let path = patches_dir.join(format!("{host}.yaml"));
            // A missing file is the from-scratch case; anything else must not read as "there was
            // nothing here", or the diff would show a whole file where one line changed.
            let before = match std::fs::read_to_string(&path) {
                Ok(raw) => raw,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => String::new(),
                Err(e) => return Err(e).with_context(|| format!("reading {}", path.display())),
            };
            let after = format!("{HEADER}{}", segments::render_file(&patches, &generated));
            Ok(HostFile {
                host: host.to_owned(),
                path,
                before,
                after,
            })
        })
        .collect()
}

const RED: &str = "\x1b[31m";
const GREEN: &str = "\x1b[32m";
const RESET: &str = "\x1b[0m";

/// `(prefix, reset)` for one diff line's tag - empty strings when `use_color` is false, so the
/// caller doesn't need a separate color/no-color code path.
fn colored_prefix(tag: similar::ChangeTag, use_color: bool) -> (&'static str, &'static str) {
    if !use_color {
        return match tag {
            similar::ChangeTag::Delete => ("-", ""),
            similar::ChangeTag::Insert => ("+", ""),
            similar::ChangeTag::Equal => (" ", ""),
        };
    }
    match tag {
        similar::ChangeTag::Delete => ("\x1b[31m-", RESET),
        similar::ChangeTag::Insert => ("\x1b[32m+", RESET),
        similar::ChangeTag::Equal => (" ", ""),
    }
}

/// Colors on only when stdout is an actual terminal and `NO_COLOR` isn't set - the same
/// convention `git diff`/most CLI tools use, so piping into a file or `less` still gets plain
/// `+`/`-` text, not raw escape codes.
fn use_color() -> bool {
    std::io::stdout().is_terminal() && std::env::var_os("NO_COLOR").is_none()
}

fn print_diff(node_name: &str, before: &str, after: &str) {
    if before == after {
        println!("{node_name}: no changes");
        return;
    }
    let use_color = use_color();
    let (header_del, header_ins) = if use_color { (RED, GREEN) } else { ("", "") };
    let reset = if use_color { RESET } else { "" };
    println!("{header_del}--- {node_name} (current){reset}");
    println!("{header_ins}+++ {node_name} (generated){reset}");
    for change in similar::TextDiff::from_lines(before, after).iter_all_changes() {
        let (prefix, reset) = colored_prefix(change.tag(), use_color);
        print!("{prefix}{change}{reset}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    #[test]
    fn colored_prefix_without_color_is_plain_signs_with_no_reset() {
        assert_eq!(colored_prefix(similar::ChangeTag::Delete, false), ("-", ""));
        assert_eq!(colored_prefix(similar::ChangeTag::Insert, false), ("+", ""));
        assert_eq!(colored_prefix(similar::ChangeTag::Equal, false), (" ", ""));
    }

    #[test]
    fn colored_prefix_with_color_wraps_delete_in_red_and_insert_in_green() {
        let (prefix, reset) = colored_prefix(similar::ChangeTag::Delete, true);
        assert_eq!(prefix, "\x1b[31m-");
        assert_eq!(reset, RESET);
        let (prefix, reset) = colored_prefix(similar::ChangeTag::Insert, true);
        assert_eq!(prefix, "\x1b[32m+");
        assert_eq!(reset, RESET);
    }

    #[test]
    fn colored_prefix_equal_line_is_never_colored() {
        assert_eq!(colored_prefix(similar::ChangeTag::Equal, true), (" ", ""));
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

    #[test]
    fn render_extension_service_document_is_the_serializers_output() {
        let inner = "interfaces:\n- name: mesh-b\n  listen_port: 51820\n";
        let doc = render_extension_service_document("awg", "/etc/talos-extensions/awg.yaml", inner)
            .unwrap();
        assert_eq!(
            doc,
            "apiVersion: v1alpha1\nkind: ExtensionServiceConfig\nname: awg\nconfigFiles:\n- mountPath: /etc/talos-extensions/awg.yaml\n  content: |\n    interfaces:\n    - name: mesh-b\n      listen_port: 51820\n"
        );
    }

    #[test]
    fn render_extension_service_document_round_trips_through_owned_segment_and_serde() {
        let inner = yaml_serde::to_string(&nftables::config::NftablesConfig {
            ruleset: "table inet x {}".to_string(),
        })
        .unwrap();
        let doc = render_extension_service_document(
            "nftables",
            "/etc/talos-extensions/nftables.yaml",
            &inner,
        )
        .unwrap();
        let found = segments::owned_segment(&doc, "nftables").unwrap().unwrap();
        assert!(segments::is_owned(&found));

        #[derive(serde::Deserialize)]
        struct Doc {
            #[serde(rename = "configFiles")]
            config_files: Vec<ConfigFile>,
        }
        #[derive(serde::Deserialize)]
        struct ConfigFile {
            content: String,
        }
        let parsed: Doc = yaml_serde::from_str(&found).unwrap();
        let cfg: nftables::config::NftablesConfig =
            yaml_serde::from_str(&parsed.config_files[0].content).unwrap();
        assert_eq!(cfg.ruleset, "table inet x {}");
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
            SlipmeshFile::parse(&self.config())
                .unwrap()
                .topology()
                .unwrap()
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
    fn generate_writes_each_host_its_patches_and_its_generated_documents() {
        let paths = setup("");
        paths.generate(None, false, false).unwrap();

        let a = paths.patch("a").unwrap();
        assert!(a.contains("disk: /dev/vda"), "{a}");
        let awg = segments::owned_segment(&a, "awg").unwrap().unwrap();
        assert!(awg.contains("mesh-b"), "{awg}");
        assert!(segments::owned_segment(&a, "router").unwrap().is_some());
        assert!(!paths.patch("b").unwrap().contains("disk:"));
    }

    #[test]
    fn every_written_file_opens_with_the_header() {
        let paths = setup("");
        paths.generate(None, false, false).unwrap();
        for host in ["a", "b", "c", "d"] {
            assert!(paths.patch(host).unwrap().starts_with(HEADER), "{host}");
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
        let raw = paths.config();
        let file = SlipmeshFile::parse(&raw).unwrap();
        let render = || {
            let (resolved, _) = settle_secrets(&paths.config, &raw, &file, true).unwrap();
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
        // A key used to be read back only from its own host's patch file, so rendering one host
        // before its peer had a file minted the peer a new key on every run. Secrets are settled
        // for the whole topology now, whichever host is rendered.
        let paths = setup("");
        paths.generate(Some("a"), false, false).unwrap();
        let first = paths.snapshot();
        paths.generate(Some("a"), false, false).unwrap();
        assert_eq!(paths.snapshot(), first);
        assert!(paths.patch("b").is_none());
    }

    #[test]
    fn a_host_that_fails_validation_leaves_every_host_unwritten() {
        let paths = setup(
            "---\nslipmesh:\n  kind: nftables\n  include: [d]\nruleset: |\n  table inet t { {{ bogus }} }\n",
        );
        let err = paths.generate(None, false, false).unwrap_err();
        assert!(format!("{err:#}").contains("\"d\""), "{err:#}");
        for host in ["a", "b", "c", "d"] {
            assert!(paths.patch(host).is_none(), "{host} was written");
        }
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

    fn pool_span(paths: &Paths, pool: &str) -> (String, std::ops::Range<usize>) {
        let raw = std::fs::read_to_string(&paths.config).unwrap();
        let span = SlipmeshFile::parse(&raw).unwrap().pool_span(pool).unwrap();
        (raw, span)
    }

    #[test]
    fn rw_add_edits_only_the_pools_own_document() {
        let paths = setup(POOLS);
        // Minted first, so that the only change the client makes is its own.
        paths.generate(None, false, false).unwrap();
        let (before, span) = pool_span(&paths, "first");
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

        let after = std::fs::read_to_string(&paths.config).unwrap();
        assert!(after.starts_with(&before[..span.start]), "{after}");
        assert!(after.ends_with(&before[span.end..]), "{after}");
        let (_, new_span) = pool_span(&paths, "first");
        assert!(after[new_span].contains("name: dave"), "{after}");
    }

    #[test]
    fn rw_del_edits_only_the_pools_own_document() {
        let paths = setup(POOLS);
        let (before, span) = pool_span(&paths, "second");

        rw_del("second", "carol", &paths.config).unwrap();

        let after = std::fs::read_to_string(&paths.config).unwrap();
        assert!(after.starts_with(&before[..span.start]), "{after}");
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
        // The key used to be generated for the exported config and then thrown away, so the next
        // `generate` minted a different one and the exported config never connected.
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

    /// The shape of a real repository, with nothing real in it: six hosts, one of them not a Talos
    /// node, two booting from different disks, three plain links, a plain pool with its key written
    /// out, an obfuscated pool with all nine fields written out, and a ruleset carrying a `---` line
    /// and a line with a trailing space.
    fn legacy_mesh_yaml() -> String {
        let plain_key = taloscfg::keys::generate_private_key();
        let obfuscated_key = taloscfg::keys::generate_private_key();
        format!(
            r#"bfd:
  enable: true

cluster:
  bgp_as: 64512
  loopback_networks: {{ipv4: "10.62.0.0/24", ipv6: "fd00:62::/120"}}
  # the metrics ports every node listens on
  awg_metrics_port: 9586

nodes:
  - {{name: node-a, node_id: "10.62.0.1", endpoint: "192.0.2.1"}}
  - {{name: node-b, node_id: "10.62.0.2", endpoint: "192.0.2.2"}}
  - {{name: node-c, node_id: "10.62.0.3", endpoint: "192.0.2.3"}}
  - {{name: node-d, node_id: "10.62.0.4", endpoint: "192.0.2.4"}}
  - {{name: node-e, node_id: "10.62.0.5"}}
  - {{name: router-1, node_id: "10.62.0.6", endpoint: "192.0.2.6"}}

mesh:
  links:
    - pair: [node-a, node-b]
      port: 52801
    - pair: [node-b, node-c]
      port: 52802
    - pair: [node-c, node-a]
      port: 52803

    - pair: [node-d, node-a]
      port: 52821
    - pair: [node-e, node-d]
      port: 52886

    - pair: [router-1, node-a]
      port: 52891
      plain: true
    - pair: [router-1, node-b]
      port: 52892
      plain: true
    - pair: [router-1, node-c]
      port: 52893
      plain: true

roadwarriors:
  - name: plain
    node_hostnames: [node-a, node-b]
    address: "198.51.100.1/24"
    listen_port: 51820
    private_key: "{plain_key}"
    plain: true
    clients:
      - {{name: client-a, public_key: "AAA=", allowed_ips: ["198.51.100.2/32"]}}
  - name: obfuscated
    node_hostnames: [node-c]
    address: "203.0.113.1/24"
    listen_port: 51821
    private_key: "{obfuscated_key}"
    obfuscation:
      jc: 4
      jmin: 81
      jmax: 408
      s1: 1114
      s2: 131
      h1: 883683258
      h2: 2249923740
      h3: 891489045
      h4: 2070706730
    clients: []

# prefixes that leave through the local uplink
bypass:
  - node: node-d
    include:
      - {{kind: literal, prefixes: [{{net: "203.0.113.128/25"}}]}}

nftables:
  ruleset: |
    table inet talos_filter {{
        chain input {{
            type filter hook input priority filter; policy accept;
    ---
        }}
    }}
"#
        )
        // Written as a replacement rather than in the literal above, where an editor trimming
        // trailing whitespace would take the space away without anyone noticing.
        .replace("        chain input {\n", "        chain input { \n")
    }

    /// Hand-written documents the old generator kept in front of its own, by host.
    fn legacy_hand_written(host: &str) -> Vec<String> {
        match host {
            "node-d" => vec![
                "apiVersion: v1alpha1\nkind: UnattendedInstallConfig\ninstaller:\n    disk: /dev/vda"
                    .to_owned(),
            ],
            "node-e" => vec![
                "# a smaller box\napiVersion: v1alpha1\nkind: UnattendedInstallConfig\ninstaller:\n    disk: /dev/nvme0n1"
                    .to_owned(),
            ],
            "router-1" => vec![
                "apiVersion: v1alpha1\nkind: ExtensionServiceConfig\nname: device\nconfigFiles:\n  - content: |\n      password: \"x\" \n      -----BEGIN CERTIFICATE-----\n      MIIB\n      -----END CERTIFICATE-----\n    mountPath: /etc/device.yaml"
                    .to_owned(),
            ],
            _ => Vec::new(),
        }
    }

    const HOSTS: [&str; 6] = ["node-a", "node-b", "node-c", "node-d", "node-e", "router-1"];

    #[test]
    fn a_migrated_repository_regenerates_its_patch_files_document_for_document() {
        let mesh = legacy_mesh_yaml();
        assert!(
            mesh.contains("chain input { \n"),
            "the fixture lost its trailing space"
        );

        // What the old generator left on disk: its documents per host, keys minted once, with the
        // hand-written ones in front.
        let first = temp_dir();
        let bootstrap = taloscfg::migrate::migrate(&mesh, &first.join("none")).unwrap();
        std::fs::write(first.join("slipmesh.yaml"), &bootstrap.slipmesh).unwrap();
        generate(
            None,
            false,
            false,
            &first.join("slipmesh.yaml"),
            &first.join("patches"),
        )
        .unwrap();
        let legacy = temp_dir().join("patches");
        std::fs::create_dir_all(&legacy).unwrap();
        for host in HOSTS {
            let generated =
                std::fs::read_to_string(first.join("patches").join(format!("{host}.yaml")))
                    .unwrap();
            let generated = generated.strip_prefix(HEADER).unwrap();
            // The old generator's layout: hand-written documents trimmed, its own as rendered,
            // all joined by the one separator.
            let hand_written = legacy_hand_written(host);
            let file = if hand_written.is_empty() {
                generated.to_owned()
            } else {
                format!("{}\n---\n{generated}", hand_written.join("\n---\n"))
            };
            std::fs::write(legacy.join(format!("{host}.yaml")), file).unwrap();
        }

        let dir = temp_dir();
        let migration = taloscfg::migrate::migrate(&mesh, &legacy).unwrap();
        assert!(migration.minted.is_empty(), "{:?}", migration.minted);
        let paths = Paths {
            config: dir.join("slipmesh.yaml"),
            patches: dir.join("patches"),
        };
        std::fs::write(&paths.config, &migration.slipmesh).unwrap();
        assert_eq!(
            SlipmeshFile::parse(&migration.slipmesh)
                .unwrap()
                .topology()
                .unwrap()
                .roadwarriors
                .len(),
            2
        );

        paths.generate(None, false, false).unwrap();
        for host in HOSTS {
            let before = std::fs::read_to_string(legacy.join(format!("{host}.yaml"))).unwrap();
            let after = paths.patch(host).unwrap();
            assert_eq!(after, format!("{HEADER}{before}"), "{host}");
        }

        let settled = |p: &Paths| {
            let mut files = vec![p.config()];
            files.extend(HOSTS.map(|h| p.patch(h).unwrap()));
            files
        };
        let once = settled(&paths);
        paths.generate(None, false, false).unwrap();
        assert_eq!(settled(&paths), once);
    }
}
