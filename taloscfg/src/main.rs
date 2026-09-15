//! `generate`: reads `slipmesh.yaml`, settles the topology's secrets against
//! `slipmesh-secrets.yaml`, computes every target node's `awg`/`router`/`nftables` config,
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
use taloscfg::secrets::SecretsFile;
use taloscfg::slipmesh_file::SlipmeshFile;
use taloscfg::{mesh_config, render, roadwarrior, segments};

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
        /// Only this node's patch file, instead of every node's. Secrets are still settled for
        /// the whole topology: a link's two ends need the same ones.
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
        #[arg(long, default_value = "slipmesh-secrets.yaml")]
        secrets: PathBuf,
        #[arg(long, default_value = "patches")]
        patches_dir: PathBuf,
    },
    /// Add a client to a `roadwarriors:` pool in mesh.yaml.
    RwAdd {
        /// Which roadwarriors pool (mesh.yaml's `roadwarriors[].name`, e.g. `plain`).
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
        /// first one in mesh.yaml's own order) - the rest still appear as commented #Endpoint =.
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
        #[arg(long, default_value = "mesh.yaml")]
        config: PathBuf,
        #[arg(long, default_value = "patches")]
        patches_dir: PathBuf,
    },
    /// Remove a client from a `roadwarriors:` pool in mesh.yaml.
    RwDel {
        #[arg(long = "if")]
        if_: String,
        #[arg(long)]
        name: String,
        #[arg(long, default_value = "mesh.yaml")]
        config: PathBuf,
    },
    /// Re-render an existing client's config/QR without changing mesh.yaml.
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
        /// first one in mesh.yaml's own order) - the rest still appear as commented #Endpoint =.
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
        #[arg(long, default_value = "mesh.yaml")]
        config: PathBuf,
        #[arg(long, default_value = "patches")]
        patches_dir: PathBuf,
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
            secrets,
            patches_dir,
        } => generate(
            node.as_deref(),
            check,
            diff,
            &config,
            &secrets,
            &patches_dir,
        ),
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
            patches_dir,
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
            &patches_dir,
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
            patches_dir,
        } => rw_inspect(
            &if_,
            &name,
            private_key.as_deref(),
            endpoint.as_deref(),
            export,
            qr,
            invert,
            &config,
            &patches_dir,
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
    patches_dir: &Path,
) -> Result<()> {
    let raw_mesh =
        std::fs::read_to_string(config_path).with_context(|| format!("reading {config_path:?}"))?;
    let mesh: mesh_config::MeshConfig =
        serde_yaml::from_str(&raw_mesh).with_context(|| format!("parsing {config_path:?}"))?;
    mesh_config::validate(&mesh).context("mesh.yaml failed validation")?;

    let (updated, client_config) = roadwarrior::add(
        &mesh,
        &raw_mesh,
        patches_dir,
        if_,
        name,
        allowed_ips,
        public_key,
        endpoint,
        export,
        qr,
    )?;

    std::fs::write(config_path, &updated).with_context(|| format!("writing {config_path:?}"))?;
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
    let raw_mesh =
        std::fs::read_to_string(config_path).with_context(|| format!("reading {config_path:?}"))?;
    let mesh: mesh_config::MeshConfig =
        serde_yaml::from_str(&raw_mesh).with_context(|| format!("parsing {config_path:?}"))?;
    mesh_config::validate(&mesh).context("mesh.yaml failed validation")?;

    let (updated, public_key) = roadwarrior::del(&mesh, &raw_mesh, if_, name)?;

    std::fs::write(config_path, &updated).with_context(|| format!("writing {config_path:?}"))?;
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
    patches_dir: &Path,
) -> Result<()> {
    let raw_mesh =
        std::fs::read_to_string(config_path).with_context(|| format!("reading {config_path:?}"))?;
    let mesh: mesh_config::MeshConfig =
        serde_yaml::from_str(&raw_mesh).with_context(|| format!("parsing {config_path:?}"))?;
    mesh_config::validate(&mesh).context("mesh.yaml failed validation")?;

    let text = roadwarrior::inspect(&mesh, patches_dir, if_, name, private_key, endpoint)?;

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

/// Renders one owned `ExtensionServiceConfig` document: `name`/`mountPath` fixed by convention,
/// `inner_yaml` (the daemon's own already-serialized config) nested under `content: |`, indented
/// so it parses back as a YAML literal block scalar.
fn render_extension_service_document(name: &str, mount_path: &str, inner_yaml: &str) -> String {
    let indented: String = inner_yaml.lines().map(|l| format!("      {l}\n")).collect();
    format!(
        "apiVersion: v1alpha1\nkind: ExtensionServiceConfig\nname: {name}\nconfigFiles:\n  - mountPath: {mount_path}\n    content: |\n{indented}"
    )
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
    secrets_path: &Path,
    patches_dir: &Path,
) -> Result<()> {
    let raw = std::fs::read_to_string(config_path)
        .with_context(|| format!("reading {}", config_path.display()))?;
    let file =
        SlipmeshFile::parse(&raw).with_context(|| format!("reading {}", config_path.display()))?;
    let targets = match node {
        Some(n) => {
            anyhow::ensure!(file.hosts().contains(&n), "unknown node {n:?}");
            vec![n]
        }
        None => file.hosts(),
    };

    let resolved = settle_secrets(&file, secrets_path, check || diff)?;
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

/// Resolves the whole topology's secrets against the secrets file. On a write run, whatever that
/// minted is recorded first; on a dry run, needing to mint anything is an error, since a minted
/// value that is never written would differ on the next run.
fn settle_secrets(
    file: &SlipmeshFile,
    secrets_path: &Path,
    dry_run: bool,
) -> Result<render::ResolvedSecrets> {
    let secrets = SecretsFile::read(secrets_path)?;
    let topology = file.topology()?;
    for orphan in secrets.orphans(&topology) {
        eprintln!(
            "warning: {orphan} in {} belongs to nothing in slipmesh.yaml - kept; delete it by \
             hand if it is gone for good",
            secrets_path.display()
        );
    }

    let resolved = render::resolve_secrets(&topology, &secrets);
    let additions = secrets.additions(&topology, &resolved)?;
    if additions.is_empty() {
        return Ok(resolved);
    }
    let routes = additions.routes().join(", ");
    anyhow::ensure!(
        !dry_run,
        "{} lacks {routes} - run `slipmesh-taloscfg generate` to mint and record them",
        secrets_path.display()
    );

    write_replacing(secrets_path, &secrets.with(&additions)?)?;
    println!("recorded {routes} in {}", secrets_path.display());
    Ok(resolved)
}

/// Writes `content` to a sibling file and renames it over `path`, so an interrupted write cannot
/// leave the secrets file half-written - a key lost that way is an identity rotated.
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
                    &serde_yaml::to_string(&awg_cfg)?,
                ),
                render_extension_service_document(
                    "router",
                    "/etc/talos-extensions/router.yaml",
                    &serde_yaml::to_string(&router_cfg)?,
                ),
            ];
            if let Some(cfg) = &nftables_cfg {
                generated.push(render_extension_service_document(
                    "nftables",
                    "/etc/talos-extensions/nftables.yaml",
                    &serde_yaml::to_string(cfg)?,
                ));
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
    fn render_extension_service_document_indents_content_as_a_literal_block() {
        let doc = render_extension_service_document(
            "awg",
            "/etc/talos-extensions/awg.yaml",
            "interfaces: []",
        );
        assert_eq!(
            doc,
            "apiVersion: v1alpha1\nkind: ExtensionServiceConfig\nname: awg\nconfigFiles:\n  - mountPath: /etc/talos-extensions/awg.yaml\n    content: |\n      interfaces: []\n"
        );
    }

    #[test]
    fn render_extension_service_document_round_trips_through_owned_segment_and_serde() {
        let inner = serde_yaml::to_string(&nftables::config::NftablesConfig {
            ruleset: "table inet x {}".to_string(),
        })
        .unwrap();
        let doc = render_extension_service_document(
            "nftables",
            "/etc/talos-extensions/nftables.yaml",
            &inner,
        );
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
        let parsed: Doc = serde_yaml::from_str(&found).unwrap();
        let cfg: nftables::config::NftablesConfig =
            serde_yaml::from_str(&parsed.config_files[0].content).unwrap();
        assert_eq!(cfg.ruleset, "table inet x {}");
    }

    const SLIPMESH: &str = r#"slipmesh:
  kind: network
cluster:
  bgp_as: 64512
  loopback_networks: {ipv4: "10.62.0.0/16", ipv6: "fd00:62::/32"}
nodes:
  - {name: a, node_id: "10.62.0.1"}
  - {name: b, node_id: "10.62.0.2"}
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
        secrets: PathBuf,
        patches: PathBuf,
    }

    impl Paths {
        fn generate(&self, node: Option<&str>, check: bool, diff: bool) -> Result<()> {
            generate(
                node,
                check,
                diff,
                &self.config,
                &self.secrets,
                &self.patches,
            )
        }

        fn patch(&self, host: &str) -> Option<String> {
            std::fs::read_to_string(self.patches.join(format!("{host}.yaml"))).ok()
        }

        /// Every file a run could have written, with what it holds.
        fn snapshot(&self) -> Vec<(PathBuf, Option<String>)> {
            let mut paths = vec![self.secrets.clone()];
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
            secrets: dir.join("slipmesh-secrets.yaml"),
            patches: dir.join("patches"),
        }
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
            let err = paths.generate(None, check, diff).unwrap_err();
            assert!(format!("{err:#}").contains("generate"), "{err:#}");
            assert!(!paths.secrets.exists());
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
        let file = SlipmeshFile::parse(&std::fs::read_to_string(&paths.config).unwrap()).unwrap();
        let render = || {
            let resolved = settle_secrets(&file, &paths.secrets, true).unwrap();
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
}
