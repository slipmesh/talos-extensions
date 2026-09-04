//! `patches generate`: reads `mesh.yaml`, computes every target node's `awg`/`router`/`nftables`
//! config, validates each through the real daemon's own `validate()` (not a re-implementation -
//! see the lib-target refactor this crate depends on), and writes the result into
//! `patches/<node>.yaml` as `ExtensionServiceConfig` documents - preserving any segment this tool
//! doesn't own (see `segments.rs`). `--check`/`--diff` both stop short of writing; `--diff` also
//! prints what would change.
//!
//! `validate`/`diff`/`apply` are deliberately not separate subcommands: `generate`'s own
//! `--check`/`--diff` flags already cover them.

mod addressing;
mod existing;
mod keys;
mod mesh_config;
mod obfuscation_gen;
mod render;
mod roadwarrior;
mod segments;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use std::io::IsTerminal;
use std::path::{Path, PathBuf};

#[derive(Parser)]
#[command(
    name = "patches",
    version,
    about = "Generates Talos machine-config patches for awg/router/nftables from mesh.yaml"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Compute and write patches/<node>.yaml for one or every node in mesh.yaml.
    Generate {
        /// Only this node, instead of every node in mesh.yaml's `nodes`.
        #[arg(long)]
        node: Option<String>,
        /// Validate only, don't write anything to disk.
        #[arg(long)]
        check: bool,
        /// Validate and print a unified diff of what would change, don't write.
        #[arg(long)]
        diff: bool,
        #[arg(long, default_value = "mesh.yaml")]
        config: PathBuf,
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

fn generate(
    node: Option<&str>,
    check: bool,
    diff: bool,
    config_path: &Path,
    patches_dir: &Path,
) -> Result<()> {
    let raw_mesh =
        std::fs::read_to_string(config_path).with_context(|| format!("reading {config_path:?}"))?;
    let mesh: mesh_config::MeshConfig =
        serde_yaml::from_str(&raw_mesh).with_context(|| format!("parsing {config_path:?}"))?;
    mesh_config::validate(&mesh).context("mesh.yaml failed validation")?;

    if let Some(n) = node {
        anyhow::ensure!(
            mesh.nodes.iter().any(|entry| entry.name == n),
            "unknown node {n:?}"
        );
    }

    let existing_state = existing::FileExistingState::new(&mesh, patches_dir)?;
    let resolved = render::resolve_secrets(&mesh, &existing_state);

    let target_nodes: Vec<&str> = match node {
        Some(n) => vec![n],
        None => mesh.nodes.iter().map(|n| n.name.as_str()).collect(),
    };

    for node_name in target_nodes {
        let awg_cfg = render::render_awg_config(&mesh, node_name, &resolved)
            .with_context(|| format!("rendering awg config for node {node_name:?}"))?;
        awg::config::validate(&awg_cfg)
            .with_context(|| format!("rendered awg config for node {node_name:?} is invalid"))?;

        let router_cfg = render::render_router_config(&mesh, node_name)
            .with_context(|| format!("rendering router config for node {node_name:?}"))?;
        router::config::validate(&router_cfg)
            .with_context(|| format!("rendered router config for node {node_name:?} is invalid"))?;

        let nftables_cfg = render::render_nftables_config(&mesh);
        if let Some(cfg) = &nftables_cfg {
            nftables::config::validate(cfg).with_context(|| {
                format!("rendered nftables config for node {node_name:?} is invalid")
            })?;
        }

        let mut owned = vec![
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
            owned.push(render_extension_service_document(
                "nftables",
                "/etc/talos-extensions/nftables.yaml",
                &serde_yaml::to_string(cfg)?,
            ));
        }

        let patch_path = patches_dir.join(format!("{node_name}.yaml"));
        let existing_raw = std::fs::read_to_string(&patch_path).unwrap_or_default();
        let foreign = segments::foreign_segments(&existing_raw)
            .with_context(|| format!("reading the existing {patch_path:?}"))?;
        let new_content = segments::render_file(&foreign, &owned);

        if diff {
            print_diff(node_name, &existing_raw, &new_content);
            continue;
        }
        if check {
            println!("{node_name}: ok");
            continue;
        }

        std::fs::create_dir_all(patches_dir)
            .with_context(|| format!("creating {}", patches_dir.display()))?;
        std::fs::write(&patch_path, &new_content)
            .with_context(|| format!("writing {}", patch_path.display()))?;
        println!("wrote {}", patch_path.display());
    }

    Ok(())
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

    fn write_mesh_yaml(dir: &Path) -> PathBuf {
        let path = dir.join("mesh.yaml");
        std::fs::write(
            &path,
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
"#,
        )
        .unwrap();
        path
    }

    #[test]
    fn generate_writes_a_valid_owned_segment_and_preserves_foreign_content() {
        let dir = temp_dir();
        let config_path = write_mesh_yaml(&dir);
        let patches_dir = dir.join("patches");
        std::fs::create_dir_all(&patches_dir).unwrap();
        std::fs::write(
            patches_dir.join("a.yaml"),
            "machine:\n    install:\n        disk: /dev/vda\n",
        )
        .unwrap();

        generate(Some("a"), false, false, &config_path, &patches_dir).unwrap();

        let written = std::fs::read_to_string(patches_dir.join("a.yaml")).unwrap();
        assert!(written.contains("machine:"));
        assert!(written.contains("disk: /dev/vda"));
        let awg_segment = segments::owned_segment(&written, "awg").unwrap().unwrap();
        assert!(awg_segment.contains("mesh-"));
        assert!(
            segments::owned_segment(&written, "router")
                .unwrap()
                .is_some()
        );
    }

    #[test]
    fn generate_check_does_not_write_anything() {
        let dir = temp_dir();
        let config_path = write_mesh_yaml(&dir);
        let patches_dir = dir.join("patches");

        generate(Some("a"), true, false, &config_path, &patches_dir).unwrap();

        assert!(!patches_dir.join("a.yaml").exists());
    }

    #[test]
    fn generate_second_run_is_idempotent_for_mesh_private_keys() {
        // Bootstrap every node first (the normal workflow: `generate` with no `--node` filter
        // writes every node's file in one pass) - a peer's identity can only stay stable across
        // runs once that peer's own patch file exists to read it back from.
        let dir = temp_dir();
        let config_path = write_mesh_yaml(&dir);
        let patches_dir = dir.join("patches");

        generate(None, false, false, &config_path, &patches_dir).unwrap();
        let first = std::fs::read_to_string(patches_dir.join("a.yaml")).unwrap();
        generate(Some("a"), false, false, &config_path, &patches_dir).unwrap();
        let second = std::fs::read_to_string(patches_dir.join("a.yaml")).unwrap();

        assert_eq!(first, second);
    }

    #[test]
    fn generate_without_bootstrapping_the_peer_first_does_not_stay_idempotent() {
        // Documents the real limitation this exposed: regenerating only one node, when its peer's
        // own patch file was never written, can't recover the peer's identity from anywhere -
        // there's nothing on disk yet to read it back from, so the peer's derived public key
        // drifts between runs. Not a bug to fix here; a reason `generate`'s own docs (and this
        // test) should say "bootstrap with no --node filter first".
        let dir = temp_dir();
        let config_path = write_mesh_yaml(&dir);
        let patches_dir = dir.join("patches");

        generate(Some("a"), false, false, &config_path, &patches_dir).unwrap();
        let first = std::fs::read_to_string(patches_dir.join("a.yaml")).unwrap();
        generate(Some("a"), false, false, &config_path, &patches_dir).unwrap();
        let second = std::fs::read_to_string(patches_dir.join("a.yaml")).unwrap();

        assert_ne!(
            first, second,
            "expected peer b's never-persisted key to drift"
        );
    }

    #[test]
    fn generate_rejects_an_unknown_node() {
        let dir = temp_dir();
        let config_path = write_mesh_yaml(&dir);
        let patches_dir = dir.join("patches");

        assert!(generate(Some("nonexistent"), true, false, &config_path, &patches_dir).is_err());
    }
}
