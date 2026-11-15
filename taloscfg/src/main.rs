//! `generate`: reads `slipmesh.yaml`, computes every target node's `awg`/`router` config through
//! `sliplib-mesh`, which checks each the way the daemon would, and writes `patches/<node>.yaml`:
//! the `patch` documents aimed at that node, then the generated `ExtensionServiceConfig`
//! documents. It only reads `slipmesh.yaml`: what the file lacks is refused, with the command that
//! writes it. A patch file is output only - nothing in it is read back. `--check`/`--diff` both
//! stop short of writing; `--diff` also prints what would change.
//!
//! `validate`/`diff`/`apply` are deliberately not separate subcommands: `generate`'s own
//! `--check`/`--diff` flags already cover them.

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use sliplib_config::mesh_config::missing_defaults;
use sliplib_config::slipmesh_file::SlipmeshFile;
use sliplib_mesh::secrets::{MissingSecret, ResolvedSecrets};
use sliplib_yaml::MultiDoc;
use std::path::{Path, PathBuf};
use taloscfg::{defaults, patch_file};

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
        /// Only this node's patch file, instead of every node's. Only the secrets this node's
        /// config needs have to be written in slipmesh.yaml.
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

fn read_slipmesh(config_path: &Path) -> Result<SlipmeshFile> {
    SlipmeshFile::read(&MultiDoc::read(config_path)?)
        .with_context(|| format!("reading {}", config_path.display()))
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
    let file = read_slipmesh(config_path)?;
    if let Some(n) = node {
        anyhow::ensure!(file.hosts().contains(&n), "unknown node {n:?}");
    }
    // The nodes are told these, so a default the file does not show is refused rather than sent.
    let unset: Vec<&str> = missing_defaults(file.topology())
        .into_iter()
        .map(|(key, _)| key)
        .collect();
    anyhow::ensure!(
        unset.is_empty(),
        "{} lacks {} - `slipmesh mint` writes their defaults",
        config_path.display(),
        unset.join(", ")
    );
    // A node a template does not reach was aimed past; a template no document sets at all was
    // left out, and its service would start on every node without one.
    let untemplated: Vec<String> = defaults::missing(&file)
        .iter()
        .map(|service| format!("`slipmesh-taloscfg template {service}`"))
        .collect();
    anyhow::ensure!(
        untemplated.is_empty(),
        "{} gives no node a template for a service that takes one - {} prints the document to add",
        config_path.display(),
        untemplated.join(" and ")
    );
    let resolved = sliplib_mesh::secrets::read(file.topology());
    let targets = match node {
        Some(n) => vec![n],
        None => file.hosts(),
    };

    // Every host is rendered and validated before anything is written, so a host that fails
    // leaves the patch files as they were rather than half of them new.
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

    for host in &hosts {
        if sliplib_yaml::write_if_changed(&host.path, &host.after)? {
            println!("wrote {}", host.path.display());
        } else {
            println!("{}: no changes", host.host);
        }
    }
    Ok(())
}

/// Every target host's patch file, rendered and validated in memory.
fn render_hosts(
    file: &SlipmeshFile,
    resolved: &ResolvedSecrets,
    targets: &[&str],
    patches_dir: &Path,
) -> Result<Vec<HostFile>> {
    targets
        .iter()
        .map(|&host| {
            let after = patch_file::render(file, resolved, host).map_err(with_its_cure)?;
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

/// `refusal`, with the command that creates the secret when a missing one is what it is about.
fn with_its_cure(refusal: anyhow::Error) -> anyhow::Error {
    if refusal.is::<MissingSecret>() {
        anyhow::anyhow!("{refusal:#} - `slipmesh mint` creates it")
    } else {
        refusal
    }
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
    use sliplib_secrets::wireguard::PrivateKey;
    use std::sync::LazyLock;
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

    const OBFUSCATION: &str =
        ", obfuscation: {jc: 4, jmin: 10, jmax: 50, s1: 15, s2: 16, h1: 5, h2: 6, h3: 7, h4: 8}";

    /// A key generated for these tests alone.
    fn key() -> String {
        PrivateKey::generate().expose().to_owned()
    }

    /// The key of node `a` in `SLIPMESH`.
    static KEY_OF_A: LazyLock<String> = LazyLock::new(key);

    /// A file with everything `slipmesh mint` writes.
    static SLIPMESH: LazyLock<String> = LazyLock::new(|| {
        format!(
            r#"slipmesh:
  kind: network
cluster:
  bgp_as: 64512
  loopback_networks: {{ipv4: "198.51.100.0/25", ipv6: "3fff::/32"}}
  interface_prefix: {{mesh: mesh-}}
  route_proto_id: {{egress: 152}}
nodes:
  - {{name: a, node_id: "198.51.100.1", endpoint: "192.0.2.10", mesh_private_key: "{a}"}}
  - {{name: b, node_id: "198.51.100.2", endpoint: "192.0.2.11", mesh_private_key: "{b}"}}
  - {{name: c, node_id: "198.51.100.3", mesh_private_key: "{c}"}}
  - {{name: d, node_id: "198.51.100.4", mesh_private_key: "{d}"}}
mesh:
  links:
    - {{pair: [a, b], port: 51820{OBFUSCATION}}}
---
slipmesh:
  kind: patch
  include: [a]
apiVersion: v1alpha1
kind: UnattendedInstallConfig
installer:
    disk: /dev/vda
"#,
            a = *KEY_OF_A,
            b = key(),
            c = key(),
            d = key(),
        )
    });

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

    /// A file holding `content`, with where its patch files go.
    fn holding(content: &str) -> Paths {
        let dir = temp_dir();
        let config = dir.join("slipmesh.yaml");
        std::fs::write(&config, content).unwrap();
        Paths {
            config,
            patches: dir.join("patches"),
        }
    }

    /// `network`, which is `SLIPMESH` or an edit of it, with both reference templates for every
    /// host and then `extra_documents`.
    fn setup_from(network: &str, extra_documents: &str) -> Paths {
        let router = defaults::document(defaults::Service::Router);
        let nftables = defaults::document(defaults::Service::Nftables);
        holding(&format!(
            "{network}---\n{router}---\n{nftables}{extra_documents}"
        ))
    }

    fn setup(extra_documents: &str) -> Paths {
        setup_from(&SLIPMESH, extra_documents)
    }

    const MODES: [(bool, bool); 3] = [(false, false), (true, false), (false, true)];

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

    /// A pool on node `a`, with `settings` after its required ones.
    fn pool(settings: &str) -> String {
        format!(
            "---\nslipmesh:\n  kind: roadwarriors\nname: north\nnode_hostnames: [a]\naddress: \"203.0.113.1/27\"\nlisten_port: 51900\n{settings}"
        )
    }

    #[test]
    fn a_file_lacking_a_secret_is_refused_in_every_mode_naming_the_command_that_creates_it() {
        let without = |part: &str| {
            assert!(SLIPMESH.contains(part), "{part}");
            SLIPMESH.replace(part, "")
        };
        let key_of_a = format!(", mesh_private_key: \"{}\"", *KEY_OF_A);
        let pool_key = format!("private_key: \"{}\"\n", key());
        let key_of_a_is_not_set = "node \"a\": mesh_private_key is not set";
        let cases = [
            (key_of_a_is_not_set, without(&key_of_a), String::new(), "a"),
            (key_of_a_is_not_set, without(&key_of_a), String::new(), "b"),
            (
                "mesh link a-b: obfuscation lacks",
                without(OBFUSCATION),
                String::new(),
                "a",
            ),
            (
                "roadwarriors pool \"north\": private_key is not set",
                SLIPMESH.to_owned(),
                pool("plain: true\n"),
                "a",
            ),
            (
                "roadwarriors pool \"north\": obfuscation lacks",
                SLIPMESH.to_owned(),
                pool(&pool_key),
                "a",
            ),
        ];
        for (missing, network, extra, node) in cases {
            for (check, diff) in MODES {
                let paths = setup_from(&network, &extra);
                let before = paths.snapshot();
                let err = paths.generate(Some(node), check, diff).unwrap_err();
                let err = format!("{err:#}");
                assert!(err.contains(missing), "{missing}: {err}");
                assert!(err.contains("`slipmesh mint`"), "{missing}: {err}");
                assert_eq!(paths.snapshot(), before, "{missing}");
            }
        }
    }

    #[test]
    fn a_key_that_does_not_decode_is_refused_naming_its_node_and_no_command() {
        let network = SLIPMESH.replace(KEY_OF_A.as_str(), "not a key");
        let err = setup_from(&network, "")
            .generate(Some("b"), true, false)
            .unwrap_err();
        let err = format!("{err:#}");
        assert!(err.contains("node \"a\": mesh_private_key"), "{err}");
        assert!(!err.contains("slipmesh mint"), "{err}");
    }

    #[test]
    fn a_run_for_one_node_needs_no_secret_of_a_node_it_is_not_linked_to() {
        let key_of_d = SLIPMESH
            .lines()
            .find(|line| line.contains("name: d,"))
            .and_then(|line| line.split(", mesh_private_key").nth(1))
            .unwrap();
        let network = SLIPMESH.replace(&format!(", mesh_private_key{key_of_d}"), "}");
        assert_ne!(network, *SLIPMESH);
        setup_from(&network, "")
            .generate(Some("a"), true, false)
            .unwrap();
        let err = setup_from(&network, "")
            .generate(None, true, false)
            .unwrap_err();
        assert!(format!("{err:#}").contains("node \"d\""), "{err:#}");
    }

    #[test]
    fn a_file_in_which_no_document_sets_a_template_is_refused_in_every_mode_naming_template() {
        let router = defaults::document(defaults::Service::Router);
        let nftables = defaults::document(defaults::Service::Nftables);
        for (lacking, present) in [("nftables", &router), ("router", &nftables)] {
            for (check, diff) in MODES {
                let paths = holding(&format!("{}---\n{present}", *SLIPMESH));
                let before = paths.snapshot();
                let err = format!("{:#}", paths.generate(None, check, diff).unwrap_err());
                let command = format!("`slipmesh-taloscfg template {lacking}`");
                assert!(err.contains(&command), "{lacking}: {err}");
                assert_eq!(paths.snapshot(), before, "{lacking}");
            }
        }
    }

    #[test]
    fn a_full_run_leaves_slipmesh_yaml_as_it_is() {
        let paths = setup("");
        let before = std::fs::read(&paths.config).unwrap();
        paths.generate(None, false, false).unwrap();
        assert_eq!(std::fs::read(&paths.config).unwrap(), before);
    }

    #[test]
    fn a_refusal_that_no_secret_cures_names_no_command() {
        let network = SLIPMESH.replace(
            "  bgp_as: 64512\n",
            "  bgp_as: 64512\n  awg_metrics_port: 0\n",
        );
        let err = setup_from(&network, "")
            .generate(None, true, false)
            .unwrap_err();
        let err = format!("{err:#}");
        assert!(err.contains("awg_metrics_port"), "{err}");
        assert!(!err.contains("slipmesh mint"), "{err}");
    }

    #[test]
    fn a_file_without_the_prefix_and_protocol_keys_is_refused_in_every_mode_naming_them() {
        let network = SLIPMESH
            .replace("  interface_prefix: {mesh: mesh-}\n", "")
            .replace("  route_proto_id: {egress: 152}\n", "");
        for (check, diff) in MODES {
            let paths = setup_from(&network, "");
            let before = paths.snapshot();
            let err = format!("{:#}", paths.generate(None, check, diff).unwrap_err());
            for named in [
                "cluster.interface_prefix.mesh",
                "cluster.route_proto_id.egress",
                "`slipmesh mint`",
            ] {
                assert!(err.contains(named), "{named}: {err}");
            }
            assert_eq!(paths.snapshot(), before);
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
    fn a_dry_run_writes_no_patch_file() {
        for (check, diff) in [(true, false), (false, true)] {
            let paths = setup("");
            paths.generate(None, check, diff).unwrap();
            assert!(!paths.patches.exists());
        }
    }

    #[test]
    fn two_runs_render_the_same() {
        let paths = setup("");
        let render = || {
            let file = read_slipmesh(&paths.config).unwrap();
            let resolved = sliplib_mesh::secrets::read(file.topology());
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
    fn a_run_for_one_host_writes_that_hosts_file_only() {
        let paths = setup("");
        paths.generate(Some("a"), false, false).unwrap();
        assert!(paths.patch("a").is_some());
        assert!(paths.patch("b").is_none());
    }

    #[test]
    fn a_host_that_fails_validation_leaves_every_file_unwritten() {
        let paths = setup(
            "---\nslipmesh:\n  kind: patch\n  include: [d]\napiVersion: v1alpha1\nkind: ExtensionServiceConfig\nname: nftables\nconfigFiles:\n  - mountPath: /etc/talos-extensions/nftables.conf.j2\n    content: |\n      table inet t { {{ bogus }} }\n",
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
