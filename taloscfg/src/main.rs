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
use sliplib_config::v2::{File, Platform};
use sliplib_mesh::Mesh;
use std::path::{Path, PathBuf};
use taloscfg::documents::{TalosSettings, Template};
use taloscfg::{defaults, patch_file, patches};

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
    /// Compute and write patches/<node>.yaml for one or every node of `talos` in slipmesh.yaml.
    Generate {
        /// Only this node's patch file, instead of every node's; a node of `talos`. Only the
        /// secrets this node's config needs have to be written in slipmesh.yaml.
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
    /// Print the `template` document holding a daemon's reference template, to add to
    /// slipmesh.yaml.
    Template { daemon: defaults::Service },
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
        Command::Template { daemon } => {
            print!("{}", defaults::document(daemon));
            Ok(())
        }
    }
}

/// Checked as far as this generator reads them.
fn read_slipmesh(config_path: &Path) -> Result<File> {
    let files = File::open(config_path)?;
    patches::check(&files).with_context(|| format!("reading {}", config_path.display()))?;
    Ok(files)
}

/// A warning for every `template` document reaching one of `targets` whose `base` is not the hash
/// of its daemon's current reference template, with how its text differs from that reference.
fn base_warnings(files: &File, targets: &[&str]) -> Result<Vec<String>> {
    let mut warnings = Vec::new();
    for document in files.templates() {
        if !targets.iter().any(|target| document.aim().reaches(target)) {
            continue;
        }
        let template = Template::of(document)?;
        let service = defaults::Service::of(template.daemon);
        if template.base.digest() == service.digest() {
            continue;
        }
        warnings.push(match service.differences_from_reference(&template.content) {
            Some(differences) => format!(
                "{}: its `base` is not the hash of the current reference {service} template, \
                 which its text differs from as follows - once it is brought up to it, set `base` \
                 to {}\n{}",
                document.aim(),
                service.base(),
                differences.trim_end()
            ),
            None => format!(
                "{}: its text is the current reference {service} template, and its `base` is not \
                 that template's hash - set `base` to {}",
                document.aim(),
                service.base(),
            ),
        });
    }
    Ok(warnings)
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
    let files = read_slipmesh(config_path)?;
    let reading = || format!("reading {}", config_path.display());
    let network = Mesh::of(&files).with_context(reading)?;
    let settings = TalosSettings::of(&files).with_context(reading)?;
    if let Some(n) = node {
        network.node_on(n, Platform::Talos)?;
    }
    // A node a template does not reach was aimed past; a daemon no document gives a template at
    // all was left out, and would start on every node without one.
    let untemplated: Vec<String> = defaults::missing(&files)
        .with_context(reading)?
        .iter()
        .map(|service| format!("`slipmesh-taloscfg template {service}`"))
        .collect();
    anyhow::ensure!(
        untemplated.is_empty(),
        "{} gives no node a template for a daemon that takes one - {} prints the document to add",
        config_path.display(),
        untemplated.join(" and ")
    );
    let targets: Vec<&str> = match node {
        Some(n) => vec![n],
        None => network
            .network()
            .nodes
            .iter()
            .filter(|(_, node)| node.platform == Platform::Talos)
            .map(|(name, _)| name.as_str())
            .collect(),
    };

    // Every host is rendered and validated before anything is written, so a host that fails
    // leaves the patch files as they were rather than half of them new.
    let hosts = render_hosts(&files, &network, &settings, &targets, patches_dir)?;

    // Told in every mode, and failing none: the files are valid, and their writer should still
    // know.
    for warning in sliplib_mesh::warnings::warnings(&network)
        .iter()
        .filter(|warning| targets.iter().any(|target| warning.concerns(target)))
    {
        eprintln!("warning: {warning}");
    }
    for warning in base_warnings(&files, &targets)? {
        eprintln!("warning: {warning}");
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

    for host in &hosts {
        if sliplib_fs::write_if_changed(&host.path, &host.after)? {
            println!("wrote {}", host.path.display());
        } else {
            println!("{}: no changes", host.host);
        }
    }
    Ok(())
}

/// Every target host's patch file, rendered and validated in memory.
fn render_hosts(
    files: &File,
    network: &Mesh<'_>,
    settings: &TalosSettings,
    targets: &[&str],
    patches_dir: &Path,
) -> Result<Vec<HostFile>> {
    targets
        .iter()
        .map(|&host| {
            // One line: `main`'s `{:?}` would print the chain over several.
            let after = patch_file::render(files, network, settings, host)
                .map_err(|refusal| anyhow::anyhow!("{refusal:#}"))?;
            let path = patches_dir.join(format!("{host}.yaml"));
            // A missing file is the from-scratch case; anything else must not read as "there was
            // nothing here", or the diff would show a whole file where one line changed.
            let before = sliplib_fs::read_or_empty(&path)?;
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
    Some(taloscfg::text::unified_diff(
        &before,
        &after,
        &format!("{host} (current)"),
        &format!("{host} (generated)"),
    ))
}

/// Prints `diff_text` in colour where the output takes it - `anstream` leaves the colour out when
/// stdout is not a terminal or `NO_COLOR` is set.
fn print_diff(host: &str, before: &str, after: &str) {
    let Some(text) = diff_text(host, before, after) else {
        println!("{host}: no changes");
        return;
    };
    for line in text.lines() {
        let style = style_of(line);
        anstream::println!("{style}{line}{style:#}");
    }
}

fn style_of(line: &str) -> anstyle::Style {
    match line.as_bytes().first() {
        Some(b'-') => anstyle::AnsiColor::Red.on_default(),
        Some(b'+') => anstyle::AnsiColor::Green.on_default(),
        Some(b'@') => anstyle::AnsiColor::Cyan.on_default(),
        _ => anstyle::Style::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sliplib_secrets::wireguard::PrivateKey;
    use std::sync::LazyLock;
    use std::sync::atomic::{AtomicU64, Ordering};

    #[test]
    fn a_diff_line_is_coloured_by_its_first_character() {
        use anstyle::{AnsiColor, Style};
        assert_eq!(style_of("-  mtu: 1400"), AnsiColor::Red.on_default());
        assert_eq!(style_of("+  mtu: 1420"), AnsiColor::Green.on_default());
        assert_eq!(style_of("@@ -1,3 +1,3 @@"), AnsiColor::Cyan.on_default());
        assert_eq!(style_of("   mtu: 1400"), Style::new());
        assert_eq!(style_of(""), Style::new());
    }

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

    /// The obfuscation of `a-b`, every field `slipmesh mint` writes.
    const OBFUSCATION: &str = "\n        obfuscation: {jc: 4, jmin: 10, jmax: 50, s1: 15, s2: 16, h1: 5, h2: 6, h3: 7, h4: 8}";

    /// A key generated for these tests alone.
    fn key() -> String {
        PrivateKey::generate().expose().to_owned()
    }

    /// The key of node `a` in `SLIPMESH`.
    static KEY_OF_A: LazyLock<String> = LazyLock::new(key);

    /// The key of node `d` in `SLIPMESH`.
    static KEY_OF_D: LazyLock<String> = LazyLock::new(key);

    /// Files with everything `slipmesh mint` writes: four nodes of `talos`, `a-b` and `c-d`
    /// between them, `router1` of `routeros` on a link to `a`, and a `patch` for `a`.
    static SLIPMESH: LazyLock<String> = LazyLock::new(|| {
        format!(
            r#"slipmesh: {{kind: network, version: 2, revision: 1}}
addressing: {{loopback: {{ipv4: 198.51.100.0/25, ipv6: "3fff::/64"}}}}
routing:
  bgp: {{as: 64512}}
  classes: {{egress: {{protocol: 152}}}}
mesh:
  interface_prefix: mesh-
  links:
    a-b:
      type: amneziawg
      ends: {{a: {{}}, b: {{}}}}
      amneziawg:
        port: 51820{OBFUSCATION}
    c-d:
      type: wireguard
      ends: {{c: {{}}, d: {{}}}}
      wireguard: {{port: 51821}}
    a-r1:
      type: wireguard
      ends: {{a: {{}}, router1: {{}}}}
      wireguard: {{port: 51822}}
nodes:
  a: {{platform: talos, node_id: 0.0.0.1, underlay: {{wan: {{endpoint: {{ipv4: 192.0.2.10}}}}}}, wireguard: {{private_key: "{a}"}}}}
  b: {{platform: talos, node_id: 0.0.0.2, underlay: {{wan: {{endpoint: {{ipv4: 192.0.2.11}}}}}}, wireguard: {{private_key: "{b}"}}}}
  c: {{platform: talos, node_id: 0.0.0.3, underlay: {{wan: {{endpoint: {{ipv4: 192.0.2.12}}}}}}, wireguard: {{private_key: "{c}"}}}}
  d: {{platform: talos, node_id: 0.0.0.4, underlay: {{wan: {{}}}}, wireguard: {{private_key: "{d}"}}}}
  router1:
    platform: routeros
    node_id: 0.0.0.5
    underlay: {{wan: {{}}}}
    wireguard: {{private_key: "{r}"}}
    routing: {{learn: [], announce: []}}
---
slipmesh: {{kind: patch, platform: talos, include: [a]}}
apiVersion: v1alpha1
kind: UnattendedInstallConfig
installer:
    disk: /dev/vda
"#,
            a = *KEY_OF_A,
            b = key(),
            c = key(),
            d = *KEY_OF_D,
            r = key(),
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
            paths.extend(
                ["a", "b", "c", "d", "router1"].map(|h| self.patches.join(format!("{h}.yaml"))),
            );
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
        let firewall = defaults::document(defaults::Service::Firewall);
        holding(&format!(
            "{network}---\n{router}---\n{firewall}{extra_documents}"
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

    #[test]
    fn a_file_lacking_a_secret_is_refused_in_every_mode_naming_the_command_that_creates_it() {
        let without = |part: &str, put: &str| {
            assert!(SLIPMESH.contains(part), "{part}");
            SLIPMESH.replace(part, put)
        };
        let key_of_a = format!("wireguard: {{private_key: \"{}\"}}", *KEY_OF_A);
        let key_of_a_is_not_set = "node \"a\": wireguard.private_key is not set";
        let cases = [
            (
                key_of_a_is_not_set,
                without(&key_of_a, "wireguard: null"),
                "a",
            ),
            (
                key_of_a_is_not_set,
                without(&key_of_a, "wireguard: null"),
                "b",
            ),
            (
                "mesh link a-b: obfuscation lacks",
                without(OBFUSCATION, ""),
                "a",
            ),
        ];
        for (missing, network, node) in cases {
            for (check, diff) in MODES {
                let paths = setup_from(&network, "");
                let before = paths.snapshot();
                let err = paths.generate(Some(node), check, diff).unwrap_err();
                // `main` prints it with `{:?}`, on one line only without causes.
                assert_eq!(err.chain().count(), 1, "{missing}: {err:?}");
                let err = err.to_string();
                assert!(err.contains(missing), "{missing}: {err}");
                assert!(
                    err.ends_with(" - `slipmesh mint` creates it"),
                    "{missing}: {err}"
                );
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
        assert!(err.contains("node \"a\": wireguard.private_key"), "{err}");
        assert!(!err.contains("slipmesh mint"), "{err}");
    }

    #[test]
    fn a_run_for_one_node_needs_no_secret_of_a_node_it_is_not_linked_to() {
        let network = SLIPMESH.replace(
            &format!("wireguard: {{private_key: \"{}\"}}", *KEY_OF_D),
            "wireguard: null",
        );
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
    fn a_node_of_another_platform_is_refused_by_name_and_skipped_for_all() {
        let paths = setup("");
        let err = format!(
            "{:#}",
            paths.generate(Some("router1"), true, false).unwrap_err()
        );
        assert!(err.contains("router1") && err.contains("routeros"), "{err}");
        paths.generate(None, false, false).unwrap();
        assert!(paths.patch("a").is_some());
        assert!(paths.patch("router1").is_none());
    }

    #[test]
    fn a_patch_talos_could_not_key_is_refused_in_every_mode_and_nothing_is_written() {
        for (check, diff) in MODES {
            let paths = setup(
                "---\nslipmesh:\n  kind: patch\n  platform: talos\nmachine:\n  install: {disk: /dev/vda}\n",
            );
            let before = paths.snapshot();
            let err = format!("{:#}", paths.generate(None, check, diff).unwrap_err());
            assert!(err.contains("has no Talos `kind`"), "{err}");
            assert!(
                err.starts_with(&format!("reading {}", paths.config.display())),
                "{err}"
            );
            assert_eq!(paths.snapshot(), before);
        }
    }

    #[test]
    fn a_file_in_which_no_document_sets_a_template_is_refused_in_every_mode_naming_template() {
        let router = defaults::document(defaults::Service::Router);
        let firewall = defaults::document(defaults::Service::Firewall);
        for (lacking, present) in [("firewall", &router), ("router", &firewall)] {
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
    fn a_refusal_of_one_node_names_it_and_its_document_and_changes_no_patch_file() {
        let paths = setup("");
        paths.generate(None, false, false).unwrap();
        let router = defaults::document(defaults::Service::Router);
        let firewall = defaults::document(defaults::Service::Firewall)
            .replace("  platform: talos\n", "  platform: talos\n  exclude: [b]\n");
        let head = format!("{}---\n{router}---\n{firewall}", *SLIPMESH);
        let line = head.lines().count() + 2;
        std::fs::write(
            &paths.config,
            format!(
                "{head}---\nslipmesh: {{kind: patch, platform: talos}}\napiVersion: v1alpha1\nkind: \
                 ExtensionServiceConfig\nname: nftables\nconfigFiles:\n  - mountPath: \
                 /etc/talos-extensions/extra.conf\n    content: x\n"
            ),
        )
        .unwrap();
        for (check, diff) in MODES {
            let before = paths.snapshot();
            let err = paths.generate(None, check, diff).unwrap_err();
            assert_eq!(
                format!("{err:#}"),
                format!(
                    "node \"b\": the `kind: patch` document at line {line}: adds files to \
                     `nftables`, which no `template` document for the firewall reaches on this \
                     node, so it gets no `nftables` document - aim the `patch` or a template so \
                     that both reach the node or neither"
                )
            );
            assert_eq!(paths.snapshot(), before);
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
        let metrics =
            "---\nslipmesh: {kind: platform, platform: talos}\nmetrics: {mesh: {port: 0}}\n";
        let err = setup(metrics).generate(None, true, false).unwrap_err();
        let err = format!("{err:#}");
        let router = defaults::document(defaults::Service::Router);
        let firewall = defaults::document(defaults::Service::Firewall);
        let line = format!("{}---\n{router}---\n{firewall}", *SLIPMESH)
            .lines()
            .count()
            + 2;
        assert!(
            err.contains(&format!(
                "the `kind: platform` document at line {line}: metrics.mesh.port: invalid value"
            )),
            "{line}: {err}"
        );
        assert!(!err.contains("slipmesh mint"), "{err}");
    }

    #[test]
    fn files_without_the_interface_prefix_are_refused_in_every_mode_naming_mint() {
        let network = SLIPMESH.replace("  interface_prefix: mesh-\n", "");
        assert_ne!(network, *SLIPMESH);
        for (check, diff) in MODES {
            let paths = setup_from(&network, "");
            let before = paths.snapshot();
            let err = format!("{:#}", paths.generate(None, check, diff).unwrap_err());
            for named in ["mesh.interface_prefix", "`slipmesh mint`"] {
                assert!(err.contains(named), "{named}: {err}");
            }
            assert_eq!(paths.snapshot(), before);
        }
    }

    #[test]
    fn a_missing_interface_prefix_is_refused_before_a_talos_body_that_does_not_read() {
        let network = SLIPMESH.replace("  interface_prefix: mesh-\n", "");
        let paths = setup_from(
            &network,
            "---\nslipmesh: {kind: platform, platform: talos}\nlisten: true\n",
        );
        let err = format!("{:#}", paths.generate(None, false, false).unwrap_err());
        assert!(err.contains("mesh.interface_prefix"), "{err}");
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
            let files = read_slipmesh(&paths.config).unwrap();
            let network = Mesh::of(&files).unwrap();
            let settings = TalosSettings::of(&files).unwrap();
            render_hosts(
                &files,
                &network,
                &settings,
                &["a", "b", "c", "d"],
                &paths.patches,
            )
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
            "---\nslipmesh: {kind: template, platform: talos, include: [d]}\ndaemon: firewall\nbase: \
             sha256:0000000000000000000000000000000000000000000000000000000000000000\ncontent: |\n  \
             table inet t { {{ bogus }} }\n",
        );
        let err = paths.generate(None, false, false).unwrap_err();
        assert!(format!("{err:#}").contains("\"d\""), "{err:#}");
        for host in ["a", "b", "c", "d", "router1"] {
            assert!(paths.patch(host).is_none(), "{host} was written");
        }
    }

    #[test]
    fn generate_rejects_an_unknown_node() {
        let paths = setup("");
        let err = paths
            .generate(Some("nonexistent"), false, false)
            .unwrap_err();
        assert_eq!(format!("{err:#}"), "unknown node \"nonexistent\"");
    }
}
