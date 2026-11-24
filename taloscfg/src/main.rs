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
        let template: Template = document.read()?;
        let service = template.daemon;
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
    // A node no firewall template reaches gets no ruleset; one no router template reaches is
    // refused on its own.
    anyhow::ensure!(
        defaults::has_firewall_template(&files).with_context(reading)?,
        "{} gives no node a firewall template - `slipmesh-taloscfg template firewall` prints the \
         document to add",
        config_path.display()
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

    std::fs::create_dir_all(patches_dir)
        .with_context(|| format!("creating {}", patches_dir.display()))?;
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
            d = key(),
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
    fn a_refused_file_is_refused_in_every_mode_naming_what_cures_it_and_nothing_is_written() {
        let without = |part: &str, put: &str| {
            assert!(SLIPMESH.contains(part), "{part}");
            SLIPMESH.replace(part, put)
        };
        let key_of_a = format!("wireguard: {{private_key: \"{}\"}}", *KEY_OF_A);
        let key_of_a_is_not_set = "node \"a\": wireguard.private_key is not set";
        let router = defaults::document(defaults::Service::Router);
        let firewall = defaults::document(defaults::Service::Firewall);
        /// What a refusal holds besides its name of the defect.
        enum Also {
            /// One line, ending in the command that cures it.
            Minted,
            /// The file it read.
            Reading,
            Nothing,
        }
        // The file, the node asked for, what the refusal names, and what else it holds.
        let cases = [
            (
                setup_from(&without(&key_of_a, "wireguard: null"), ""),
                Some("a"),
                key_of_a_is_not_set.to_owned(),
                Also::Minted,
            ),
            (
                setup_from(&without(&key_of_a, "wireguard: null"), ""),
                Some("b"),
                key_of_a_is_not_set.to_owned(),
                Also::Minted,
            ),
            (
                setup_from(&without(OBFUSCATION, ""), ""),
                Some("a"),
                "mesh link a-b: obfuscation lacks".to_owned(),
                Also::Minted,
            ),
            (
                setup(
                    "---\nslipmesh:\n  kind: patch\n  platform: talos\nmachine:\n  install: \
                     {disk: /dev/vda}\n",
                ),
                None,
                "has no Talos `kind`".to_owned(),
                Also::Reading,
            ),
            (
                setup(
                    "---\nslipmesh: {kind: platform, platform: talos}\nmetrics: {mesh: {port: 0}}\n",
                ),
                None,
                "metrics.mesh.port: invalid value".to_owned(),
                Also::Reading,
            ),
            (
                holding(&format!("{}---\n{router}", *SLIPMESH)),
                None,
                "`slipmesh-taloscfg template firewall`".to_owned(),
                Also::Nothing,
            ),
            (
                holding(&format!("{}---\n{firewall}", *SLIPMESH)),
                None,
                "`slipmesh-taloscfg template router`".to_owned(),
                Also::Nothing,
            ),
        ];
        for (paths, node, named, also) in cases {
            let before = paths.snapshot();
            for (check, diff) in MODES {
                let err = paths.generate(node, check, diff).unwrap_err();
                let shown = format!("{err:#}");
                assert!(shown.contains(&named), "{named}: {shown}");
                match also {
                    Also::Minted => {
                        // `main` prints it with `{:?}`, on one line only without causes.
                        assert_eq!(err.chain().count(), 1, "{named}: {err:?}");
                        assert!(
                            shown.ends_with(" - `slipmesh mint` creates it"),
                            "{named}: {shown}"
                        );
                    }
                    Also::Reading => assert!(
                        shown.starts_with(&format!("reading {}", paths.config.display())),
                        "{named}: {shown}"
                    ),
                    Also::Nothing => {}
                }
                assert_eq!(paths.snapshot(), before, "{named}");
            }
        }
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
    fn a_dry_run_writes_no_patch_file() {
        for (check, diff) in [(true, false), (false, true)] {
            let paths = setup("");
            paths.generate(None, check, diff).unwrap();
            assert!(!paths.patches.exists());
        }
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
}
