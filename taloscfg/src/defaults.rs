//! The reference template of each daemon that takes one. A template reaches a node from a
//! `template` document of the files; the reference is what such a document starts from.

use sliplib_config::v2::platform::Daemon;
use sliplib_config::v2::{Error, File};

/// A daemon with a reference template, as the `template` command and a `template` document name
/// it. `firewall` is the daemon of the `nftables` service: this is the one place the two names
/// meet.
#[derive(Clone, Copy, Debug, PartialEq, Eq, clap::ValueEnum)]
pub enum Service {
    Router,
    Firewall,
}

impl Service {
    pub fn of(daemon: Daemon) -> Self {
        match daemon {
            Daemon::Router => Self::Router,
            Daemon::Firewall => Self::Firewall,
        }
    }

    /// The `ExtensionServiceConfig` the template is a file of.
    pub const fn name(self) -> &'static str {
        match self {
            Self::Router => "router",
            Self::Firewall => "nftables",
        }
    }

    /// Where the daemon reads its template.
    pub const fn mount_path(self) -> &'static str {
        match self {
            Self::Router => router::bird_conf::TEMPLATE_PATH,
            Self::Firewall => nftables::template::TEMPLATE_PATH,
        }
    }

    /// The text of the current reference template.
    pub fn reference(self) -> &'static str {
        match self {
            Self::Router => router::bird_conf::REFERENCE_TEMPLATE,
            Self::Firewall => nftables::template::REFERENCE_TEMPLATE,
        }
    }

    /// The 64 lower-case hexadecimal digits of the SHA-256 of the reference's text, the digits a
    /// template made from it names in its `base`.
    pub fn digest(self) -> String {
        crate::text::sha256_hex(self.reference())
    }

    /// What a template made from the current reference names as its `base`: `sha256:` and the
    /// [`Service::digest`].
    pub fn base(self) -> String {
        format!("sha256:{}", self.digest())
    }

    /// A unified diff from `text`, this daemon's template in the files, to the current reference,
    /// `None` when they are the same.
    pub fn differences_from_reference(self, text: &str) -> Option<String> {
        (text != self.reference()).then(|| {
            crate::text::unified_diff(
                text,
                self.reference(),
                &format!("the {self} template in the files"),
                &format!("the current reference {self} template"),
            )
        })
    }
}

/// Reads as the `daemon` of a `template` document and the word the `template` command takes.
impl std::fmt::Display for Service {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Router => "router",
            Self::Firewall => "firewall",
        })
    }
}

/// The daemons for which no `template` document stands in `files` at all. A `template` document
/// whose keys do not read is refused here, naming it, rather than counted as no template.
///
/// A template for some nodes only is not missing: who goes without it was decided by whoever
/// aimed that document. A node no router template reaches is refused when its patch file is
/// rendered, since `router` cannot run.
pub fn missing(files: &File) -> Result<Vec<Service>, Error> {
    let written = files
        .templates()
        .iter()
        .map(|template| Ok(Service::of(template.read()?.daemon)))
        .collect::<Result<Vec<Service>, Error>>()?;
    Ok([Service::Router, Service::Firewall]
        .into_iter()
        .filter(|service| !written.contains(service))
        .collect())
}

/// The `template` document that gives every node of `talos` the reference template of
/// `service`, `base` included, to add to the files and edit there. The content is written as a
/// literal block so that it reads in the files the way it reads in the file it becomes.
pub fn document(service: Service) -> String {
    let content: String = service
        .reference()
        .lines()
        .map(|line| match line {
            "" => "\n".to_owned(),
            line => format!("  {line}\n"),
        })
        .collect();
    format!(
        "slipmesh:\n  kind: template\n  platform: talos\ndaemon: {service}\nbase: {}\ncontent: |\n{content}",
        service.base()
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    const NETWORK: &str = r#"slipmesh: {kind: network, version: 2, revision: 1}
addressing: {loopback: {ipv4: 198.51.100.0/25, ipv6: "3fff::/64"}}
routing: {bgp: {as: 64512}}
mesh: {interface_prefix: mesh-}
nodes:
  node-a: {platform: talos, node_id: 0.0.0.1, underlay: {wan: {}}}
  node-b: {platform: talos, node_id: 0.0.0.2, underlay: {wan: {}}}
"#;

    fn missing_in(documents: &[&str]) -> Vec<Service> {
        let text = std::iter::once(NETWORK)
            .chain(documents.iter().copied())
            .collect::<Vec<_>>()
            .join("---\n");
        missing(&File::parse(&text).unwrap()).unwrap()
    }

    #[test]
    fn files_without_templates_miss_both() {
        assert_eq!(missing_in(&[]), [Service::Router, Service::Firewall]);
    }

    #[test]
    fn a_template_that_does_not_read_is_refused_naming_it_not_counted_as_missing() {
        let reference = document(Service::Firewall);
        let short_base = reference.replace(&Service::Firewall.base(), "sha256:abc");
        let unknown_key = reference.replace("content: |", "contnet: |");
        for broken in [short_base, unknown_key] {
            let text = format!("{NETWORK}---\n{broken}");
            let err = missing(&File::parse(&text).unwrap()).unwrap_err();
            assert!(
                err.to_string()
                    .contains("`kind: template` document at line 9"),
                "{err:#}"
            );
        }
    }

    #[test]
    fn a_template_for_some_nodes_only_is_not_missing() {
        let firewall = document(Service::Firewall).replace(
            "  platform: talos\n",
            "  platform: talos\n  exclude: [node-b]\n",
        );
        assert_eq!(missing_in(&[&firewall]), [Service::Router]);
    }

    #[test]
    fn a_daemons_document_gives_every_node_its_reference_template_and_names_its_base() {
        for service in [Service::Router, Service::Firewall] {
            let text = format!("{NETWORK}---\n{}", document(service));
            let files = File::parse(&text).unwrap();
            for node in ["node-a", "node-b"] {
                let [reaching] = files.templates_for(node).try_into().unwrap();
                let template = reaching.read().unwrap();
                assert_eq!(Service::of(template.daemon), service, "{node}");
                assert_eq!(template.content, service.reference(), "{node}: {service}");
                assert_eq!(template.base.digest(), service.digest(), "{service}");
            }
        }
    }

    #[test]
    fn a_daemon_reads_as_the_word_the_files_and_the_command_take() {
        assert_eq!(Service::Router.to_string(), "router");
        assert_eq!(Service::Firewall.to_string(), "firewall");
        assert_eq!(Service::Router.name(), "router");
        assert_eq!(Service::Firewall.name(), "nftables");
    }

    // Pinned: a change of a reference changes its digest on purpose, and the digest is of the
    // bytes as they are, line endings included.
    #[test]
    fn the_digest_of_each_reference_is_pinned() {
        assert_eq!(
            Service::Router.digest(),
            "37259e51772ccc05ce786974fc2f86c4e00f788f63a5cdf192ae93508c633bb0"
        );
        assert_eq!(
            Service::Firewall.digest(),
            "338c55f97281e90a7464f1bd6cb5f8fa4f750ff99e21d878cc0301688467f4e5"
        );
        assert_eq!(
            Service::Router.base(),
            format!("sha256:{}", Service::Router.digest())
        );
    }

    #[test]
    fn a_text_differs_from_the_reference_under_the_daemons_name() {
        let reference = Service::Firewall.reference();
        assert_eq!(
            Service::Firewall.differences_from_reference(reference),
            None
        );
        let edited = format!("{reference}# added by hand\n");
        let diff = Service::Firewall
            .differences_from_reference(&edited)
            .unwrap();
        assert!(
            diff.starts_with(
                "--- the firewall template in the files\n+++ the current reference firewall \
                 template\n"
            ),
            "{diff}"
        );
        assert!(diff.ends_with("\n-# added by hand\n"), "{diff}");
    }
}
