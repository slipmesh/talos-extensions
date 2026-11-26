//! The reference template of each daemon that takes one. A template reaches a node from a
//! `template` document of the files; the reference is what such a document starts from, and what
//! a node that none reaches gets.

/// A daemon with a reference template, as the `template` command and a `template` document name
/// it. `firewall` is the daemon of the `nftables` service: this is the one place the two names
/// meet.
#[derive(Clone, Copy, Debug, PartialEq, Eq, clap::ValueEnum, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Service {
    Router,
    Firewall,
}

impl Service {
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
    use crate::documents::Template;
    use sliplib_config::v2::File;

    const NETWORK: &str = r#"slipmesh: {kind: network, version: 2, revision: 1}
addressing: {loopback: {ipv4: 198.51.100.0/25, ipv6: "3fff::/64"}}
routing: {bgp: {as: 64496}}
mesh: {interface_prefix: mesh-}
nodes:
  node-a: {platform: talos, node_id: 0.0.0.1, underlay: {wan: {}}}
  node-b: {platform: talos, node_id: 0.0.0.2, underlay: {wan: {}}}
"#;

    #[test]
    fn a_daemons_document_gives_every_node_its_reference_template_and_names_its_base() {
        for service in [Service::Router, Service::Firewall] {
            let text = format!("{NETWORK}---\n{}", document(service));
            let files = File::parse(&text).unwrap();
            for node in ["node-a", "node-b"] {
                let [reaching] = files.templates_for(node).try_into().unwrap();
                let template: Template = reaching.read().unwrap();
                assert_eq!(template.daemon, service, "{node}");
                assert_eq!(template.content, service.reference(), "{node}: {service}");
                assert_eq!(template.base.digest(), service.digest(), "{service}");
            }
        }
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
