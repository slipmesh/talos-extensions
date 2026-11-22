//! The reference template of each service that takes one. A template reaches a node only as a
//! `patch` document of `slipmesh.yaml`; the reference is what such a document starts from.

use sliplib_config::slipmesh_file::SlipmeshFile;

struct DefaultFile {
    /// The `ExtensionServiceConfig` the file belongs to.
    service: &'static str,
    mount_path: &'static str,
    content: &'static str,
}

/// A service with a reference template.
#[derive(Clone, Copy, Debug, clap::ValueEnum)]
pub enum Service {
    Router,
    Nftables,
}

impl Service {
    fn file(self) -> DefaultFile {
        match self {
            Service::Router => DefaultFile {
                service: "router",
                mount_path: router::bird_conf::TEMPLATE_PATH,
                content: router::bird_conf::REFERENCE_TEMPLATE,
            },
            Service::Nftables => DefaultFile {
                service: "nftables",
                mount_path: nftables::template::TEMPLATE_PATH,
                content: nftables::template::REFERENCE_TEMPLATE,
            },
        }
    }

    /// The text of the current reference template.
    pub fn reference(self) -> &'static str {
        self.file().content
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

impl std::fmt::Display for Service {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.file().service)
    }
}

/// The services whose template no `patch` document of `file` sets, for any host.
///
/// A template set for some hosts only is not missing: who goes without it was decided by whoever
/// aimed that document. Going without a router template is refused when the patch files are
/// rendered, since `router` cannot run.
pub fn missing(file: &SlipmeshFile) -> Vec<Service> {
    [Service::Router, Service::Nftables]
        .into_iter()
        .filter(|service| {
            let default = service.file();
            !crate::patches::sets_file(file, default.service, default.mount_path)
        })
        .collect()
}

/// The `patch` document that gives every host the reference template of `service`, to add to
/// `slipmesh.yaml` and edit there. The content is written as a literal block so that it reads in
/// `slipmesh.yaml` the way it reads in the file it becomes.
pub fn document(service: Service) -> String {
    let default = service.file();
    let content: String = default
        .content
        .lines()
        .map(|line| match line {
            "" => "\n".to_owned(),
            line => format!("      {line}\n"),
        })
        .collect();
    format!(
        "slipmesh:\n  kind: patch\napiVersion: v1alpha1\nkind: ExtensionServiceConfig\nname: {}\nconfigFiles:\n  - mountPath: {}\n    content: |\n{content}",
        default.service, default.mount_path
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    const NETWORK: &str = r#"slipmesh:
  kind: network
cluster:
  bgp_as: 64512
  loopback_networks: {ipv4: "198.51.100.0/25", ipv6: "3fff::/32"}
nodes:
  - {name: node-a, node_id: "198.51.100.1"}
  - {name: node-b, node_id: "198.51.100.2"}
"#;

    fn file_content(document: &sliplib_yaml::Value, mount_path: &str) -> Option<String> {
        document["configFiles"]
            .as_sequence()?
            .iter()
            .find(|f| f["mountPath"].as_str() == Some(mount_path))
            .and_then(|f| f["content"].as_str())
            .map(str::to_owned)
    }

    fn missing_in(text: &str) -> Vec<String> {
        missing(&SlipmeshFile::parse(text).unwrap())
            .iter()
            .map(Service::to_string)
            .collect()
    }

    #[test]
    fn a_file_without_them_misses_every_default() {
        assert_eq!(missing_in(NETWORK), ["router", "nftables"]);
    }

    #[test]
    fn a_file_set_for_some_hosts_only_is_not_missing() {
        let nftables = format!(
            "---\nslipmesh:\n  kind: patch\n  exclude: [node-b]\napiVersion: v1alpha1\nkind: ExtensionServiceConfig\nname: nftables\nconfigFiles:\n  - mountPath: {}\n    content: \"table inet t {{}}\\n\"\n",
            nftables::template::TEMPLATE_PATH
        );
        assert_eq!(missing_in(&format!("{NETWORK}{nftables}")), ["router"]);
    }

    #[test]
    fn a_services_document_gives_every_host_its_reference_template() {
        for service in [Service::Router, Service::Nftables] {
            let default = service.file();
            let text = format!("{NETWORK}---\n{}", document(service));
            let file = SlipmeshFile::parse(&text).unwrap();
            for host in ["node-a", "node-b"] {
                let documents = crate::patches::for_host(&file, host).unwrap();
                let document = documents
                    .iter()
                    .find(|d| d.identity == format!("ExtensionServiceConfig/{}", default.service))
                    .unwrap_or_else(|| panic!("{host}: no {} document", default.service));
                assert_eq!(
                    file_content(&document.value, default.mount_path).as_deref(),
                    Some(default.content),
                    "{host}: {}",
                    default.service
                );
            }
        }
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
            Service::Nftables.digest(),
            "338c55f97281e90a7464f1bd6cb5f8fa4f750ff99e21d878cc0301688467f4e5"
        );
        assert_eq!(
            Service::Router.base(),
            format!("sha256:{}", Service::Router.digest())
        );
    }

    #[test]
    fn a_text_differs_from_the_reference_under_the_daemons_name() {
        let reference = Service::Router.reference();
        assert_eq!(Service::Router.differences_from_reference(reference), None);
        let edited = format!("{reference}# added by hand\n");
        let diff = Service::Router.differences_from_reference(&edited).unwrap();
        assert!(
            diff.starts_with(
                "--- the router template in the files\n+++ the current reference router template\n"
            ),
            "{diff}"
        );
        assert!(diff.ends_with("\n-# added by hand\n"), "{diff}");
    }
}
