//! The reference template of each service that takes one. A template reaches a node only as a
//! `patch` document of `slipmesh.yaml`; the reference is what such a document starts from.

use sha2::{Digest, Sha256};
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
}

impl Service {
    /// The text of the current reference template.
    pub fn reference(self) -> &'static str {
        self.file().content
    }

    /// What a template made from the current reference names as its `base`: `sha256:` and the
    /// 64 lower-case hexadecimal digits of the SHA-256 of the reference's text.
    pub fn base(self) -> String {
        format!("sha256:{}", digest(self.reference()))
    }

    /// A unified diff from `text` to the current reference, `None` when they are the same.
    pub fn differences_from_reference(self, text: &str) -> Option<String> {
        (text != self.reference()).then(|| {
            similar::TextDiff::from_lines(text, self.reference())
                .unified_diff()
                .header("the template in the files", "the current reference")
                .to_string()
        })
    }
}

/// The SHA-256 of `text`, as 64 lower-case hexadecimal digits.
fn digest(text: &str) -> String {
    Sha256::digest(text)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
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

    // The text's bytes as they are, digested and written in lower case.
    #[test]
    fn a_digest_is_the_sha_256_of_the_text_in_lower_case_hexadecimal() {
        assert_eq!(
            digest("abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn the_base_of_a_reference_is_sha_256_and_its_64_digits() {
        for service in [Service::Router, Service::Nftables] {
            let base = service.base();
            let digits = base
                .strip_prefix("sha256:")
                .unwrap_or_else(|| panic!("{base}"));
            assert_eq!(digits, digest(service.reference()), "{service}");
        }
        assert_ne!(Service::Router.base(), Service::Nftables.base());
    }

    #[test]
    fn a_text_differs_from_the_reference_by_the_lines_it_changes() {
        let reference = Service::Router.reference();
        assert_eq!(Service::Router.differences_from_reference(reference), None);
        let edited = format!("{reference}# added by hand\n");
        let diff = Service::Router.differences_from_reference(&edited).unwrap();
        assert!(diff.contains("--- the template in the files"), "{diff}");
        assert!(diff.contains("+++ the current reference"), "{diff}");
        assert!(diff.contains("\n-# added by hand\n"), "{diff}");
        assert!(
            !diff
                .lines()
                .any(|line| line.starts_with('+') && !line.starts_with("+++")),
            "{diff}"
        );
    }
}
