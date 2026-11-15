//! The reference template of each service that takes one. A template reaches a node only as a
//! `patch` document of `slipmesh.yaml`; the reference is what such a document starts from.

pub struct DefaultFile {
    /// The `ExtensionServiceConfig` the file belongs to.
    pub service: &'static str,
    pub mount_path: &'static str,
    pub content: &'static str,
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
    use sliplib_config::slipmesh_file::SlipmeshFile;

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

    #[test]
    fn a_services_document_gives_every_host_its_reference_template() {
        for service in [Service::Router, Service::Nftables] {
            let default = service.file();
            let text = format!("{NETWORK}---\n{}", document(service));
            let file = SlipmeshFile::parse(&text).unwrap();
            for host in ["node-a", "node-b"] {
                let documents = file.patches_for(host).unwrap();
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
}
