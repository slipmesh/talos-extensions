//! The files a daemon cannot run without and `slipmesh.yaml` gives it - its template - with the
//! reference each one starts from. `generate` writes the reference into `slipmesh.yaml` where the
//! file is missing; from then on the copy there is the one in force, edited like any other document.

use crate::slipmesh_file::SlipmeshFile;

pub struct DefaultFile {
    /// The `ExtensionServiceConfig` the file belongs to.
    pub service: &'static str,
    pub mount_path: &'static str,
    pub content: &'static str,
}

pub const DEFAULT_FILES: [DefaultFile; 2] = [
    DefaultFile {
        service: "router",
        mount_path: router::bird_conf::TEMPLATE_PATH,
        content: router::bird_conf::REFERENCE_TEMPLATE,
    },
    DefaultFile {
        service: "nftables",
        mount_path: nftables::template::TEMPLATE_PATH,
        content: nftables::template::REFERENCE_TEMPLATE,
    },
];

/// The default files no `patch` document in `file` sets for any host.
///
/// A file set for some hosts only is not missing: who goes without it was decided by whoever
/// aimed that document, and a default for everyone would undo the decision. Going without a
/// router template is refused when the patch files are rendered, since `router` cannot run.
pub fn missing(file: &SlipmeshFile) -> Vec<&'static DefaultFile> {
    DEFAULT_FILES
        .iter()
        .filter(|d| !file.sets_file(d.service, d.mount_path))
        .collect()
}

/// `text` with a document for each of `defaults` added at its end.
pub fn append(text: &str, defaults: &[&DefaultFile]) -> String {
    let mut out = text.to_owned();
    if !out.is_empty() && !out.ends_with('\n') {
        out.push('\n');
    }
    for default in defaults {
        out.push_str("---\n");
        out.push_str(&document(default));
    }
    out
}

/// A `patch` document for every host, the content written as a literal block so that it reads in
/// `slipmesh.yaml` the way it reads in the file it becomes.
fn document(default: &DefaultFile) -> String {
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
  loopback_networks: {ipv4: "10.62.0.0/16", ipv6: "fd00:62::/32"}
nodes:
  - {name: node-a, node_id: "10.62.0.1"}
  - {name: node-b, node_id: "10.62.0.2"}
"#;

    fn file_content(document: &yaml_serde::Value, mount_path: &str) -> Option<String> {
        document["configFiles"]
            .as_sequence()?
            .iter()
            .find(|f| f["mountPath"].as_str() == Some(mount_path))
            .and_then(|f| f["content"].as_str())
            .map(str::to_owned)
    }

    #[test]
    fn a_file_without_them_misses_every_default() {
        let file = SlipmeshFile::parse(NETWORK).unwrap();
        let services: Vec<&str> = missing(&file).iter().map(|d| d.service).collect();
        assert_eq!(services, ["router", "nftables"]);
    }

    #[test]
    fn the_appended_documents_reach_every_host_with_the_reference_text() {
        let text = append(NETWORK, &missing(&SlipmeshFile::parse(NETWORK).unwrap()));
        let file = SlipmeshFile::parse(&text).unwrap();
        assert!(missing(&file).is_empty());
        for host in ["node-a", "node-b"] {
            let documents = file.patches_for(host).unwrap();
            for default in &DEFAULT_FILES {
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

    #[test]
    fn a_file_set_for_some_hosts_only_is_not_missing() {
        let nftables = format!(
            "---\nslipmesh:\n  kind: patch\n  exclude: [node-b]\napiVersion: v1alpha1\nkind: ExtensionServiceConfig\nname: nftables\nconfigFiles:\n  - mountPath: {}\n    content: \"table inet t {{}}\\n\"\n",
            nftables::template::TEMPLATE_PATH
        );
        let file = SlipmeshFile::parse(&format!("{NETWORK}{nftables}")).unwrap();
        let services: Vec<&str> = missing(&file).iter().map(|d| d.service).collect();
        assert_eq!(services, ["router"]);
    }
}
