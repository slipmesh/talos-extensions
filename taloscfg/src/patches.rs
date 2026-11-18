//! The `patch` documents of `slipmesh.yaml` as Talos documents: checked as far as the generator
//! knows them, and merged into what one host gets.

use anyhow::{Context, Result, bail, ensure};
use sliplib_config::slipmesh_file::{Patch, SlipmeshFile};
use sliplib_config::talos::{self, Identity};
use sliplib_yaml::Value;

/// The `ExtensionServiceConfig`s generated from the network, by name, with the file each one
/// mounts. Talos keeps `name` unique per `kind`, so a `patch` document of one of these names is
/// that same document: it may add files to it, and nothing else - not the generated file itself.
pub(crate) const GENERATED: [(&str, &str); 2] = [
    ("awg", "/etc/talos-extensions/awg.yaml"),
    ("router", "/etc/talos-extensions/router.yaml"),
];

/// One Talos document as it goes into one host's patch file, serialized - its comments stay in
/// `slipmesh.yaml`.
#[derive(Debug, PartialEq)]
pub(crate) struct HostDocument {
    /// `kind`, plus `/name` when the document has one.
    pub identity: String,
    pub text: String,
    /// What `text` serializes - for a caller that reads its fields.
    pub value: Value,
}

/// Refuses a `patch` document Talos could not key, and one that sets more on a generated document
/// than files beside the generated one.
pub fn check(file: &SlipmeshFile) -> Result<()> {
    file.patches().iter().try_for_each(check_one)
}

fn check_one(patch: &Patch) -> Result<()> {
    let identity = Identity::of(patch.value());
    let Some(kind) = &identity.kind else {
        bail!("{patch}: has no Talos `kind`, so it has no identity to merge by");
    };
    if let Some(name) = &identity.name
        && kind == "ExtensionServiceConfig"
        && let Some((_, generated)) = GENERATED.iter().find(|(n, _)| n == name)
    {
        let others: Vec<&str> = patch
            .value()
            .as_mapping()
            .into_iter()
            .flatten()
            .filter_map(|(key, _)| key.as_str())
            .filter(|key| !["apiVersion", "kind", "name", "configFiles"].contains(key))
            .collect();
        ensure!(
            others.is_empty(),
            "{patch}: `ExtensionServiceConfig` {name:?} is generated from the network - a patch \
             may add `configFiles` to it and nothing else, not {others:?}"
        );
        let over_generated = patch
            .value()
            .get("configFiles")
            .and_then(Value::as_sequence)
            .into_iter()
            .flatten()
            .any(|f| f.get("mountPath").and_then(Value::as_str) == Some(generated));
        ensure!(
            !over_generated,
            "{patch}: {generated} is the file generated for {name:?} - add files next to it, not \
             over it"
        );
    }
    Ok(())
}

/// The Talos documents that go into `host`'s patch file, in the order their identities first
/// appear.
///
/// Documents of one identity are merged in the order of their rank, so the more specific document
/// wins wherever it sits in the file.
pub(crate) fn for_host(file: &SlipmeshFile, host: &str) -> Result<Vec<HostDocument>> {
    let reaching = file.patches_for(host)?;

    let mut identities: Vec<Identity> = Vec::new();
    for patch in &reaching {
        let identity = Identity::of(patch.value());
        if !identities.contains(&identity) {
            identities.push(identity);
        }
    }

    identities
        .into_iter()
        .map(|identity| {
            let mut sources: Vec<&Patch> = reaching
                .iter()
                .filter(|p| Identity::of(p.value()) == identity)
                .copied()
                .collect();
            sources.sort_by_key(|patch| patch.rank());
            let [first, rest @ ..] = sources.as_slice() else {
                unreachable!("every identity comes from at least one document")
            };
            let mut document = rest.iter().fold(first.value().clone(), |base, patch| {
                talos::merge(base, patch.value())
            });
            talos::contents_as_text(&mut document)?;
            let text =
                sliplib_yaml::to_string(&document).context("serializing a patch document")?;
            Ok(HostDocument {
                identity: identity.to_string(),
                text,
                value: document,
            })
        })
        .collect()
}

/// Whether a `patch` document, for whichever hosts, sets the file `mount_path` of
/// `ExtensionServiceConfig` `service`.
pub(crate) fn sets_file(file: &SlipmeshFile, service: &str, mount_path: &str) -> bool {
    file.patches()
        .iter()
        .any(|p| talos::sets_file(p.value(), service, mount_path))
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
  - {name: node-c, node_id: "198.51.100.3"}
"#;

    const KUBELET: &str = r#"slipmesh:
  kind: patch
apiVersion: v1alpha1
kind: KubeletConfig
extraArgs:
    rotate-server-certificates: "true"
"#;

    fn file(documents: &[&str]) -> String {
        documents.join("---\n")
    }

    fn parse(documents: &[&str]) -> SlipmeshFile {
        SlipmeshFile::parse(&file(documents)).unwrap()
    }

    fn error(documents: &[&str]) -> String {
        match check(&parse(documents)) {
            Ok(()) => panic!("checked, but should have been refused"),
            Err(err) => format!("{err:#}"),
        }
    }

    const DEVICE: &str = "slipmesh:\n  kind: patch\n  include: [node-b]\n# the device the converger talks to\napiVersion: v1alpha1\nkind: ExtensionServiceConfig\nname: device\nconfigFiles:\n  - mountPath: /etc/device.yaml\n    content:\n      host: router1.example.com\n      port: 8729\n      username: admin\n      password: hunter2   # the one secret here\n";

    /// A `configFiles[].content` in `text`.
    fn content(text: &str, index: usize) -> sliplib_yaml::Value {
        let value: sliplib_yaml::Value = sliplib_yaml::from_str(text).unwrap();
        value["configFiles"][index]["content"].clone()
    }

    #[test]
    fn a_content_mapping_goes_out_as_the_text_of_that_yaml() {
        let parsed = parse(&[NETWORK, DEVICE]);
        let text = &for_host(&parsed, "node-b").unwrap()[0].text;
        assert_eq!(
            content(text, 0).as_str(),
            Some("host: router1.example.com\nport: 8729\nusername: admin\npassword: hunter2\n"),
            "{text}"
        );
    }

    #[test]
    fn a_content_ending_in_blank_lines_keeps_them() {
        let patch = "slipmesh:\n  kind: patch\napiVersion: v1alpha1\nkind: ExtensionServiceConfig\nname: script\nconfigFiles:\n  - mountPath: /etc/script\n    content: \"run\\n\\n\\n\"\n";
        let parsed = parse(&[NETWORK, patch]);
        let text = &for_host(&parsed, "node-a").unwrap()[0].text;
        assert_eq!(content(text, 0).as_str(), Some("run\n\n\n"), "{text}");
    }

    #[test]
    fn a_content_mapping_goes_out_as_text_after_a_merge_too() {
        let default = "slipmesh:\n  kind: patch\napiVersion: v1alpha1\nkind: ExtensionServiceConfig\nname: device\nconfigFiles:\n  - mountPath: /etc/device.yaml\n    content:\n      host: router0.example.com\n";
        let parsed = parse(&[NETWORK, default, DEVICE]);
        let documents = for_host(&parsed, "node-b").unwrap();
        assert_eq!(
            content(&documents[0].text, 0).as_str(),
            Some("host: router1.example.com\nport: 8729\nusername: admin\npassword: hunter2\n")
        );
        assert_eq!(
            content(&for_host(&parsed, "node-a").unwrap()[0].text, 0).as_str(),
            Some("host: router0.example.com\n")
        );
    }

    #[test]
    fn patches_of_one_identity_merge_with_the_included_one_over_the_default() {
        let host = "slipmesh:\n  kind: patch\n  include: [node-a]\napiVersion: v1alpha1\nkind: KubeletConfig\nextraArgs:\n    v: \"4\"\n";
        // The host document comes first in the file and still lands on top.
        let parsed = parse(&[NETWORK, host, KUBELET]);

        let merged = for_host(&parsed, "node-a").unwrap();
        assert_eq!(merged.len(), 1);
        let value: sliplib_yaml::Value = sliplib_yaml::from_str(&merged[0].text).unwrap();
        assert_eq!(value["extraArgs"]["v"].as_str(), Some("4"));
        assert_eq!(
            value["extraArgs"]["rotate-server-certificates"].as_str(),
            Some("true")
        );
    }

    #[test]
    fn of_two_patches_of_one_identity_and_one_rank_the_later_in_the_file_wins() {
        let later = KUBELET.replace("\"true\"", "\"false\"");
        let parsed = parse(&[NETWORK, KUBELET, &later]);
        let merged = for_host(&parsed, "node-a").unwrap();
        assert_eq!(merged.len(), 1);
        assert_eq!(
            merged[0].value["extraArgs"]["rotate-server-certificates"].as_str(),
            Some("false")
        );

        let named = |value: &str| {
            KUBELET
                .replace("  kind: patch\n", "  kind: patch\n  include: [node-a]\n")
                .replace("\"true\"", value)
        };
        let parsed = parse(&[NETWORK, &named("\"first\""), &named("\"second\"")]);
        assert_eq!(
            for_host(&parsed, "node-a").unwrap()[0].value["extraArgs"]
                ["rotate-server-certificates"]
                .as_str(),
            Some("second")
        );
    }

    #[test]
    fn patches_come_out_in_the_order_their_identities_first_appear() {
        let install =
            "slipmesh:\n  kind: patch\napiVersion: v1alpha1\nkind: UnattendedInstallConfig\n";
        let parsed = parse(&[NETWORK, install, KUBELET]);
        let identities: Vec<_> = for_host(&parsed, "node-a")
            .unwrap()
            .into_iter()
            .map(|d| d.identity)
            .collect();
        assert_eq!(identities, ["UnattendedInstallConfig", "KubeletConfig"]);
    }

    #[test]
    fn a_patch_without_kind_is_refused() {
        let err = error(&[
            NETWORK,
            "slipmesh:\n  kind: patch\nmachine:\n  install: {disk: /dev/vda}\n",
        ]);
        assert!(
            err.contains("the `kind: patch` document at line 11: has no Talos `kind`"),
            "{err}"
        );
    }

    fn generated_with(name: &str, body: &str) -> String {
        format!(
            "slipmesh:
  kind: patch
apiVersion: v1alpha1
kind: ExtensionServiceConfig
name: {name}
{body}"
        )
    }

    #[test]
    fn a_patch_adding_files_to_a_generated_document_is_accepted() {
        for name in ["awg", "router", "nftables"] {
            let patch = generated_with(
                name,
                "configFiles:
  - mountPath: /etc/talos-extensions/extra
    content: x
",
            );
            check(&parse(&[NETWORK, &patch])).unwrap();
        }
    }

    #[test]
    fn a_patch_setting_more_than_files_on_a_generated_document_is_refused() {
        let patch = generated_with(
            "router",
            "environment:
  - RUST_LOG=debug
",
        );
        let err = error(&[NETWORK, &patch]);
        assert!(err.contains("configFiles"), "{err}");
    }

    #[test]
    fn a_patch_replacing_the_generated_file_is_refused() {
        let patch = generated_with(
            "router",
            "configFiles:
  - mountPath: /etc/talos-extensions/router.yaml
    content: x
",
        );
        let err = error(&[NETWORK, &patch]);
        assert!(err.contains("/etc/talos-extensions/router.yaml"), "{err}");
    }

    #[test]
    fn a_file_is_set_only_by_a_patch_that_sets_it() {
        let ruleset = generated_with(
            "nftables",
            "configFiles:\n  - mountPath: /etc/talos-extensions/nftables.conf.j2\n    content: |\n      table inet t {}\n",
        );
        let parsed = parse(&[NETWORK, &ruleset]);
        let template = nftables::template::TEMPLATE_PATH;
        assert!(sets_file(&parsed, "nftables", template));
        assert!(!sets_file(
            &parsed,
            "nftables",
            "/etc/talos-extensions/other.conf"
        ));
        assert!(!sets_file(&parsed, "router", template));
    }
}
