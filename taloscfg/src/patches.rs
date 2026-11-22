//! The `patch` documents of `slipmesh.yaml` as Talos documents: checked as far as the generator
//! knows them, and merged into what one host gets.

use crate::defaults::Service;
use crate::talos::{self, Identity};
use anyhow::{Context, Result, bail, ensure};
use sliplib_config::v2::{File, PatchDocument};
use sliplib_yaml::Value;

/// Where the `nftables` daemon read its ruleset before it took a template.
pub(crate) const LEGACY_NFTABLES_PATH: &str = "/etc/talos-extensions/nftables.yaml";

/// The `ExtensionServiceConfig`s the generator makes, by name, with the files it writes there, its
/// own config first where it has one. Talos keeps `name` unique per `kind`, so a `patch` document
/// of one of these names is that same document: it may add files to it, and nothing else - not a
/// file the generator writes.
const GENERATED: [(&str, &[&str]); 3] = [
    ("awg", &["/etc/talos-extensions/awg.yaml"]),
    (
        Service::Router.name(),
        &[
            "/etc/talos-extensions/router.yaml",
            Service::Router.mount_path(),
        ],
    ),
    (
        Service::Firewall.name(),
        &[Service::Firewall.mount_path(), LEGACY_NFTABLES_PATH],
    ),
];

/// The config file the generator writes into its document `name`, `awg` or `router`.
pub(crate) fn config_path(name: &str) -> &'static str {
    let (_, files) = GENERATED
        .iter()
        .find(|(generated, _)| *generated == name)
        .expect("only generated documents are asked for");
    files[0]
}

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
/// than files beside the generated ones.
pub fn check(files: &File) -> Result<()> {
    files.patches().iter().try_for_each(check_one)
}

fn check_one(patch: &PatchDocument) -> Result<()> {
    let place = patch.aim();
    let identity = Identity::of(patch.value());
    let Some(kind) = &identity.kind else {
        bail!("{place}: has no Talos `kind`, so it has no identity to merge by");
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
            "{place}: `ExtensionServiceConfig` {name:?} is generated - a patch may add \
             `configFiles` to it and nothing else, not {others:?}"
        );
        if let Some(over) = generated
            .iter()
            .find(|path| talos::sets_file(patch.value(), name, path))
        {
            bail!(
                "{place}: {over} is a file the generator writes for {name:?} - add files next to \
                 it, not over it"
            );
        }
    }
    Ok(())
}

/// The Talos documents that go into `host`'s patch file, in the order their identities first
/// appear in the files.
///
/// Documents of one identity are merged in the order of their rank, so the more specific document
/// wins wherever it sits in the file.
pub(crate) fn for_host(files: &File, host: &str) -> Result<Vec<HostDocument>> {
    let reaching: Vec<&PatchDocument> = files
        .patches()
        .iter()
        .filter(|patch| patch.aim().reaches(host))
        .collect();

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
            let mut sources: Vec<&PatchDocument> = reaching
                .iter()
                .filter(|patch| Identity::of(patch.value()) == identity)
                .copied()
                .collect();
            // Stable: of two of one rank, the later read stays the later.
            sources.sort_by_key(|patch| patch.aim().rank());
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
  node-c: {platform: talos, node_id: 0.0.0.3, underlay: {wan: {}}}
"#;

    /// A `patch` document of `talos`, with `aim` after `platform` in its block.
    fn patch(aim: &str, body: &str) -> String {
        format!("slipmesh:\n  kind: patch\n  platform: talos\n{aim}{body}")
    }

    fn kubelet(aim: &str, args: &str) -> String {
        patch(
            aim,
            &format!("apiVersion: v1alpha1\nkind: KubeletConfig\nextraArgs:\n{args}"),
        )
    }

    fn parse(documents: &[&str]) -> File {
        File::parse(&documents.join("---\n")).unwrap()
    }

    fn error(documents: &[&str]) -> String {
        match check(&parse(documents)) {
            Ok(()) => panic!("checked, but should have been refused"),
            Err(err) => format!("{err:#}"),
        }
    }

    fn device(aim: &str, host: &str) -> String {
        patch(
            aim,
            &format!(
                "# the device the converger talks to\napiVersion: v1alpha1\nkind: \
                 ExtensionServiceConfig\nname: device\nconfigFiles:\n  - mountPath: \
                 /etc/device.yaml\n    content:\n      host: {host}\n      port: 8729\n"
            ),
        )
    }

    /// A `configFiles[].content` in `text`.
    fn content(text: &str, index: usize) -> Value {
        let value: Value = sliplib_yaml::from_str(text).unwrap();
        value["configFiles"][index]["content"].clone()
    }

    #[test]
    fn a_content_mapping_goes_out_as_the_text_of_that_yaml() {
        let parsed = parse(&[
            NETWORK,
            &device("  include: [node-b]\n", "router1.example.com"),
        ]);
        let text = &for_host(&parsed, "node-b").unwrap()[0].text;
        assert_eq!(
            content(text, 0).as_str(),
            Some("host: router1.example.com\nport: 8729\n"),
            "{text}"
        );
    }

    #[test]
    fn a_content_ending_in_blank_lines_keeps_them() {
        let script = patch(
            "",
            "apiVersion: v1alpha1\nkind: ExtensionServiceConfig\nname: script\nconfigFiles:\n  - \
             mountPath: /etc/script\n    content: \"run\\n\\n\\n\"\n",
        );
        let parsed = parse(&[NETWORK, &script]);
        let text = &for_host(&parsed, "node-a").unwrap()[0].text;
        assert_eq!(content(text, 0).as_str(), Some("run\n\n\n"), "{text}");
    }

    #[test]
    fn a_content_mapping_goes_out_as_text_after_a_merge_too() {
        let parsed = parse(&[
            NETWORK,
            &device("", "router0.example.com"),
            &device("  include: [node-b]\n", "router1.example.com"),
        ]);
        let documents = for_host(&parsed, "node-b").unwrap();
        assert_eq!(
            content(&documents[0].text, 0).as_str(),
            Some("host: router1.example.com\nport: 8729\n")
        );
        assert_eq!(
            content(&for_host(&parsed, "node-a").unwrap()[0].text, 0).as_str(),
            Some("host: router0.example.com\nport: 8729\n")
        );
    }

    #[test]
    fn patches_of_one_identity_merge_with_the_included_one_over_the_one_for_all() {
        // The narrower document comes first in the files and still lands on top.
        let parsed = parse(&[
            NETWORK,
            &kubelet("  include: [node-a]\n", "    v: \"4\"\n"),
            &kubelet("", "    rotate-server-certificates: \"true\"\n"),
        ]);
        let merged = for_host(&parsed, "node-a").unwrap();
        assert_eq!(merged.len(), 1);
        let value: Value = sliplib_yaml::from_str(&merged[0].text).unwrap();
        assert_eq!(value["extraArgs"]["v"].as_str(), Some("4"));
        assert_eq!(
            value["extraArgs"]["rotate-server-certificates"].as_str(),
            Some("true")
        );
        let elsewhere = for_host(&parsed, "node-b").unwrap();
        assert!(elsewhere[0].value["extraArgs"]["v"].is_null());
    }

    #[test]
    fn of_two_patches_of_one_identity_and_one_rank_the_later_in_the_files_wins() {
        for aim in ["", "  include: [node-a]\n"] {
            let parsed = parse(&[
                NETWORK,
                &kubelet(aim, "    rotate-server-certificates: \"first\"\n"),
                &kubelet(aim, "    rotate-server-certificates: \"second\"\n"),
            ]);
            let merged = for_host(&parsed, "node-a").unwrap();
            assert_eq!(merged.len(), 1, "{aim:?}");
            assert_eq!(
                merged[0].value["extraArgs"]["rotate-server-certificates"].as_str(),
                Some("second"),
                "{aim:?}"
            );
        }
    }

    #[test]
    fn an_order_set_on_purpose_moves_a_document_past_a_narrower_one() {
        let parsed = parse(&[
            NETWORK,
            &kubelet("  order: 2000\n", "    v: \"for all\"\n"),
            &kubelet("  include: [node-a]\n", "    v: \"narrower\"\n"),
        ]);
        let merged = for_host(&parsed, "node-a").unwrap();
        assert_eq!(merged[0].value["extraArgs"]["v"].as_str(), Some("for all"));
    }

    #[test]
    fn patches_come_out_in_the_order_their_identities_first_appear() {
        let install = patch(
            "  include: [node-a]\n",
            "apiVersion: v1alpha1\nkind: UnattendedInstallConfig\n",
        );
        let parsed = parse(&[NETWORK, &install, &kubelet("", "    v: \"4\"\n")]);
        let identities: Vec<_> = for_host(&parsed, "node-a")
            .unwrap()
            .into_iter()
            .map(|d| d.identity)
            .collect();
        assert_eq!(identities, ["UnattendedInstallConfig", "KubeletConfig"]);
    }

    #[test]
    fn a_patch_without_kind_is_refused_naming_where_it_stands() {
        let err = error(&[
            NETWORK,
            &patch("", "machine:\n  install: {disk: /dev/vda}\n"),
        ]);
        assert!(
            err.contains("the `kind: patch` document at line 10: has no Talos `kind`"),
            "{err}"
        );
    }

    fn generated_with(name: &str, body: &str) -> String {
        patch(
            "",
            &format!("apiVersion: v1alpha1\nkind: ExtensionServiceConfig\nname: {name}\n{body}"),
        )
    }

    #[test]
    fn a_patch_adding_files_to_a_generated_document_is_accepted() {
        for name in ["awg", "router", "nftables"] {
            let patch = generated_with(
                name,
                "configFiles:\n  - mountPath: /etc/talos-extensions/extra\n    content: x\n",
            );
            check(&parse(&[NETWORK, &patch])).unwrap();
        }
    }

    #[test]
    fn a_patch_setting_more_than_files_on_a_generated_document_is_refused() {
        for name in ["awg", "router", "nftables"] {
            let patch = generated_with(name, "environment:\n  - RUST_LOG=debug\n");
            let err = error(&[NETWORK, &patch]);
            assert!(err.contains("configFiles") && err.contains(name), "{err}");
        }
    }

    #[test]
    fn a_patch_setting_a_file_the_generator_writes_is_refused_naming_it() {
        for (name, paths) in GENERATED {
            for path in paths {
                let patch = generated_with(
                    name,
                    &format!("configFiles:\n  - mountPath: {path}\n    content: x\n"),
                );
                let err = error(&[NETWORK, &patch]);
                assert!(err.contains(path), "{err}");
            }
        }
    }

    #[test]
    fn the_config_of_a_generated_document_is_its_first_file() {
        assert_eq!(config_path("awg"), "/etc/talos-extensions/awg.yaml");
        assert_eq!(config_path("router"), "/etc/talos-extensions/router.yaml");
    }
}
