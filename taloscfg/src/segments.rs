//! Raw multi-document YAML I/O for `patches/<node>.yaml`: splits a patch file into segments this
//! tool owns (its own `ExtensionServiceConfig` documents for awg/router/nftables) versus segments
//! it must never touch (anything else - e.g. `machine.install.disk`, hand-written per node).
//! Segments are handed back as raw text, never re-serialized: a foreign one keeps its keys, its
//! order, its comments and its formatting, and only `apiVersion`/`kind`/`name` are ever parsed out
//! of it. Not byte for byte, though - surrounding blank lines and the document markers themselves
//! are dropped here, because `render_file` writes those back itself.
//!
//! Where one document ends and the next begins is `document.rs`'s to decide, not this module's.

use crate::document::split;
use anyhow::Result;
use serde::Deserialize;

/// The `name`s this tool ever writes, under `kind: ExtensionServiceConfig` - the exact ownership
/// key. Talos itself requires `name` to be unique per `kind`, so this pair is already a sufficient
/// identity; no extra "managed-by" marker is needed in the document itself.
pub const OWNED_NAMES: [&str; 3] = ["awg", "router", "nftables"];

#[derive(Deserialize, Default)]
struct SegmentHeader {
    kind: Option<String>,
    name: Option<String>,
}

pub fn is_owned(segment: &str) -> bool {
    let header: SegmentHeader = yaml_serde::from_str(segment).unwrap_or_default();
    header.kind.as_deref() == Some("ExtensionServiceConfig")
        && header
            .name
            .as_deref()
            .is_some_and(|n| OWNED_NAMES.contains(&n))
}

/// Segments this tool must preserve as-is, in original order.
pub fn foreign_segments(raw: &str) -> Result<Vec<String>> {
    Ok(split(raw)?.into_iter().filter(|s| !is_owned(s)).collect())
}

/// The single owned segment for a specific `name` (`"awg"`/`"router"`/`"nftables"`), if present -
/// used to read back a previous run's output for the idempotency tiers in `render.rs`.
pub fn owned_segment(raw: &str, name: &str) -> Result<Option<String>> {
    Ok(split(raw)?.into_iter().find(|s| {
        let header: SegmentHeader = yaml_serde::from_str(s).unwrap_or_default();
        header.kind.as_deref() == Some("ExtensionServiceConfig")
            && header.name.as_deref() == Some(name)
    }))
}

/// Rebuilds a patch file: foreign segments (original order) first, then the freshly-rendered owned
/// segments, `---`-separated, single trailing newline.
pub fn render_file(foreign: &[String], owned: &[String]) -> String {
    let all: Vec<&str> = foreign
        .iter()
        .chain(owned.iter())
        .map(String::as_str)
        .collect();
    let mut out = all.join("\n---\n");
    out.push('\n');
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identifies_extensionserviceconfig_awg_segment_as_owned() {
        let segment =
            "apiVersion: v1alpha1\nkind: ExtensionServiceConfig\nname: awg\nconfigFiles: []";
        assert!(is_owned(segment));
    }

    #[test]
    fn identifies_extensionserviceconfig_unrelated_name_as_foreign() {
        let segment = "apiVersion: v1alpha1\nkind: ExtensionServiceConfig\nname: some-other-service\nconfigFiles: []";
        assert!(!is_owned(segment));
    }

    #[test]
    fn identifies_segment_without_kind_as_foreign() {
        let segment = "machine:\n    install:\n        disk: /dev/vda";
        assert!(!is_owned(segment));
    }

    #[test]
    fn foreign_segments_excludes_owned_and_preserves_order() {
        let raw = "machine:\n    install:\n        disk: /dev/vda\n---\napiVersion: v1alpha1\nkind: ExtensionServiceConfig\nname: awg\nconfigFiles: []\n---\napiVersion: v1alpha1\nkind: ExtensionServiceConfig\nname: router\nconfigFiles: []\n";
        let foreign = foreign_segments(raw).unwrap();
        assert_eq!(foreign.len(), 1);
        assert!(foreign[0].starts_with("machine:"));
    }

    #[test]
    fn foreign_segments_of_file_with_no_foreign_content_is_empty() {
        let raw =
            "apiVersion: v1alpha1\nkind: ExtensionServiceConfig\nname: awg\nconfigFiles: []\n";
        assert!(foreign_segments(raw).unwrap().is_empty());
    }

    #[test]
    fn foreign_segment_keeps_its_own_text() {
        let disk_segment = "machine:\n    install:\n        disk: /dev/vda";
        let raw = format!("{disk_segment}\n");
        let foreign = foreign_segments(&raw).unwrap();
        assert_eq!(foreign, vec![disk_segment.to_string()]);
    }

    #[test]
    fn render_file_puts_foreign_first_then_owned_separated_by_doc_marker() {
        let foreign = vec!["machine:\n    install:\n        disk: /dev/vda".to_string()];
        let owned = vec![
            "apiVersion: v1alpha1\nkind: ExtensionServiceConfig\nname: awg\nconfigFiles: []"
                .to_string(),
        ];
        let out = render_file(&foreign, &owned);
        assert_eq!(
            out,
            "machine:\n    install:\n        disk: /dev/vda\n---\napiVersion: v1alpha1\nkind: ExtensionServiceConfig\nname: awg\nconfigFiles: []\n"
        );
    }

    #[test]
    fn owned_segment_finds_the_named_segment() {
        let raw = "apiVersion: v1alpha1\nkind: ExtensionServiceConfig\nname: awg\nconfigFiles: []\n---\napiVersion: v1alpha1\nkind: ExtensionServiceConfig\nname: router\nconfigFiles: [x]\n";
        let found = owned_segment(raw, "router").unwrap().unwrap();
        assert!(found.contains("configFiles: [x]"));
    }

    #[test]
    fn owned_segment_returns_none_when_absent() {
        let raw = "machine:\n    install:\n        disk: /dev/vda\n";
        assert!(owned_segment(raw, "awg").unwrap().is_none());
    }

    #[test]
    fn a_directive_survives_a_round_trip_as_valid_yaml() {
        // The `---` after a directive is what terminates it, not a separator to be rewritten:
        // dropping it turns the file into something no YAML parser accepts.
        let raw = "%YAML 1.2\n---\nmachine:\n    install:\n        disk: /dev/vda\n";
        let rebuilt = render_file(&split(raw).unwrap(), &[]);
        assert!(rebuilt.contains("%YAML 1.2\n---\n"), "rebuilt: {rebuilt:?}");

        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&tree_sitter_yaml::LANGUAGE.into())
            .unwrap();
        let tree = parser.parse(&rebuilt, None).unwrap();
        assert!(
            !tree.root_node().has_error(),
            "rebuilding produced invalid YAML: {rebuilt:?}"
        );
    }

    #[test]
    fn render_file_from_scratch_has_only_owned_segments() {
        let owned = vec![
            "apiVersion: v1alpha1\nkind: ExtensionServiceConfig\nname: router\nconfigFiles: []"
                .to_string(),
        ];
        let out = render_file(&[], &owned);
        assert_eq!(
            out,
            "apiVersion: v1alpha1\nkind: ExtensionServiceConfig\nname: router\nconfigFiles: []\n"
        );
    }
}
