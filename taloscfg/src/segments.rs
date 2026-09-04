//! Raw multi-document YAML I/O for `patches/<node>.yaml`: splits a patch file into segments this
//! tool owns (its own `ExtensionServiceConfig` documents for awg/router/nftables) versus segments
//! it must never touch (anything else - e.g. `machine.install.disk`, hand-written per node).
//! Segments are handed back as raw text, never re-serialized: a foreign one keeps its keys, its
//! order, its comments and its formatting, and only `apiVersion`/`kind`/`name` are ever parsed out
//! of it. Not byte for byte, though - surrounding blank lines and the document markers themselves
//! are dropped here, because `render_file` writes those back itself.
//!
//! Where a document begins comes from the YAML grammar rather than from a search for `---`: a
//! text split cannot tell a document marker from the same three characters inside a block
//! scalar, and an nftables ruleset is a block scalar carrying arbitrary text. The parser is
//! tree-sitter-yaml, already in this build under `yamlpath` - which parses a whole source but
//! exposes no way to walk the documents of a stream, hence the direct use here.

use anyhow::{Context, Result};
use serde::Deserialize;
use std::ops::Range;
use tree_sitter::Parser;

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
    let header: SegmentHeader = serde_yaml::from_str(segment).unwrap_or_default();
    header.kind.as_deref() == Some("ExtensionServiceConfig")
        && header
            .name
            .as_deref()
            .is_some_and(|n| OWNED_NAMES.contains(&n))
}

/// Splits a patch file's raw text into trimmed segments, in file order. Empty input yields no
/// segments (a from-scratch file has nothing to preserve).
///
/// The cut points are the byte offsets where the grammar says a document starts; each segment then
/// runs to the next one, so every byte of the file lands in exactly one segment. Taking each
/// document node's own span instead would drop whatever the grammar parses as trailing trivia - a
/// comment after the last key, say - and losing it would corrupt a file this tool promises only to
/// add to.
pub fn split(raw: &str) -> Result<Vec<String>> {
    let mut parser = Parser::new();
    parser
        .set_language(&tree_sitter_yaml::LANGUAGE.into())
        .context("loading the YAML grammar")?;
    // `parse` returns None only when the parser has no language, which the line above just gave
    // it - not for malformed input, which comes back as a tree with error nodes in it instead.
    let tree = parser
        .parse(raw, None)
        .context("the YAML grammar did not load")?;
    anyhow::ensure!(
        !tree.root_node().has_error(),
        "the patch file is not valid YAML - refusing to rewrite it"
    );

    let mut starts: Vec<usize> = Vec::new();
    let mut markers: Vec<Range<usize>> = Vec::new();
    // One cursor per level, reused across nodes: `children` resets it to the node it is given, and
    // the crate asks for exactly this rather than a fresh cursor per call.
    let mut documents = tree.root_node().walk();
    let mut inside = tree.root_node().walk();
    for document in tree.root_node().children(&mut documents) {
        if document.kind() != "document" {
            continue;
        }
        starts.push(document.start_byte());
        let mut after_directive = false;
        for child in document.children(&mut inside) {
            if child.kind().ends_with("_directive") {
                after_directive = true;
                continue;
            }
            // A `---` that follows a directive is not a separator this module writes back - it is
            // what terminates the directives, and a document that loses it stops being YAML.
            if child.kind() == "---" && after_directive {
                continue;
            }
            // The markers are anonymous tokens: the grammar has already decided that this `---`
            // opens a document and that `---foo` is a mapping key, which is not a distinction to
            // re-derive from the text.
            if matches!(child.kind(), "---" | "...") {
                // Up to whatever the parser found next: that swallows the rest of the marker's
                // line - trailing spaces, the newline - without this module deciding what those
                // are, and stops at a comment written beside the marker, which is content.
                let end = child
                    .next_sibling()
                    .map_or(child.end_byte(), |next| next.start_byte());
                markers.push(child.start_byte()..end);
            }
        }
    }

    match starts.first_mut() {
        // Whatever precedes the first document - a comment, a directive - is a sibling of the
        // documents rather than part of one, and belongs to the document it introduces.
        Some(first) => *first = 0,
        // A file the grammar finds no document in is not necessarily empty: one of nothing but
        // comments parses to no documents at all, and dropping it would delete someone's note.
        // There is nothing to split, so the whole of it is one segment; an actually empty file
        // still yields none, since that segment trims away to nothing.
        None => starts.push(0),
    }

    Ok(starts
        .iter()
        .enumerate()
        .map(|(i, &start)| {
            let end = starts.get(i + 1).copied().unwrap_or(raw.len());
            without_markers(raw, start..end, &markers)
        })
        .filter(|s| !s.is_empty())
        .collect())
}

/// The segment's text with the document markers inside it removed - `render_file` writes its own.
/// Everything else survives, including the line endings the file was written with.
fn without_markers(raw: &str, segment: Range<usize>, markers: &[Range<usize>]) -> String {
    let mut out = String::with_capacity(segment.len());
    let mut cursor = segment.start;
    for marker in markers
        .iter()
        .filter(|m| m.start >= segment.start && m.end <= segment.end)
    {
        out.push_str(&raw[cursor..marker.start]);
        cursor = marker.end;
    }
    out.push_str(&raw[cursor..segment.end]);
    out.trim().to_owned()
}

/// Segments this tool must preserve as-is, in original order.
pub fn foreign_segments(raw: &str) -> Result<Vec<String>> {
    Ok(split(raw)?.into_iter().filter(|s| !is_owned(s)).collect())
}

/// The single owned segment for a specific `name` (`"awg"`/`"router"`/`"nftables"`), if present -
/// used to read back a previous run's output for the idempotency tiers in `render.rs`.
pub fn owned_segment(raw: &str, name: &str) -> Result<Option<String>> {
    Ok(split(raw)?.into_iter().find(|s| {
        let header: SegmentHeader = serde_yaml::from_str(s).unwrap_or_default();
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
    fn splits_multi_document_file_preserving_order() {
        let raw = "machine:\n    install:\n        disk: /dev/vda\n---\napiVersion: v1alpha1\nkind: ExtensionServiceConfig\nname: awg\nconfigFiles: []\n";
        let segments = split(raw).unwrap();
        assert_eq!(segments.len(), 2);
        assert!(segments[0].starts_with("machine:"));
        assert!(segments[1].starts_with("apiVersion:"));
    }

    #[test]
    fn split_of_empty_file_is_empty() {
        assert!(split("").unwrap().is_empty());
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

    // What a text split on the document marker gets wrong, and what this module decides on top
    // of the grammar: which markers to strip, what to do with a file that will not parse, and
    // where the bytes before the first document belong.

    #[test]
    fn a_document_terminator_is_not_content() {
        let raw = "machine:\n    install:\n        disk: /dev/vda\n...\n";
        let segments = split(raw).unwrap();
        assert_eq!(
            segments,
            vec!["machine:\n    install:\n        disk: /dev/vda".to_string()]
        );
    }

    #[test]
    fn a_marker_line_with_trailing_spaces_leaves_no_blank_line() {
        let raw = "# note\n---   \nmachine: x\n";
        let segments = split(raw).unwrap();
        assert_eq!(segments, vec!["# note\nmachine: x".to_string()]);
    }

    #[test]
    fn a_comment_written_beside_a_marker_survives_it() {
        let raw = "# note\n--- # why this document exists\nmachine: x\n";
        let segments = split(raw).unwrap();
        assert_eq!(
            segments,
            vec!["# note\n# why this document exists\nmachine: x".to_string()]
        );
    }

    #[test]
    fn a_directive_survives_a_round_trip_as_valid_yaml() {
        // The `---` after a directive is what terminates it, not a separator to be rewritten:
        // dropping it turns the file into something no YAML parser accepts.
        let raw = "%YAML 1.2\n---\nmachine:\n    install:\n        disk: /dev/vda\n";
        let rebuilt = render_file(&split(raw).unwrap(), &[]);
        assert!(rebuilt.contains("%YAML 1.2\n---\n"), "rebuilt: {rebuilt:?}");

        let mut parser = Parser::new();
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
    fn a_file_of_only_comments_is_kept_whole() {
        let raw = "# a note someone left, and nothing else
";
        let segments = split(raw).unwrap();
        assert_eq!(
            segments,
            vec!["# a note someone left, and nothing else".to_string()]
        );
    }

    #[test]
    fn a_marker_after_leading_comments_is_still_stripped() {
        let raw = "# hand-written, keep me\n---\nmachine:\n    install:\n        disk: /dev/vda\n";
        let segments = split(raw).unwrap();
        assert_eq!(segments.len(), 1);
        assert_eq!(
            segments[0],
            "# hand-written, keep me\nmachine:\n    install:\n        disk: /dev/vda"
        );
    }

    #[test]
    fn a_comment_then_a_marker_and_nothing_else_leaves_no_empty_document() {
        let raw = "# just a note\n---\n";
        let segments = split(raw).unwrap();
        assert_eq!(segments, vec!["# just a note".to_string()]);
    }

    #[test]
    fn crlf_inside_a_segment_survives() {
        let raw = "machine:\r\n    install:\r\n        disk: /dev/vda\r\n";
        let segments = split(raw).unwrap();
        assert!(
            segments[0].contains("\r\n"),
            "line endings were rewritten: {:?}",
            segments[0]
        );
    }

    #[test]
    fn invalid_yaml_is_refused_rather_than_split() {
        let raw = "machine:\n  install:\n   disk: [unterminated\n";
        assert!(split(raw).is_err());
    }

    #[test]
    fn a_comment_before_the_first_document_is_kept_with_it() {
        let raw =
            "# hand-written, do not lose me\nmachine:\n    install:\n        disk: /dev/vda\n";
        let segments = split(raw).unwrap();
        assert_eq!(segments.len(), 1);
        assert!(segments[0].starts_with("# hand-written"));
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
