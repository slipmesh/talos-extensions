//! Byte-level access to the documents of a multi-document YAML file.
//!
//! This is the only module that knows a file holds more than one document. Everything above it
//! works on a single document, and hands the result back here to be put in place - which matters
//! because `yamlpath::Document::new` addresses the *first* document of a stream and silently
//! ignores the rest (`yamlpath-1.30.0/src/lib.rs:1124-1148`), so patching a multi-document file
//! through it directly edits whichever document happens to come first.
//!
//! Where a document begins comes from the YAML grammar rather than from a search for `---`: a
//! text split cannot tell a document marker from the same three characters inside a block
//! scalar, and an nftables ruleset is a block scalar carrying arbitrary text. The parser is
//! tree-sitter-yaml, already in this build under `yamlpath` - which parses a whole source but
//! exposes no way to walk the documents of a stream, hence the direct use here.

use anyhow::{Context, Result};
use std::ops::Range;
use tree_sitter::Parser;

/// The generator's own top-level block in every `slipmesh.yaml` document: what the document is for
/// and which hosts it reaches. It is addressed to this tool, so it never reaches a patch file.
pub const META_KEY: &str = "slipmesh";

/// Where each document starts, and where the document markers inside them are.
///
/// The cut points are the byte offsets the grammar says a document starts at; each document runs
/// to the next cut, so the cuts leave no gaps and nothing in the file falls between two documents.
/// Taking each document node's own span instead would leave such gaps, since the grammar parses a
/// comment after the last key as trailing trivia outside the node.
fn scan(raw: &str) -> Result<(Vec<usize>, Vec<Range<usize>>)> {
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
        "the file is not valid YAML - refusing to rewrite it"
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
        for child in document.children(&mut inside) {
            // A `---` right after a directive is not a separator anything writes back - it is what
            // terminates the directive, and a document that loses it stops being YAML. The tree
            // says which one it is, so there is no state to carry through the loop.
            if child.kind() == "---"
                && child
                    .prev_sibling()
                    .is_some_and(|prev| prev.kind().ends_with("_directive"))
            {
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
        None => starts.push(0),
    }

    Ok((starts, markers))
}

/// Byte ranges of the documents in `raw`, in file order.
///
/// The ranges tile the input: they are contiguous, the first starts at 0 and the last ends at
/// `raw.len()`, so concatenating the slices reproduces the file byte for byte. Nothing is trimmed
/// and no marker is dropped - a document owns the `---` that opens it and the whitespace that
/// follows it, which is what lets a document be replaced without disturbing its neighbours.
///
/// An empty file has no documents.
pub fn spans(raw: &str) -> Result<Vec<Range<usize>>> {
    if raw.is_empty() {
        return Ok(Vec::new());
    }
    let (starts, _) = scan(raw)?;
    Ok(starts
        .iter()
        .enumerate()
        .map(|(i, &start)| start..starts.get(i + 1).copied().unwrap_or(raw.len()))
        .collect())
}

/// `raw` with the bytes at `span` replaced by `replacement` - one document swapped for its edited
/// version, every other byte carried over.
pub fn splice(raw: &str, span: Range<usize>, replacement: &str) -> String {
    let mut out = String::with_capacity(raw.len() - span.len() + replacement.len());
    out.push_str(&raw[..span.start]);
    out.push_str(replacement);
    out.push_str(&raw[span.end..]);
    out
}

/// Applies `patches` to the single document at `span`, returning the whole file with that document
/// replaced. Every byte outside `span` is carried over untouched.
pub fn patch_document(
    raw: &str,
    span: Range<usize>,
    patches: &[yamlpatch::Patch],
) -> Result<String> {
    let document = yamlpath::Document::new(&raw[span.clone()])
        .context("parsing the document being patched")?;
    let patched = yamlpatch::apply_yaml_patches(&document, patches)
        .context("applying patches to the document")?;
    Ok(splice(raw, span, patched.source()))
}

/// `document` without its top-level `key` and everything under it. A document without that key
/// comes back unchanged.
pub fn remove_key(document: &str, key: &str) -> Result<String> {
    let mut out = document.to_owned();
    if let Some(span) = key_span(document, key)? {
        out.replace_range(span, "");
    }
    Ok(out)
}

/// `document` with its top-level `key` and everything under it replaced by as many empty lines as
/// it took up - gone for a parser, while every other line keeps its number, so an error found in
/// what is left still points at the line the operator wrote.
pub fn blank_key(document: &str, key: &str) -> Result<String> {
    let mut out = document.to_owned();
    if let Some(span) = key_span(document, key)? {
        let lines = document[span.clone()].matches('\n').count();
        out.replace_range(span, &"\n".repeat(lines));
    }
    Ok(out)
}

/// The bytes a top-level `key` and its block take up, if the document has it.
fn key_span(document: &str, key: &str) -> Result<Option<Range<usize>>> {
    let parsed = yamlpath::Document::new(document).context("parsing the document")?;
    let route = yamlpath::route![key];
    if !parsed.query_exists(&route) {
        return Ok(None);
    }
    let span = parsed
        .removal_span(&route)
        .with_context(|| format!("locating `{key}`"))?;
    Ok(Some(without_trailing_comments_and_blank_lines(
        document, span,
    )))
}

/// `document` without its `slipmesh:` block - what is left is what goes into a patch file. A
/// document that has no such block comes back unchanged, so this is safe to call on anything.
pub fn strip_meta(document: &str) -> Result<String> {
    remove_key(document, META_KEY)
}

/// `span` cut back to end before any top-level comment lines and blank lines it closes with. The
/// grammar hangs what follows a nested block's last line onto that block, so a removal span swallows
/// it - but a comment written at column 0 speaks to the document, not to the block above it, and a
/// blank line separates the block from whatever comes next rather than belonging to it.
fn without_trailing_comments_and_blank_lines(text: &str, span: Range<usize>) -> Range<usize> {
    let mut end = span.end;
    loop {
        let body = &text[span.start..end];
        let body = body.strip_suffix('\n').unwrap_or(body);
        let body = body.strip_suffix('\r').unwrap_or(body);
        // The first line is the key itself, never a line to keep.
        let Some(newline) = body.rfind('\n') else {
            break;
        };
        let last = &body[newline + 1..];
        if !last.starts_with('#') && !last.trim().is_empty() {
            break;
        }
        end = span.start + newline + 1;
    }
    span.start..end
}

/// Every document in `raw` that has anything in it, as the byte range it occupies and its trimmed
/// text without markers - the range is for putting an edited document back, the text is for
/// reading it.
pub fn documents(raw: &str) -> Result<Vec<(Range<usize>, String)>> {
    let (starts, markers) = scan(raw)?;
    Ok(starts
        .iter()
        .enumerate()
        .map(|(i, &start)| {
            let span = start..starts.get(i + 1).copied().unwrap_or(raw.len());
            let text = without_markers(raw, span.clone(), &markers);
            (span, text)
        })
        .filter(|(_, text)| !text.is_empty())
        .collect())
}

/// Splits a patch file's raw text into trimmed segments, in file order. Empty input yields no
/// segments (a from-scratch file has nothing to preserve).
///
/// What each segment drops is its markers and the whitespace around it - see
/// `segments::render_file`, which writes those back. For byte-exact ranges instead, use [`spans`].
pub fn split(raw: &str) -> Result<Vec<String>> {
    Ok(documents(raw)?.into_iter().map(|(_, text)| text).collect())
}

/// The segment's text with the document markers inside it removed - `segments::render_file` writes
/// its own. Everything else survives, including the line endings the file was written with.
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

#[cfg(test)]
mod tests {
    use super::*;

    /// Rebuilds the file from its spans - what every "leaves the rest alone" claim below rests on.
    fn rejoin(raw: &str) -> String {
        spans(raw)
            .unwrap()
            .into_iter()
            .map(|span| &raw[span])
            .collect()
    }

    #[test]
    fn spans_of_a_single_document_file_cover_all_of_it() {
        let raw = "machine:\n    install:\n        disk: /dev/vda\n";
        assert_eq!(spans(raw).unwrap(), vec![0..raw.len()]);
    }

    #[test]
    fn spans_of_an_empty_file_are_none() {
        assert!(spans("").unwrap().is_empty());
    }

    #[test]
    fn spans_of_a_three_document_file_are_contiguous_and_rebuild_it() {
        let raw = "a: 1\n---\nb: 2\n---\nc: 3\n";
        let found = spans(raw).unwrap();
        assert_eq!(found.len(), 3, "{found:?}");
        assert_eq!(found[0].start, 0);
        assert_eq!(found[0].end, found[1].start);
        assert_eq!(found[1].end, found[2].start);
        assert_eq!(found[2].end, raw.len());
        assert_eq!(rejoin(raw), raw);
    }

    #[test]
    fn a_marker_inside_a_block_scalar_is_not_a_boundary() {
        let raw = "\
apiVersion: v1alpha1
kind: ExtensionServiceConfig
name: nftables
configFiles:
    - content: |
        table inet talos_filter {
            # ---
            chain input { type filter hook input priority 0; }
        }
      mountPath: /etc/nftables.conf
";
        assert_eq!(spans(raw).unwrap(), vec![0..raw.len()]);
    }

    #[test]
    fn a_directive_does_not_start_a_second_document() {
        let raw = "%YAML 1.2\n---\nmachine:\n    install:\n        disk: /dev/vda\n";
        assert_eq!(spans(raw).unwrap(), vec![0..raw.len()]);
    }

    #[test]
    fn splicing_replaces_exactly_the_span() {
        let raw = "a: 1\n---\nb: 2\n---\nc: 3\n";
        let span = spans(raw).unwrap()[1].clone();
        assert_eq!(
            splice(raw, span, "---\nb: 20\n"),
            "a: 1\n---\nb: 20\n---\nc: 3\n"
        );
    }

    #[test]
    fn patching_the_middle_document_leaves_its_neighbours_byte_for_byte() {
        let raw = "a: 1 # first\n---\nb: 2\n---\nc: 3 # third\n";
        let span = spans(raw).unwrap()[1].clone();
        let patch = yamlpatch::Patch {
            route: yamlpath::route!["b"],
            operation: yamlpatch::Op::Remove,
        };
        let out = patch_document(raw, span, std::slice::from_ref(&patch)).unwrap();
        assert!(out.starts_with("a: 1 # first\n---\n"), "{out:?}");
        assert!(out.ends_with("---\nc: 3 # third\n"), "{out:?}");
        assert!(!out.contains("b: 2"), "{out:?}");
    }

    #[test]
    fn patching_the_first_document_leaves_the_rest_byte_for_byte() {
        let raw = "a: 1\nkeep: me\n---\nb: 2 # second\n";
        let span = spans(raw).unwrap()[0].clone();
        let patch = yamlpatch::Patch {
            route: yamlpath::route!["a"],
            operation: yamlpatch::Op::Remove,
        };
        let out = patch_document(raw, span, std::slice::from_ref(&patch)).unwrap();
        assert!(out.ends_with("---\nb: 2 # second\n"), "{out:?}");
        assert!(out.contains("keep: me"), "{out:?}");
        assert!(!out.contains("a: 1"), "{out:?}");
    }

    #[test]
    fn crlf_survives_a_splice() {
        let raw = "a: 1\r\nkeep: me\r\n---\r\nb: 2\r\n";
        let span = spans(raw).unwrap()[0].clone();
        let patch = yamlpatch::Patch {
            route: yamlpath::route!["a"],
            operation: yamlpatch::Op::Remove,
        };
        let out = patch_document(raw, span, std::slice::from_ref(&patch)).unwrap();
        assert!(
            out.contains("keep: me\r\n"),
            "line endings rewritten: {out:?}"
        );
        assert!(out.ends_with("b: 2\r\n"), "{out:?}");
    }

    #[test]
    fn stripping_meta_written_first_leaves_no_blank_line() {
        let document = "slipmesh:\n    kind: patch\napiVersion: v1alpha1\nkind: KubeletConfig\n";
        assert_eq!(
            strip_meta(document).unwrap(),
            "apiVersion: v1alpha1\nkind: KubeletConfig\n"
        );
    }

    #[test]
    fn stripping_meta_written_last_keeps_a_trailing_comment() {
        let document =
            "apiVersion: v1alpha1\nkind: KubeletConfig\nslipmesh:\n    kind: patch\n# why\n";
        let out = strip_meta(document).unwrap();
        assert!(out.contains("# why"), "{out:?}");
        assert!(!out.contains("slipmesh:"), "{out:?}");
    }

    #[test]
    fn a_comment_indented_inside_the_meta_block_goes_with_it() {
        let document = "apiVersion: v1alpha1\nkind: KubeletConfig\nslipmesh:\n    kind: patch\n    # meta note\n";
        assert_eq!(
            strip_meta(document).unwrap(),
            "apiVersion: v1alpha1\nkind: KubeletConfig\n"
        );
    }

    #[test]
    fn removing_a_block_keeps_the_comment_that_introduces_the_next_one() {
        let document = "a: 1\npools:\n  - name: x\n    port: 1\n\n# where traffic bypasses the mesh\nbypass: []\n";
        assert_eq!(
            remove_key(document, "pools").unwrap(),
            "a: 1\n\n# where traffic bypasses the mesh\nbypass: []\n"
        );
    }

    #[test]
    fn removing_the_last_block_leaves_the_rest_as_it_was() {
        let document = "a: 1  # kept\nruleset: |\n  table inet t {}\n";
        assert_eq!(remove_key(document, "ruleset").unwrap(), "a: 1  # kept\n");
    }

    #[test]
    fn blanking_a_key_keeps_every_other_line_where_it_was() {
        let document = "slipmesh:\n  kind: network\ncluster:\n  bgp_as: 1\n";
        let blanked = blank_key(document, "slipmesh").unwrap();
        assert_eq!(blanked, "\n\ncluster:\n  bgp_as: 1\n");
    }

    #[test]
    fn stripping_meta_that_is_not_there_changes_nothing() {
        let document = "apiVersion: v1alpha1\nkind: KubeletConfig\n";
        assert_eq!(strip_meta(document).unwrap(), document);
    }

    // What a text split on the document marker gets wrong, and what this module decides on top
    // of the grammar: which markers to strip, what to do with a file that will not parse, and
    // where the bytes before the first document belong.

    #[test]
    fn each_document_comes_with_the_span_it_was_cut_from() {
        let raw = "a: 1
---
# b's note
b: 2
";
        let found = documents(raw).unwrap();
        let spans_found: Vec<_> = found.iter().map(|(span, _)| span.clone()).collect();
        assert_eq!(spans_found, spans(raw).unwrap());
        assert_eq!(
            found[1].1,
            "# b's note
b: 2"
        );
    }

    #[test]
    fn a_document_with_nothing_in_it_is_not_one() {
        let raw = "a: 1
---
";
        assert_eq!(documents(raw).unwrap().len(), 1);
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
    fn a_file_of_only_comments_is_kept_whole() {
        let raw = "# a note someone left, and nothing else\n";
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
}
