//! What this tool adds to `slipmesh.yaml`, written in the layout sops writes YAML in.
//!
//! sops re-emits a whole file through the go-yaml v3 emitter every time it writes one, so text
//! laid out any other way would move again on the next encryption. That emitter nests a
//! collection at the next multiple of four past its parent's column, puts a mapping that is a
//! sequence item two columns past the dash, and quotes a string only where a plain one would read
//! back as something else: double quotes for what looks like a number, bool or null, single quotes
//! for the rest.

use anyhow::{Context, Result, bail};
use yaml_serde::Value;
use yamlpatch::Style;

const INDENT: usize = 4;

/// Words YAML 1.1 reads as a bool or null. YAML 1.2 reads them as strings, but go-yaml quotes them
/// anyway, for readers still on 1.1.
const YAML_1_1_WORDS: &[&str] = &[
    "y", "Y", "yes", "Yes", "YES", "n", "N", "no", "No", "NO", "on", "On", "ON", "off", "Off",
    "OFF", "true", "True", "TRUE", "false", "False", "FALSE", "null", "Null", "NULL", "~",
];

/// `source` with `entries` added to the end of the mapping at `route`, after its last line of
/// content. A flow mapping takes them in its own flow style.
pub fn append_to_mapping(
    source: &str,
    route: &yamlpath::Route,
    entries: &[(&str, Value)],
) -> Result<String> {
    let doc = yamlpath::Document::new(source).context("parsing the document")?;
    let feature = feature_at(&doc, route)?;
    match Style::from_feature(&feature, &doc) {
        Style::BlockMapping => {
            let column = yamlpatch::extract_leading_indentation_for_block_item(&doc, &feature);
            let mut lines = Vec::new();
            for (key, value) in entries {
                entry(key, value, column, &mut lines)?;
            }
            Ok(insert_after_content(&doc, &feature, &lines))
        }
        Style::FlowMapping => {
            let patches: Vec<yamlpatch::Patch> = entries
                .iter()
                .map(|(key, value)| yamlpatch::Patch {
                    route: route.clone(),
                    operation: yamlpatch::Op::Add {
                        key: (*key).to_owned(),
                        value: value.clone(),
                    },
                })
                .collect();
            let patched = yamlpatch::apply_yaml_patches(&doc, &patches)
                .with_context(|| format!("adding to the flow mapping at {route:?}"))?;
            Ok(patched.source().to_owned())
        }
        other => bail!("{route:?} is a {other:?}, not a mapping to add to"),
    }
}

/// `source` with `item` appended to the sequence at `route`. An empty flow sequence, `[]`, becomes
/// a block sequence holding `item`.
pub fn append_to_sequence(source: &str, route: &yamlpath::Route, item: &Value) -> Result<String> {
    let doc = yamlpath::Document::new(source).context("parsing the document")?;
    let feature = feature_at(&doc, route)?;
    let mut lines = Vec::new();
    match Style::from_feature(&feature, &doc) {
        Style::BlockSequence => {
            let dash = yamlpatch::extract_leading_whitespace(&doc, &feature).len();
            sequence_item(item, dash, &mut lines)?;
            Ok(insert_after_content(&doc, &feature, &lines))
        }
        Style::FlowSequence if doc.extract(&feature).trim() == "[]" => {
            let key = yamlpatch::extract_leading_indentation_for_block_item(&doc, &feature);
            sequence_item(item, nested(key), &mut lines)?;
            let (start, end) = feature.location.byte_span;
            // The space after the key's colon goes too, or the key's line would end in it.
            let start = source[..start].trim_end_matches(' ').len();
            let mut out = source.to_owned();
            out.replace_range(start..end, &format!("\n{}", lines.join("\n")));
            Ok(out)
        }
        other => bail!("{route:?} is a {other:?} - only a block sequence or `[]` takes an item"),
    }
}

fn feature_at<'doc>(
    doc: &'doc yamlpath::Document,
    route: &yamlpath::Route,
) -> Result<yamlpath::Feature<'doc>> {
    if route.is_empty() {
        return doc.top_feature().context("the document is empty");
    }
    doc.query_exact(route)
        .with_context(|| format!("locating {route:?}"))?
        .with_context(|| format!("{route:?} is empty"))
}

/// `lines` inserted after the last line of content in `feature`, in front of any comments that
/// close it.
fn insert_after_content(
    doc: &yamlpath::Document,
    feature: &yamlpath::Feature,
    lines: &[String],
) -> String {
    let at = yamlpatch::find_content_end(feature, doc);
    let source = doc.source();
    let text = lines.join("\n");
    let mut out = source.to_owned();
    if source[..at].ends_with('\n') {
        out.insert_str(at, &format!("{text}\n"));
    } else {
        out.insert_str(at, &format!("\n{text}"));
    }
    out
}

/// Where a collection nested under a line at `column` starts.
fn nested(column: usize) -> usize {
    (column + INDENT) / INDENT * INDENT
}

/// `key: value` at `column`, a collection value on the lines below it.
fn entry(key: &str, value: &Value, column: usize, out: &mut Vec<String>) -> Result<()> {
    let head = format!("{}{}:", " ".repeat(column), string(key));
    match value {
        Value::Mapping(fields) if !fields.is_empty() => {
            out.push(head);
            for (key, value) in fields {
                let key = key.as_str().context("a mapping key that is not a string")?;
                entry(key, value, nested(column), out)?;
            }
        }
        Value::Sequence(items) if !items.is_empty() => {
            out.push(head);
            for item in items {
                sequence_item(item, nested(column), out)?;
            }
        }
        _ => out.push(format!("{head} {}", scalar(value)?)),
    }
    Ok(())
}

/// One sequence item with its dash at `column`. A collection in it starts on the dash's line, two
/// columns past it.
fn sequence_item(value: &Value, column: usize, out: &mut Vec<String>) -> Result<()> {
    let inner = column + 2;
    let mut lines = Vec::new();
    match value {
        Value::Mapping(fields) if !fields.is_empty() => {
            for (key, value) in fields {
                let key = key.as_str().context("a mapping key that is not a string")?;
                entry(key, value, inner, &mut lines)?;
            }
        }
        Value::Sequence(items) if !items.is_empty() => {
            for item in items {
                sequence_item(item, inner, &mut lines)?;
            }
        }
        _ => {
            out.push(format!("{}- {}", " ".repeat(column), scalar(value)?));
            return Ok(());
        }
    }
    lines[0].replace_range(column..inner, "- ");
    out.extend(lines);
    Ok(())
}

/// One scalar as the emitter writes it.
fn scalar(value: &Value) -> Result<String> {
    Ok(match value {
        Value::Null => "null".to_owned(),
        Value::Bool(b) => b.to_string(),
        Value::Number(n) => n.to_string(),
        Value::String(s) => string(s),
        Value::Sequence(items) if items.is_empty() => "[]".to_owned(),
        Value::Mapping(fields) if fields.is_empty() => "{}".to_owned(),
        other => bail!("{other:?} is not a scalar"),
    })
}

fn string(s: &str) -> String {
    let looks_like_another_type = s.is_empty()
        || YAML_1_1_WORDS.contains(&s)
        || matches!(
            yaml_serde::from_str::<Value>(s),
            Ok(Value::Number(_) | Value::Bool(_))
        );
    if looks_like_another_type {
        return double_quoted(s);
    }
    let reads_back = yaml_serde::from_str::<Value>(&format!("k: {s}"))
        .is_ok_and(|v| v.get("k").and_then(Value::as_str) == Some(s));
    if reads_back {
        s.to_owned()
    } else if s.chars().any(char::is_control) {
        double_quoted(s)
    } else {
        format!("'{}'", s.replace('\'', "''"))
    }
}

fn double_quoted(s: &str) -> String {
    let mut out = String::from("\"");
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\t' => out.push_str("\\t"),
            '\r' => out.push_str("\\r"),
            c if c.is_control() => out.push_str(&format!("\\u{:04X}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use yamlpath::route;

    fn mapping(entries: &[(&str, Value)]) -> Value {
        Value::Mapping(
            entries
                .iter()
                .map(|(k, v)| (Value::from(*k), v.clone()))
                .collect(),
        )
    }

    #[test]
    fn a_scalar_joins_a_mapping_that_is_a_sequence_item() {
        let source = "nodes:\n    - name: node-a\n      node_id: 10.62.0.1\n    - name: node-b\n      node_id: 10.62.0.2\n";
        let out = append_to_mapping(
            source,
            &route!["nodes", 0],
            &[("mesh_private_key", "S0VZ".into())],
        )
        .unwrap();
        assert_eq!(
            out,
            "nodes:\n    - name: node-a\n      node_id: 10.62.0.1\n      mesh_private_key: S0VZ\n    - name: node-b\n      node_id: 10.62.0.2\n"
        );
    }

    #[test]
    fn a_mapping_nests_at_the_next_multiple_of_four() {
        let source = "mesh:\n    links:\n        - pair:\n            - node-a\n            - node-b\n          port: 51820\n";
        let obfuscation = mapping(&[("jc", 4.into()), ("jmin", 81.into())]);
        let out = append_to_mapping(
            source,
            &route!["mesh", "links", 0],
            &[("obfuscation", obfuscation)],
        )
        .unwrap();
        assert_eq!(
            out,
            "mesh:\n    links:\n        - pair:\n            - node-a\n            - node-b\n          port: 51820\n          obfuscation:\n            jc: 4\n            jmin: 81\n"
        );
    }

    #[test]
    fn fields_join_a_nested_mapping_beside_the_ones_there() {
        let source =
            "links:\n    - port: 51820\n      obfuscation:\n        jc: 9\n    - port: 51821\n";
        let out = append_to_mapping(
            source,
            &route!["links", 0, "obfuscation"],
            &[("jmin", 81.into()), ("jmax", 408.into())],
        )
        .unwrap();
        assert_eq!(
            out,
            "links:\n    - port: 51820\n      obfuscation:\n        jc: 9\n        jmin: 81\n        jmax: 408\n    - port: 51821\n"
        );
    }

    #[test]
    fn an_entry_goes_in_front_of_the_comments_that_end_the_mapping() {
        let source =
            "slipmesh:\n    kind: roadwarriors\nname: plain\nclients: []\n# a closing note\n";
        let out = append_to_mapping(source, &route![], &[("private_key", "S0VZ".into())]).unwrap();
        assert_eq!(
            out,
            "slipmesh:\n    kind: roadwarriors\nname: plain\nclients: []\nprivate_key: S0VZ\n# a closing note\n"
        );
    }

    #[test]
    fn a_flow_mapping_stays_flow() {
        let source = "nodes:\n  - {name: node-a, node_id: \"10.62.0.1\"}\n";
        let out = append_to_mapping(
            source,
            &route!["nodes", 0],
            &[("mesh_private_key", "S0VZ".into())],
        )
        .unwrap();
        assert_eq!(out.lines().count(), 2, "{out}");
        let value: Value = yaml_serde::from_str(&out).unwrap();
        assert_eq!(value["nodes"][0]["mesh_private_key"], "S0VZ");
        assert_eq!(value["nodes"][0]["node_id"], "10.62.0.1");
    }

    fn client() -> Value {
        mapping(&[
            ("name", "dave".into()),
            ("public_key", "RERE".into()),
            (
                "allowed_ips",
                Value::Sequence(vec!["198.51.100.99/32".into()]),
            ),
        ])
    }

    #[test]
    fn a_mapping_item_puts_its_list_two_past_its_keys() {
        let source = "clients:\n    - name: carol\n      public_key: Q0ND\n      allowed_ips:\n        - 203.0.113.22/32\nplain: true\n";
        let out = append_to_sequence(source, &route!["clients"], &client()).unwrap();
        assert_eq!(
            out,
            "clients:\n    - name: carol\n      public_key: Q0ND\n      allowed_ips:\n        - 203.0.113.22/32\n    - name: dave\n      public_key: RERE\n      allowed_ips:\n        - 198.51.100.99/32\nplain: true\n"
        );
    }

    #[test]
    fn an_empty_flow_sequence_becomes_a_block_one() {
        let source = "name: plain\nclients: []\nplain: true\n";
        let out = append_to_sequence(source, &route!["clients"], &client()).unwrap();
        assert_eq!(
            out,
            "name: plain\nclients:\n    - name: dave\n      public_key: RERE\n      allowed_ips:\n        - 198.51.100.99/32\nplain: true\n"
        );
    }

    #[test]
    fn a_sequence_item_that_is_a_sequence_nests_two_past_its_dash() {
        let source = "lists:\n    - - a\n      - b\n";
        let item = Value::Sequence(vec!["c".into(), "d".into()]);
        let out = append_to_sequence(source, &route!["lists"], &item).unwrap();
        assert_eq!(out, "lists:\n    - - a\n      - b\n    - - c\n      - d\n");
    }

    #[test]
    fn a_string_is_plain_where_it_reads_back_as_itself() {
        for plain in [
            "phone",
            "node-a",
            "S0VZ+/x=",
            "198.51.100.2/32",
            "2001:db8::2/128",
        ] {
            assert_eq!(scalar(&plain.into()).unwrap(), plain);
        }
    }

    #[test]
    fn a_string_that_looks_like_another_type_is_double_quoted() {
        for (string, written) in [
            ("51821", "\"51821\""),
            ("yes", "\"yes\""),
            ("on", "\"on\""),
            ("y", "\"y\""),
            ("null", "\"null\""),
            ("1e3", "\"1e3\""),
            ("", "\"\""),
        ] {
            assert_eq!(scalar(&string.into()).unwrap(), written, "{string}");
        }
    }

    #[test]
    fn a_string_plain_syntax_cannot_carry_is_single_quoted() {
        assert_eq!(scalar(&"a: b".into()).unwrap(), "'a: b'");
        assert_eq!(scalar(&"it's #1".into()).unwrap(), "'it''s #1'");
        assert_eq!(scalar(&" padded".into()).unwrap(), "' padded'");
    }

    #[test]
    fn a_string_with_a_line_break_is_double_quoted_with_escapes() {
        assert_eq!(
            scalar(&"one\ntwo \"x\"".into()).unwrap(),
            "\"one\\ntwo \\\"x\\\"\""
        );
    }

    #[test]
    fn numbers_and_bools_are_written_as_they_are() {
        assert_eq!(scalar(&4.into()).unwrap(), "4");
        assert_eq!(scalar(&2249923740u64.into()).unwrap(), "2249923740");
        assert_eq!(scalar(&true.into()).unwrap(), "true");
    }
}
