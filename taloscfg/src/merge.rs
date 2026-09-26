//! Merging `patch` documents of one identity - a default and the host-specific documents over it.
//!
//! The semantics are JSON Merge Patch (RFC 7386) applied to YAML: mappings merge recursively, an
//! explicit `null` deletes the key it names, and anything else - a scalar, a sequence - replaces
//! what was there. On top of that, key order is kept: a key the base already has stays where it
//! was, a new one is appended, so a merged document still reads in the order it was written.
//!
//! Sequences are replaced rather than appended, which is not what Talos' own strategic merge does
//! with them. Talos can append to a keyed list by that key because it knows its types; this merge
//! sees schemaless YAML, where appending could neither remove an element nor tell that two
//! `configFiles` entries share a `mountPath`.

use yaml_serde::Value;

/// The Talos directive that turns a document into a deletion. A document carrying it is a message
/// to Talos, not a set of values to merge.
const PATCH_KEY: &str = "$patch";

/// `overlay` merged over `base`. A `$patch: delete` document on either side is not merged: over the
/// base it would turn a deletion into an edit, under the overlay an edit into a deletion - the
/// overlay replaces the result outright.
pub fn merge_document(base: Value, overlay: &Value) -> Value {
    if is_deletion(overlay) || is_deletion(&base) {
        return overlay.clone();
    }
    merge(base, overlay)
}

fn is_deletion(document: &Value) -> bool {
    document.get(PATCH_KEY).and_then(Value::as_str) == Some("delete")
}

fn merge(base: Value, overlay: &Value) -> Value {
    let Some(overlay) = overlay.as_mapping() else {
        return overlay.clone();
    };
    let mut merged = match base {
        Value::Mapping(mapping) => mapping,
        // A mapping over anything else starts from nothing, so its own nulls delete nothing and
        // do not survive as values.
        _ => yaml_serde::Mapping::new(),
    };
    for (key, value) in overlay {
        if value.is_null() {
            // `shift_remove`, not `remove`: the latter swaps the last key into the gap.
            merged.shift_remove(key);
            continue;
        }
        let base_value = merged.get(key).cloned().unwrap_or(Value::Null);
        merged.insert(key.clone(), merge(base_value, value));
    }
    Value::Mapping(merged)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn yaml(text: &str) -> Value {
        yaml_serde::from_str(text).unwrap()
    }

    fn keys(value: &Value) -> Vec<&str> {
        value
            .as_mapping()
            .unwrap()
            .keys()
            .map(|k| k.as_str().unwrap())
            .collect()
    }

    #[test]
    fn the_later_scalar_wins() {
        assert_eq!(merge_document(yaml("a: 1"), &yaml("a: 2")), yaml("a: 2"));
    }

    #[test]
    fn mappings_merge_recursively() {
        let merged = merge_document(
            yaml("extraArgs: {rotate: 'true', level: '2'}"),
            &yaml("extraArgs: {level: '4'}"),
        );
        assert_eq!(merged, yaml("extraArgs: {rotate: 'true', level: '4'}"));
    }

    #[test]
    fn the_base_key_order_is_kept_and_new_keys_are_appended() {
        let merged = merge_document(yaml("a: 1\nb: 2\nc: 3"), &yaml("new: 0\nb: 20"));
        assert_eq!(keys(&merged), ["a", "b", "c", "new"]);
    }

    #[test]
    fn a_sequence_is_replaced_not_concatenated() {
        let merged = merge_document(yaml("list: [x, y]"), &yaml("list: [z]"));
        assert_eq!(merged, yaml("list: [z]"));
    }

    #[test]
    fn an_explicit_null_deletes_the_key_and_keeps_the_rest_in_order() {
        let merged = merge_document(yaml("a: 1\nb: 2\nc: 3\nd: 4"), &yaml("a: null"));
        assert_eq!(keys(&merged), ["b", "c", "d"]);
    }

    #[test]
    fn a_null_for_a_key_the_base_lacks_adds_nothing() {
        let merged = merge_document(yaml("a: 1"), &yaml("b: null"));
        assert_eq!(merged, yaml("a: 1"));
    }

    #[test]
    fn a_key_absent_from_the_overlay_is_inherited() {
        let merged = merge_document(yaml("a: 1\nb: {c: 2}"), &yaml("a: 5"));
        assert_eq!(merged, yaml("a: 5\nb: {c: 2}"));
    }

    #[test]
    fn a_mapping_over_a_scalar_replaces_it_without_its_nulls() {
        let merged = merge_document(yaml("a: 1"), &yaml("a: {b: 2, c: null}"));
        assert_eq!(merged, yaml("a: {b: 2}"));
    }

    #[test]
    fn a_delete_directive_on_the_overlay_replaces_the_result() {
        let overlay = yaml("apiVersion: v1alpha1\nkind: KubeletConfig\n$patch: delete");
        let merged = merge_document(
            yaml("apiVersion: v1alpha1\nkind: KubeletConfig\nextraArgs: {a: b}"),
            &overlay,
        );
        assert_eq!(merged, overlay);
    }

    #[test]
    fn a_document_over_a_delete_directive_replaces_it() {
        let overlay = yaml("apiVersion: v1alpha1\nkind: KubeletConfig\nextraArgs: {a: b}");
        let merged = merge_document(
            yaml("apiVersion: v1alpha1\nkind: KubeletConfig\n$patch: delete"),
            &overlay,
        );
        assert_eq!(merged, overlay);
    }

    #[test]
    fn a_nested_patch_key_is_an_ordinary_key() {
        let merged = merge_document(
            yaml("machine: {install: {disk: /dev/vda}}"),
            &yaml("machine: {install: {$patch: delete}}"),
        );
        assert_eq!(
            merged,
            yaml("machine: {install: {disk: /dev/vda, $patch: delete}}")
        );
    }
}
