//! Merging `patch` documents of one identity - a default and the host-specific documents over it.
//!
//! The merge itself is `sliplib_yaml::merge`, JSON Merge Patch (RFC 7386) with key order kept; on
//! top of it comes Talos' `$patch: delete` directive.
//!
//! Sequences are replaced rather than appended, which is not what Talos' own strategic merge does
//! with them. Talos can append to a keyed list by that key because it knows its types; this merge
//! sees schemaless YAML, where appending could neither remove an element nor tell that two
//! `configFiles` entries share a `mountPath`.

use sliplib_yaml::Value;

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
    sliplib_yaml::merge(base, overlay)
}

pub(crate) fn is_deletion(document: &Value) -> bool {
    document.get(PATCH_KEY).and_then(Value::as_str) == Some("delete")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn yaml(text: &str) -> Value {
        sliplib_yaml::from_str(text).unwrap()
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
