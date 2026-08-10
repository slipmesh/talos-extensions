//! Minimal `{{ name }}` placeholder substitution for `NftablesConfig::ruleset` - not a general
//! templating engine (no conditionals/loops, no external crate), just enough to inject values that
//! can't be known when the ruleset text is written (currently: which interface carries the
//! default route, per address family - see `main.rs`).

use std::collections::{HashMap, HashSet};

/// Every placeholder name this binary knows how to fill in. Adding a new one is: add it here, add
/// a corresponding lookup in `main.rs`'s `run`.
pub const KNOWN_PLACEHOLDERS: &[&str] =
    &["defaultroute_interface_ipv4", "defaultroute_interface_ipv6"];

/// Scans `s` for `{{ ... }}`-shaped spans, yielding `(start_byte, end_byte, trimmed_name)` for
/// each - the single primitive both `referenced_placeholders` and `substitute` build on, so
/// whitespace inside the braces (`{{name}}`, `{{  name  }}`, ...) is handled identically by both
/// instead of one matching more forms than the other.
fn placeholder_spans(s: &str) -> Vec<(usize, usize, &str)> {
    let mut out = Vec::new();
    let mut search_from = 0;
    while let Some(rel_start) = s[search_from..].find("{{") {
        let start = search_from + rel_start;
        let after = &s[start + 2..];
        let Some(rel_end) = after.find("}}") else {
            break;
        };
        let name_end = start + 2 + rel_end;
        let name = s[start + 2..name_end].trim();
        out.push((start, name_end + 2, name));
        search_from = name_end + 2;
    }
    out
}

/// Every `{{ name }}`-shaped token appearing in `s`, regardless of whether `name` is known.
pub fn referenced_placeholders(s: &str) -> HashSet<String> {
    placeholder_spans(s)
        .into_iter()
        .map(|(_, _, name)| name.to_string())
        .collect()
}

/// Placeholders referenced in `s` that aren't in `KNOWN_PLACEHOLDERS` - used by `config::validate`
/// to reject typos early instead of feeding literal `{{ typo }}` text to `nft -f`.
pub fn unknown_placeholders(s: &str) -> Vec<String> {
    let mut out: Vec<String> = referenced_placeholders(s)
        .into_iter()
        .filter(|p| !KNOWN_PLACEHOLDERS.contains(&p.as_str()))
        .collect();
    out.sort();
    out
}

/// Replaces every `{{ name }}` span whose (trimmed) name is a key in `values`. A span not in
/// `values` is left as-is verbatim - by the time this runs, `config::validate` has already
/// guaranteed every referenced name is a known placeholder, so this only happens for a known
/// placeholder the caller chose not to resolve (shouldn't occur in practice - `main.rs` resolves
/// every referenced placeholder before calling this).
pub fn substitute(s: &str, values: &HashMap<&str, String>) -> String {
    let mut out = String::with_capacity(s.len());
    let mut last = 0;
    for (start, end, name) in placeholder_spans(s) {
        out.push_str(&s[last..start]);
        match values.get(name) {
            Some(value) => out.push_str(value),
            None => out.push_str(&s[start..end]),
        }
        last = end;
    }
    out.push_str(&s[last..]);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn referenced_placeholders_finds_every_token() {
        let s = "a {{ defaultroute_interface_ipv4 }} b {{defaultroute_interface_ipv6}} c";
        let mut found: Vec<String> = referenced_placeholders(s).into_iter().collect();
        found.sort();
        assert_eq!(
            found,
            vec![
                "defaultroute_interface_ipv4".to_string(),
                "defaultroute_interface_ipv6".to_string(),
            ]
        );
    }

    #[test]
    fn referenced_placeholders_empty_text_finds_nothing() {
        assert!(referenced_placeholders("no placeholders here").is_empty());
    }

    #[test]
    fn unknown_placeholders_flags_a_typo() {
        assert_eq!(
            unknown_placeholders("{{ defaultroute_interfac_ipv4 }}"),
            vec!["defaultroute_interfac_ipv4".to_string()]
        );
    }

    #[test]
    fn unknown_placeholders_accepts_known_names() {
        assert!(
            unknown_placeholders(
                "{{ defaultroute_interface_ipv4 }} {{ defaultroute_interface_ipv6 }}"
            )
            .is_empty()
        );
    }

    #[test]
    fn substitute_replaces_a_known_placeholder_regardless_of_inner_whitespace() {
        let mut values = HashMap::new();
        values.insert("defaultroute_interface_ipv4", "eth0".to_string());
        assert_eq!(
            substitute("oifname \"{{defaultroute_interface_ipv4}}\"", &values),
            "oifname \"eth0\""
        );
        assert_eq!(
            substitute("oifname \"{{   defaultroute_interface_ipv4   }}\"", &values),
            "oifname \"eth0\""
        );
    }

    #[test]
    fn substitute_leaves_unresolved_placeholders_untouched() {
        let values = HashMap::new();
        assert_eq!(
            substitute("{{ defaultroute_interface_ipv6 }}", &values),
            "{{ defaultroute_interface_ipv6 }}"
        );
    }

    #[test]
    fn substitute_is_a_no_op_without_placeholders() {
        let values = HashMap::new();
        assert_eq!(substitute("table inet x {}", &values), "table inet x {}");
    }
}
