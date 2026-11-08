//! Keeps secrets out of what `generate --diff` prints. The daemons' configs sit in a patch file as
//! the text of `content` block scalars, YAML inside YAML, so a secret is found by its field name on
//! a line of its own at any depth, not by parsing the document.

use std::collections::HashSet;

/// Fields whose value is a secret wherever they appear: a WireGuard private key, AmneziaWG's
/// header protection key, and the RouterOS password that a `patch` document passes through.
const SECRET_FIELDS: [&str; 3] = ["private_key", "header_protection_key", "password"];

pub const REDACTED: &str = "<redacted>";
pub const REDACTED_OLD: &str = "<redacted, old>";
pub const REDACTED_NEW: &str = "<redacted, new>";

/// `before` and `after` with every secret value replaced: by [`REDACTED`] where the same value is
/// on both sides, by [`REDACTED_OLD`] or [`REDACTED_NEW`] where it is on one side only. The two
/// sides differ where a secret changed, so a diff of them still shows that it changed, and never
/// the secret.
pub fn mask_pair(before: &str, after: &str) -> (String, String) {
    let values = |text: &str| -> HashSet<String> {
        lines(text)
            .filter_map(|(content, _)| secret(content).map(|(_, value)| value.to_owned()))
            .collect()
    };
    let (in_before, in_after) = (values(before), values(after));
    (
        mask(before, &in_after, REDACTED_OLD),
        mask(after, &in_before, REDACTED_NEW),
    )
}

fn mask(text: &str, other_side: &HashSet<String>, this_side_only: &str) -> String {
    let mut masked = String::with_capacity(text.len());
    for (content, eol) in lines(text) {
        match secret(content) {
            Some((prefix, value)) => {
                masked.push_str(prefix);
                masked.push_str(if other_side.contains(value) {
                    REDACTED
                } else {
                    this_side_only
                });
            }
            None => masked.push_str(content),
        }
        masked.push_str(eol);
    }
    masked
}

/// Each line of `text` and the line ending it carries, so that rejoining them gives `text` back.
fn lines(text: &str) -> impl Iterator<Item = (&str, &str)> {
    text.split_inclusive('\n').map(|line| {
        let content = line.trim_end_matches(['\n', '\r']);
        (content, &line[content.len()..])
    })
}

/// For a line that sets a secret field, the line up to its value and the value itself.
fn secret(line: &str) -> Option<(&str, &str)> {
    let mut rest = line.trim_start_matches(' ');
    while let Some(item) = rest.strip_prefix("- ") {
        rest = item.trim_start_matches(' ');
    }
    let colon = rest.find(':')?;
    let field = rest[..colon].trim_end_matches(' ');
    let after_colon = &line[line.len() - rest.len() + colon + 1..];
    let value = after_colon.trim_start_matches([' ', '\t']);
    let prefix = &line[..line.len() - value.len()];
    let value = value.trim_end_matches([' ', '\t']);
    (SECRET_FIELDS.contains(&field) && !value.is_empty()).then_some((prefix, value))
}

#[cfg(test)]
mod tests {
    use super::*;

    const OLD: &str = "b2xkLWtleS1vbGQta2V5LW9sZC1rZXktb2xkLWtleQ==";
    const NEW: &str = "bmV3LWtleS1uZXcta2V5LW5ldy1rZXktbmV3LWtleQ==";

    #[test]
    fn a_secret_on_both_sides_is_redacted() {
        let text = format!("interfaces:\n- name: mesh-node-b\n  private_key: {OLD}\n");
        let (before, after) = mask_pair(&text, &text);
        let expected = format!("interfaces:\n- name: mesh-node-b\n  private_key: {REDACTED}\n");
        assert_eq!(
            (before.as_str(), after.as_str()),
            (expected.as_str(), expected.as_str())
        );
    }

    #[test]
    fn a_secret_on_one_side_only_is_marked_old_or_new() {
        let (before, after) = mask_pair(
            &format!("    private_key: {OLD}\n"),
            &format!("    private_key: {NEW}\n"),
        );
        assert_eq!(before, format!("    private_key: {REDACTED_OLD}\n"));
        assert_eq!(after, format!("    private_key: {REDACTED_NEW}\n"));
    }

    #[test]
    fn every_secret_field_is_redacted_wherever_it_sits() {
        for line in [
            format!("private_key: {OLD}"),
            format!("      private_key: {OLD}"),
            format!("- private_key: {OLD}"),
            format!("  - private_key: '{OLD}'"),
            format!("      password: {OLD}"),
            format!("        header_protection_key: \"{OLD}\""),
            format!("    private_key:   {OLD}   "),
            format!("private_key :\t{OLD}"),
        ] {
            let (masked, _) = mask_pair(&line, &line);
            assert!(!masked.contains(OLD), "{masked}");
            assert!(masked.ends_with(REDACTED), "{masked}");
        }
    }

    #[test]
    fn other_fields_and_lines_are_left_alone() {
        let text = format!(
            "public_key: {OLD}\nmy_private_key_note: {OLD}\n# private_key: {OLD}\n{OLD}\nprivate_key:\n"
        );
        let (before, after) = mask_pair(&text, &text);
        assert_eq!(
            (before.as_str(), after.as_str()),
            (text.as_str(), text.as_str())
        );
    }

    #[test]
    fn line_endings_are_kept() {
        let text = format!("a\r\nprivate_key: {OLD}\r\nb");
        let (masked, _) = mask_pair(&text, &text);
        assert_eq!(masked, format!("a\r\nprivate_key: {REDACTED}\r\nb"));
    }
}
