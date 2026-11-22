//! What the generator computes of a text, for the files it reads and the patch files it writes.

use sha2::{Digest, Sha256};

/// The SHA-256 of `text`'s bytes, as 64 lower-case hexadecimal digits.
pub fn sha256_hex(text: &str) -> String {
    base16ct::lower::encode_string(&Sha256::digest(text))
}

/// A unified diff from `from` to `to`, headed `from_label` and `to_label`; empty when they are the
/// same.
pub fn unified_diff(from: &str, to: &str, from_label: &str, to_label: &str) -> String {
    similar::TextDiff::from_lines(from, to)
        .unified_diff()
        .header(from_label, to_label)
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_digest_is_the_sha_256_of_the_text_in_lower_case_hexadecimal() {
        assert_eq!(
            sha256_hex("abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    fn diff(from: &str, to: &str) -> String {
        unified_diff(from, to, "from", "to")
    }

    #[test]
    fn the_same_text_has_no_difference() {
        assert_eq!(diff("a\nb\n", "a\nb\n"), "");
    }

    #[test]
    fn a_line_added_shows_as_added_under_the_labels() {
        assert_eq!(
            diff("a\nb\n", "a\nb\nc\n"),
            "--- from\n+++ to\n@@ -1,2 +1,3 @@\n a\n b\n+c\n"
        );
    }

    #[test]
    fn a_text_without_its_final_newline_differs_in_its_last_line() {
        assert_eq!(
            diff("a\nb", "a\nb\n"),
            "--- from\n+++ to\n@@ -1,2 +1,2 @@\n a\n-b\n\\ No newline at end of file\n+b\n"
        );
    }

    #[test]
    fn a_text_with_one_newline_more_differs_by_an_empty_line() {
        assert_eq!(
            diff("a\nb\n\n", "a\nb\n"),
            "--- from\n+++ to\n@@ -1,3 +1,2 @@\n a\n b\n-\n"
        );
    }

    #[test]
    fn an_empty_text_differs_by_every_line() {
        assert_eq!(
            diff("", "a\nb\n"),
            "--- from\n+++ to\n@@ -0,0 +1,2 @@\n+a\n+b\n"
        );
    }
}
