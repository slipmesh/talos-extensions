//! Config shape: everything `nftables` needs is declared statically, matching `awg`/`router`'s own
//! philosophy - no CRD watching, no env var/CLI flag, always read from a fixed path
//! (`crate::CONFIG_PATH`, see `main.rs`).

use crate::template;
use anyhow::Result;
use serde::{Deserialize, Serialize};

#[derive(Deserialize, Serialize, Debug, PartialEq)]
pub struct NftablesConfig {
    /// Raw nftables-syntax ruleset text, fed to `nft -f` almost verbatim - the only transformation
    /// applied is `{{ name }}` placeholder substitution (see `template.rs`). This binary
    /// deliberately doesn't know or care what rules are inside; see `ruleset::apply` for the only
    /// thing it does inspect (which `table <family> <name>` are declared, to remove them before
    /// reapplying).
    pub ruleset: String,
}

/// Pure, no I/O: rejects any `{{ name }}` placeholder in `cfg.ruleset` that isn't one of
/// `template::KNOWN_PLACEHOLDERS`. Runs before any netlink/subprocess work in `main.rs::run` - a
/// typo'd placeholder should fail loudly and immediately, not survive to become literal `{{ typo
/// }}` text in a confusing `nft -f` syntax error, or worse, waste the default-route retry budget
/// resolving placeholders that were never going to be used.
pub fn validate(cfg: &NftablesConfig) -> Result<()> {
    let unknown = template::unknown_placeholders(&cfg.ruleset);
    anyhow::ensure!(
        unknown.is_empty(),
        "ruleset references unknown placeholder(s): {unknown:?} (known: {:?})",
        template::KNOWN_PLACEHOLDERS
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_minimal_config() {
        let cfg: NftablesConfig =
            serde_yaml::from_str("ruleset: |\n  table inet talos_filter {}\n").unwrap();
        assert_eq!(cfg.ruleset.trim(), "table inet talos_filter {}");
        assert!(validate(&cfg).is_ok());
    }

    #[test]
    fn validate_accepts_known_placeholders() {
        let cfg = NftablesConfig {
            ruleset: "oifname \"{{ defaultroute_interface_ipv4 }}\"".to_string(),
        };
        assert!(validate(&cfg).is_ok());
    }

    #[test]
    fn validate_rejects_an_unknown_placeholder() {
        let cfg = NftablesConfig {
            ruleset: "oifname \"{{ typo_placeholder }}\"".to_string(),
        };
        assert!(validate(&cfg).is_err());
    }

    #[test]
    fn validate_accepts_a_ruleset_with_no_placeholders_at_all() {
        let cfg = NftablesConfig {
            ruleset: "table inet x {}".to_string(),
        };
        assert!(validate(&cfg).is_ok());
    }
}
