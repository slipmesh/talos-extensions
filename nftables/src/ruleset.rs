//! Applies `NftablesConfig::ruleset` (already placeholder-substituted, see `main.rs`) via a
//! vendored, statically-linked `nft` binary (subprocess) - raw NFNETLINK (`rustables`) can't
//! express the MSS-clamp statement this workspace's first real ruleset needs (`tcp option maxseg
//! size set rt mtu`), a limitation already hit and documented by the sibling k8s-operator this
//! extension mirrors (`operators/nftables/src/nftables.rs`'s own doc comment).
//!
//! Doesn't parse or understand the ruleset's *content* - only scans it for `table <family> <name>`
//! declarations, to `delete table` each one (idempotent, ignores "doesn't exist yet") before
//! reapplying. This is the whole answer to "how does this loader avoid piling up duplicate/stale
//! rules on every reapply": identify by whatever the *current* config itself declares, not by a
//! name hardcoded in this binary (unlike `operators/nftables`, which hardcodes
//! `nftables_operator_filter`/`nftables_operator_nat` in Rust - here the table names live in the
//! operator-authored `ruleset:` text instead). Not `flush ruleset`: something else on the same
//! node (kube-proxy, Talos's own ingress firewall, ...) may have its own nftables tables that must
//! survive this.
//!
//! Whoever authors `ruleset:` should avoid `comment` annotations on `set`/`map` declarations:
//! nftables >= 1.1.3 changed the on-wire userdata format those produce, which kube-proxy's own
//! bundled (older) `nft` can't parse during a full resync and segfaults on
//! (kubernetes/kubernetes#136786, unfixed as of Kubernetes 1.36) - this is exactly why
//! `../talos-nftables-extension/versions.env` deliberately pins `NFTABLES_VERSION` below 1.1.3
//! rather than latest, but staying off `comment` on sets/maps is a second, independent safeguard
//! this binary can't enforce on its own (it doesn't parse ruleset content, see above).
//!
//! **Why this daemon watches for its own tables disappearing** (see `main.rs`'s watchdog loop):
//! something on a freshly-booted Talos+Kubernetes node (most likely the first
//! `iptables`/`ip6tables` invocation transitioning into iptables-nft mode, timed around
//! kubelet/kube-proxy's own first sync) does a one-time broad nftables reset that can catch tables
//! it doesn't recognize, including ours, if our own apply happens to run before that reset.
//! Apply-then-reset wipes us; apply-after-reset coexists indefinitely. Which side of that race we
//! land on depends on scheduling, not on anything in our control, so a bare "apply once and hope"
//! isn't reliable.

use anyhow::{Context, Result};
use std::collections::HashSet;
use tokio::io::AsyncWriteExt;
use tokio::process::Command;

/// Relative to this service's own entrypoint directory - the vendored static `nft` binary is
/// staged into the same `rootfs/usr/local/lib/containers/nftables/` directory as this binary (the
/// `install:` step in `slipmesh/talos-nftables-extension`'s `patches/extensions/nftables/pkg.yaml`),
/// the same convention `router/src/main.rs`'s `BIRD_BIN` uses for `bird`.
pub const NFT_BIN: &str = "./nft";

/// `table <family> <name> {` at the start of a (non-comment) line - deliberately simple: this
/// workspace's config is authored by whoever writes the `ExtensionServiceConfig`, not arbitrary
/// untrusted input, so this only needs to find genuine table declarations, not defend against
/// adversarial text trying to look like one.
fn declared_tables(ruleset: &str) -> Vec<(String, String)> {
    ruleset
        .lines()
        .filter_map(|line| {
            let line = line.trim_start();
            if line.starts_with('#') {
                return None;
            }
            let rest = line.strip_prefix("table ")?;
            let mut parts = rest.split_whitespace();
            let family = parts.next()?;
            let name = parts.next()?;
            Some((family.to_string(), name.to_string()))
        })
        .collect()
}

pub async fn apply(ruleset: &str) -> Result<()> {
    for (family, name) in declared_tables(ruleset) {
        // Errors ignored: the delete fails (harmlessly) whenever this table doesn't exist yet -
        // first run ever, or a table this particular config version just introduced.
        let _ = Command::new(NFT_BIN)
            .arg("delete")
            .arg("table")
            .arg(&family)
            .arg(&name)
            .status()
            .await;
    }

    let mut child = Command::new(NFT_BIN)
        .args(["-f", "-"])
        .stdin(std::process::Stdio::piped())
        .spawn()
        .with_context(|| format!("failed to spawn {NFT_BIN}"))?;
    child
        .stdin
        .take()
        .expect("just configured with Stdio::piped()")
        .write_all(ruleset.as_bytes())
        .await
        .context("failed to write ruleset to nft stdin")?;
    let status = child.wait().await.context("failed waiting on nft")?;
    anyhow::ensure!(
        status.success(),
        "{NFT_BIN} -f failed with status {status:?}"
    );

    tracing::info!("nftables ruleset applied");
    Ok(())
}

/// Whether every table `ruleset` declares still exists in the kernel's live nftables state - the
/// watchdog's own check, run whenever `nft monitor` (see `main.rs`) reports *any* event, not just
/// ones that look like a deletion of one of our tables specifically: parsing `nft monitor`'s
/// output precisely enough to identify exactly which table/family a given line refers to would
/// depend on its exact text format, which isn't a stable contract - re-listing and comparing our
/// own known set is a few milliseconds and doesn't depend on that.
pub async fn all_present(ruleset: &str) -> Result<bool> {
    let wanted = declared_tables(ruleset);
    if wanted.is_empty() {
        return Ok(true);
    }
    let output = Command::new(NFT_BIN)
        .args(["list", "tables"])
        .output()
        .await
        .with_context(|| format!("failed to run {NFT_BIN} list tables"))?;
    anyhow::ensure!(
        output.status.success(),
        "{NFT_BIN} list tables failed with status {:?}",
        output.status
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    // Each line is `table <family> <name>` - same shape as a `declared_tables` line, minus the
    // trailing `{`.
    let existing: HashSet<(&str, &str)> = stdout
        .lines()
        .filter_map(|line| {
            let rest = line.trim().strip_prefix("table ")?;
            let mut parts = rest.split_whitespace();
            Some((parts.next()?, parts.next()?))
        })
        .collect();
    Ok(wanted
        .iter()
        .all(|(family, name)| existing.contains(&(family.as_str(), name.as_str()))))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn declared_tables_finds_every_table_header() {
        let ruleset = "table inet talos_filter {\n    chain forward { }\n}\ntable ip talos_nat {\n    chain postrouting { }\n}\n";
        assert_eq!(
            declared_tables(ruleset),
            vec![
                ("inet".to_string(), "talos_filter".to_string()),
                ("ip".to_string(), "talos_nat".to_string()),
            ]
        );
    }

    #[test]
    fn declared_tables_ignores_commented_lines() {
        let ruleset = "# table ip6 not_real {\ntable ip6 talos_nat6 {\n";
        assert_eq!(
            declared_tables(ruleset),
            vec![("ip6".to_string(), "talos_nat6".to_string())]
        );
    }

    #[test]
    fn declared_tables_handles_indentation() {
        let ruleset = "    table inet talos_filter {\n";
        assert_eq!(
            declared_tables(ruleset),
            vec![("inet".to_string(), "talos_filter".to_string())]
        );
    }

    #[test]
    fn declared_tables_empty_ruleset_finds_nothing() {
        assert_eq!(declared_tables(""), Vec::<(String, String)>::new());
    }
}
