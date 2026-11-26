//! Applies `NftablesConfig::ruleset` (already placeholder-substituted, see `main.rs`) via a
//! vendored, statically-linked `nft` binary (subprocess) - raw NFNETLINK (`rustables`) can't
//! express the MSS-clamp statement this workspace's first real ruleset needs (`tcp option maxseg
//! size set rt mtu`).
//!
//! Doesn't parse or understand the ruleset's *content* - only scans it for `table <family> <name>`
//! declarations, to replace each one in the transaction that loads the ruleset (see
//! [`transaction`]). This is the whole answer to "how does this loader avoid piling up
//! duplicate/stale rules on every reapply": identify by whatever the *current* config itself
//! declares, not by a name hardcoded in this binary. Not `flush ruleset`: something else on the same
//! node (kube-proxy, Talos's own ingress firewall, ...) may have its own nftables tables that must
//! survive this.
//!
//! Whoever authors `ruleset:` should avoid `comment` annotations on `set`/`map` declarations:
//! nftables >= 1.1.3 changed the on-wire userdata format those produce, and kube-proxy's bundled
//! `nft` before Kubernetes 1.36.3 segfaults on it during a full resync
//! (kubernetes/kubernetes#136786). This binary cannot enforce that; it does not parse ruleset
//! content (see above).
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
use tokio::sync::Mutex;

/// Relative to this service's own entrypoint directory: the extension stages its static `nft` in
/// `/usr/local/lib/containers/nftables/` beside this binary, as `router/src/main.rs`'s `BIRD_BIN`
/// does for `bird`.
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

/// Applies `rendered` unless it is the ruleset in force, and makes it the one in force. Holds
/// `in_force` meanwhile, so that no one reapplies the ruleset `rendered` is replacing.
pub async fn replace(in_force: &Mutex<String>, rendered: String) -> Result<()> {
    let mut in_force = in_force.lock().await;
    if *in_force != rendered {
        apply(&rendered).await?;
        *in_force = rendered;
    }
    Ok(())
}

/// `ruleset`, after a `table` and a `delete table` for each table it declares: the `table` makes
/// the delete succeed on a table not loaded yet, and in one `nft -f` the old tables go only if
/// the whole ruleset loads.
fn transaction(ruleset: &str) -> String {
    let mut text: String = declared_tables(ruleset)
        .into_iter()
        .map(|(family, name)| format!("table {family} {name}\ndelete table {family} {name}\n"))
        .collect();
    text.push_str(ruleset);
    text
}

pub async fn apply(ruleset: &str) -> Result<()> {
    let mut child = Command::new(NFT_BIN)
        .args(["-f", "-"])
        .stdin(std::process::Stdio::piped())
        .spawn()
        .with_context(|| format!("failed to spawn {NFT_BIN}"))?;
    child
        .stdin
        .take()
        .context("nft has no stdin")?
        .write_all(transaction(ruleset).as_bytes())
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
    fn a_ruleset_replaces_the_tables_it_declares_in_the_same_transaction() {
        assert_eq!(
            transaction("table inet t {\n}\ntable ip n {\n}\n"),
            "table inet t\ndelete table inet t\ntable ip n\ndelete table ip n\n\
             table inet t {\n}\ntable ip n {\n}\n"
        );
    }

    #[tokio::test]
    async fn only_a_changed_rendering_is_applied_and_only_an_applied_one_is_in_force() {
        let in_force = Mutex::new("table inet t {\n}\n".to_owned());
        replace(&in_force, "table inet t {\n}\n".to_owned())
            .await
            .unwrap();
        // No `nft` beside the test, so an apply fails.
        assert!(
            replace(&in_force, "table inet u {\n}\n".to_owned())
                .await
                .is_err()
        );
        assert_eq!(*in_force.lock().await, "table inet t {\n}\n");
    }

    #[test]
    fn declared_tables_finds_every_table_header_indented_or_not_and_no_comment() {
        let table = |family: &str, name: &str| (family.to_string(), name.to_string());
        for (ruleset, tables) in [
            (
                "table inet talos_filter {\n    chain forward { }\n}\ntable ip talos_nat {\n    chain postrouting { }\n}\n",
                vec![table("inet", "talos_filter"), table("ip", "talos_nat")],
            ),
            (
                "# table ip6 not_real {\ntable ip6 talos_nat6 {\n",
                vec![table("ip6", "talos_nat6")],
            ),
            (
                "    table inet talos_filter {\n",
                vec![table("inet", "talos_filter")],
            ),
        ] {
            assert_eq!(declared_tables(ruleset), tables, "{ruleset}");
        }
    }
}
