//! Removes any `amneziawg`-kind interface on the host that isn't in the current config. Ownership
//! is total: this daemon manages every interface of that netlink kind on the node, so no naming
//! convention or second filter is needed - unlike the two-separate-services design this replaced,
//! there's no "someone else's AWG interface" to avoid stepping on (see AGENTS.md).

use anyhow::Result;
use common::netlink::rt::RtClient;
use std::collections::HashSet;

pub async fn gc(rt: &RtClient, desired_names: &HashSet<&str>) -> Result<()> {
    for (name, index) in rt.list_links_by_kind("amneziawg").await? {
        if desired_names.contains(name.as_str()) {
            continue;
        }
        tracing::info!(iface = name, "removing interface no longer in config");
        rt.delete_link(index).await?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    // `gc` itself is a thin netlink shim (real link listing/deletion) - nothing pure to unit-test
    // beyond what `RtClient::list_links_by_kind`'s own tests already cover. Exercised end-to-end in
    // the local netns smoke test (see README).
}
