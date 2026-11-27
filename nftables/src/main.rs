use nftables::template::{
    self, CONFIG_PATH, DEFAULT_ROUTE_IPV4, DEFAULT_ROUTE_IPV6, TEMPLATE_PATH,
};
use nftables::{follow, ruleset};

use anyhow::{Context, Result};
use sliplib_net::Family;
use sliplib_net::route::{self as rt, RtClient};
use std::collections::HashMap;
use std::future::Future;
use std::path::Path;
use std::process::Stdio;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::Command;
use tokio::sync::Mutex;

/// Tries of a default-route lookup at start: network bring-up on the node is not synchronized with
/// `depends: [{configuration: true}]`, but a route that never appears is a configuration problem.
const DEFAULT_ROUTE_TRIES: u32 = 10;
const DEFAULT_ROUTE_RETRY_INTERVAL: Duration = Duration::from_secs(2);
/// Inside the 10 s Talos waits after SIGTERM before it sends SIGKILL.
const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(5);

#[tokio::main]
async fn main() -> Result<()> {
    sliplib_runtime::init_tracing();
    tracing::info!("{} {}", env!("CARGO_BIN_NAME"), env!("CARGO_PKG_VERSION"));
    // The ruleset stays loaded: a restart must not leave the node without its firewall.
    sliplib_runtime::serve("nftables", SHUTDOWN_TIMEOUT, async |shutdown| {
        tokio::select! {
            result = run() => result,
            () = shutdown.requested() => {
                tracing::info!("SIGTERM received, exiting with the ruleset left in place");
                Ok(())
            }
        }
    })
    .await
}

async fn run() -> Result<()> {
    let values = template::read_values(Path::new(CONFIG_PATH))?;
    let template = common::template::load(TEMPLATE_PATH, template::compile).await?;

    let referenced = template.variables();
    tracing::info!(variables = ?referenced, "starting nftables ruleset apply");

    let rt = RtClient::connect().context("failed to open rtnetlink socket")?;

    // Only resolve (and retry on) whichever values this particular ruleset reads - a node with no
    // IPv6 default route shouldn't fail to apply a ruleset that never mentions
    // `defaultroute_interface_ipv6`, and vice versa.
    let mut interfaces: HashMap<&str, String> = HashMap::new();
    if referenced.contains(DEFAULT_ROUTE_IPV4) {
        let iface = default_iface("IPv4", || interface_of(&rt, Family::Ipv4)).await?;
        interfaces.insert(DEFAULT_ROUTE_IPV4, iface);
    }
    if referenced.contains(DEFAULT_ROUTE_IPV6) {
        let iface = default_iface("IPv6", || interface_of(&rt, Family::Ipv6)).await?;
        interfaces.insert(DEFAULT_ROUTE_IPV6, iface);
    }

    // Before the lookup, so that no change between the two goes unseen.
    let changes = rt::link_route_and_address_changes()?;
    let uplinks = follow::lookup(&rt).await?;
    tracing::info!(?uplinks, "uplinks");
    let rendered = template::render(&template, &interfaces, &uplinks, &values)?;
    ruleset::apply(&rendered).await?;

    let in_force = Mutex::new(rendered);
    let follow = follow::follow(
        changes,
        uplinks,
        || follow::lookup(&rt),
        |uplinks| {
            tracing::info!(?uplinks, "uplinks changed");
            let rendered = template::render(&template, &interfaces, uplinks, &values);
            let in_force = &in_force;
            async move { ruleset::replace(in_force, rendered?).await }
        },
    );
    tokio::select! {
        result = follow => result,
        result = watchdog(&in_force) => result,
    }
}

/// The interface of `family`'s default route.
async fn interface_of(rt: &RtClient, family: Family) -> Result<Option<String>> {
    Ok(rt.uplink(family).await?.map(|(interface, _)| interface))
}

/// The interface of the `family` default route, which `lookup` finds.
async fn default_iface<Fut>(family: &str, lookup: impl Fn() -> Fut) -> Result<String>
where
    Fut: Future<Output = Result<Option<String>>>,
{
    common::retry::retry(
        &format!("the {family} default route lookup"),
        DEFAULT_ROUTE_TRIES,
        DEFAULT_ROUTE_RETRY_INTERVAL,
        || async {
            lookup()
                .await?
                .with_context(|| format!("no {family} default route"))
        },
    )
    .await
}

/// Watches for our own tables disappearing and reapplies the ruleset in force when they do - see
/// `ruleset.rs`'s own doc comment for *why* this exists (a real, confirmed-on-a-real-node boot
/// race with something else's first nftables/iptables-nft bootstrap, not a hypothetical). Runs
/// forever: `nft monitor` streams every nftables event on the node (table/chain/rule/set changes,
/// regardless of who made them - there's no way to subscribe to just "our tables" at the netlink
/// level), and each line is treated as nothing more than a wake-up signal to re-check our own
/// state via `ruleset::all_present` - not parsed for which specific table changed, since
/// `monitor`'s exact text format isn't a contract this binary should depend on (see that
/// function's doc comment).
///
/// `nft monitor` itself exiting (its own crash, or the node's nftables/netlink subsystem hiccuping)
/// is treated as a transient problem, not fatal: logged and respawned, not propagated as this
/// whole process's own exit - unlike `router`'s supervised `bird` child, there's no reason a
/// monitor hiccup should tear down and restart the *entire* container (an oneshot apply during
/// that restart is redundant work, not a reset of any state that needs it).
async fn watchdog(in_force: &Mutex<String>) -> Result<()> {
    loop {
        let mut monitor = match Command::new(ruleset::NFT_BIN)
            .arg("monitor")
            .stdout(Stdio::piped())
            .kill_on_drop(true)
            .spawn()
        {
            Ok(child) => child,
            Err(e) => {
                tracing::warn!(error = %e, "failed to spawn nft monitor, retrying in 5s");
                tokio::time::sleep(Duration::from_secs(5)).await;
                continue;
            }
        };
        let stdout = monitor.stdout.take().context("nft monitor has no stdout")?;
        let mut lines = BufReader::new(stdout).lines();

        loop {
            match lines.next_line().await {
                Ok(Some(_line)) => {
                    let rendered = in_force.lock().await;
                    match ruleset::all_present(&rendered).await {
                        Ok(true) => {}
                        Ok(false) => {
                            tracing::warn!(
                                "our nftables tables are missing (something else on this node \
                                 reset the ruleset) - reapplying"
                            );
                            if let Err(e) = ruleset::apply(&rendered).await {
                                tracing::warn!(error = %e, "reapply after table loss failed");
                            }
                        }
                        Err(e) => {
                            tracing::warn!(error = %e, "failed to check nftables table state")
                        }
                    }
                }
                Ok(None) => {
                    tracing::warn!("nft monitor exited, respawning");
                    break;
                }
                Err(e) => {
                    tracing::warn!(error = %e, "failed to read nft monitor output, respawning");
                    break;
                }
            }
        }
        let _ = monitor.wait().await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn the_default_route_interface_is_the_one_its_lookup_finds() {
        let found = default_iface("IPv4", || async { Ok(Some("eth9".to_owned())) }).await;
        assert_eq!(found.unwrap(), "eth9");
    }
}
