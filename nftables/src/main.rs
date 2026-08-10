mod config;
mod nftables;
mod template;

use anyhow::{Context, Result};
use common::netlink::rt::RtClient;
use config::NftablesConfig;
use std::collections::HashMap;
use std::future::Future;
use std::process::ExitCode;
use std::process::Stdio;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::Command;

/// Fixed path, matching `extension-services/nftables.yaml`'s `configFiles[].mountPath` - never an
/// env var or CLI flag (same invariant `awg`/`router`'s own `CONFIG_PATH` document).
const CONFIG_PATH: &str = "/etc/talos-extensions/nftables.yaml";

/// How many times to retry a default-route lookup before giving up, at startup only - a default
/// route can genuinely not exist yet for a few seconds after this container starts (network
/// bring-up on the node isn't synchronized with `depends: [{configuration: true}]`), but a route
/// that never appears within the budget is a real configuration problem worth failing loudly over
/// rather than silently looping on forever.
const DEFAULT_ROUTE_RETRIES: u32 = 10;
const DEFAULT_ROUTE_RETRY_INTERVAL: Duration = Duration::from_secs(2);

#[tokio::main]
async fn main() -> ExitCode {
    // No timestamp/ANSI: this only ever runs as a container's stdout, which Talos's own logging
    // (`logToConsole: true` -> dmesg, or the container runtime's own log capture) already
    // timestamps - matches `awg`/`router`'s own reasoning for the same choice.
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .without_time()
        .with_ansi(false)
        .init();

    match run().await {
        Ok(()) => {
            unreachable!("run() only returns via the watchdog loop exiting, which is always an Err")
        }
        Err(e) => {
            tracing::error!(error = %e, "nftables failed");
            ExitCode::FAILURE
        }
    }
}

async fn run() -> Result<()> {
    let raw = tokio::fs::read_to_string(CONFIG_PATH)
        .await
        .with_context(|| format!("failed to read config file {CONFIG_PATH}"))?;
    let cfg: NftablesConfig =
        serde_yaml::from_str(&raw).context("failed to parse config file as YAML")?;
    config::validate(&cfg).context("config validation failed")?;

    let referenced = template::referenced_placeholders(&cfg.ruleset);
    tracing::info!(placeholders = ?referenced, "starting nftables ruleset apply");

    let rt = RtClient::connect().context("failed to open rtnetlink socket")?;

    // Only resolve (and retry on) whichever placeholders this particular config actually
    // references - a node with no IPv6 default route shouldn't fail to apply a ruleset that never
    // mentions `defaultroute_interface_ipv6`, and vice versa.
    let mut values: HashMap<&str, String> = HashMap::new();
    if referenced.contains("defaultroute_interface_ipv4") {
        let iface = retry_default_iface("IPv4", || rt.default_iface_v4()).await?;
        values.insert("defaultroute_interface_ipv4", iface);
    }
    if referenced.contains("defaultroute_interface_ipv6") {
        let iface = retry_default_iface("IPv6", || rt.default_iface_v6()).await?;
        values.insert("defaultroute_interface_ipv6", iface);
    }

    let rendered = template::substitute(&cfg.ruleset, &values);
    nftables::apply(&rendered).await?;

    watchdog(rendered).await
}

/// Retries `lookup` up to `DEFAULT_ROUTE_RETRIES` times, `DEFAULT_ROUTE_RETRY_INTERVAL` apart - a
/// default route can genuinely not exist yet for a few seconds after this container starts
/// (network bring-up on the node isn't synchronized with `depends: [{configuration: true}]`), but
/// a route that never appears within the budget is a real configuration problem this can't paper
/// over silently.
async fn retry_default_iface<F, Fut>(label: &str, mut lookup: F) -> Result<String>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<Option<String>>>,
{
    for attempt in 1..=DEFAULT_ROUTE_RETRIES {
        match lookup().await? {
            Some(iface) => return Ok(iface),
            None if attempt < DEFAULT_ROUTE_RETRIES => {
                tracing::warn!(family = label, attempt, "no default route yet, retrying");
                tokio::time::sleep(DEFAULT_ROUTE_RETRY_INTERVAL).await;
            }
            None => anyhow::bail!(
                "no {label} default route found after {DEFAULT_ROUTE_RETRIES} attempts"
            ),
        }
    }
    unreachable!("loop above always returns on its final iteration")
}

/// Watches for our own tables disappearing and reapplies `rendered` when they do - see
/// `nftables.rs`'s own doc comment for *why* this exists (a real, confirmed-on-a-real-node boot
/// race with something else's first nftables/iptables-nft bootstrap, not a hypothetical). Runs
/// forever: `nft monitor` streams every nftables event on the node (table/chain/rule/set changes,
/// regardless of who made them - there's no way to subscribe to just "our tables" at the netlink
/// level), and each line is treated as nothing more than a wake-up signal to re-check our own
/// state via `nftables::all_present` - not parsed for which specific table changed, since
/// `monitor`'s exact text format isn't a contract this binary should depend on (see that
/// function's doc comment).
///
/// `nft monitor` itself exiting (its own crash, or the node's nftables/netlink subsystem hiccuping)
/// is treated as a transient problem, not fatal: logged and respawned, not propagated as this
/// whole process's own exit - unlike `router`'s supervised `bird` child, there's no reason a
/// monitor hiccup should tear down and restart the *entire* container (an oneshot apply during
/// that restart is redundant work, not a reset of any state that needs it).
async fn watchdog(rendered: String) -> Result<()> {
    loop {
        let mut monitor = match Command::new(nftables::NFT_BIN)
            .arg("monitor")
            .stdout(Stdio::piped())
            .spawn()
        {
            Ok(child) => child,
            Err(e) => {
                tracing::warn!(error = %e, "failed to spawn nft monitor, retrying in 5s");
                tokio::time::sleep(Duration::from_secs(5)).await;
                continue;
            }
        };
        let stdout = monitor
            .stdout
            .take()
            .expect("just configured with Stdio::piped()");
        let mut lines = BufReader::new(stdout).lines();

        loop {
            match lines.next_line().await {
                Ok(Some(_line)) => match nftables::all_present(&rendered).await {
                    Ok(true) => {}
                    Ok(false) => {
                        tracing::warn!(
                            "our nftables tables are missing (something else on this node reset \
                             the ruleset) - reapplying"
                        );
                        if let Err(e) = nftables::apply(&rendered).await {
                            tracing::warn!(error = %e, "reapply after table loss failed");
                        }
                    }
                    Err(e) => tracing::warn!(error = %e, "failed to check nftables table state"),
                },
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
