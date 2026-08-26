use awg::{config, gc, handshake, interface};

use anyhow::{Context, Result};
use common::netlink::awg::AwgClient;
use common::netlink::rt::RtClient;
use std::collections::{HashMap, HashSet};

/// Fixed path, matching `extension-services/awg.yaml`'s `configFiles[].mountPath` - never an env
/// var or CLI flag: everything comes from the `ExtensionServiceConfig`, nothing else.
const CONFIG_PATH: &str = "/etc/talos-extensions/awg.yaml";

#[tokio::main]
async fn main() -> std::process::ExitCode {
    // No timestamp/ANSI: this only ever runs as a container's stdout, which Talos's own logging
    // (`logToConsole: true` -> dmesg, or the container runtime's own log capture) already
    // timestamps - matches slipmesh-operators' own reasoning for the same choice.
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .without_time()
        .with_ansi(false)
        .init();

    match run().await {
        Ok(()) => unreachable!("run() only returns via the infinite handshake loop or an Err"),
        Err(e) => {
            tracing::error!(error = %e, "awg failed to start");
            std::process::ExitCode::FAILURE
        }
    }
}

async fn run() -> Result<()> {
    let raw = std::fs::read_to_string(CONFIG_PATH)
        .with_context(|| format!("failed to read config file {CONFIG_PATH}"))?;
    let cfg: config::AwgConfig =
        serde_yaml::from_str(&raw).context("failed to parse config file as YAML")?;
    config::validate(&cfg).context("config validation failed")?;

    tracing::info!(interfaces = cfg.interfaces.len(), "starting awg");

    let rt = RtClient::connect().context("failed to open rtnetlink socket")?;
    let mut awg = AwgClient::connect().context("failed to open genetlink socket")?;

    // GC runs first, not last: a renamed/removed interface (e.g. a roadwarrior pool split into
    // two, reusing the old one's port) must be torn down before we try to create/update whatever
    // replaces it, or the replacement can lose a socket-bind race against the interface it's
    // superseding - see the port-collision crash-loop this fixed.
    let desired_names: HashSet<&str> = cfg.interfaces.iter().map(|i| i.name.as_str()).collect();
    gc::gc(&rt, &desired_names)
        .await
        .context("GC pass failed")?;

    let mut failed = Vec::new();
    for iface in &cfg.interfaces {
        if let Err(e) = interface::ensure_interface(&rt, &mut awg, iface).await {
            tracing::error!(iface = iface.name, error = %e, "failed to converge interface");
            failed.push(iface.name.clone());
        }
    }

    if !failed.is_empty() {
        anyhow::bail!(
            "failed to converge {} of {} interfaces: {}",
            failed.len(),
            cfg.interfaces.len(),
            failed.join(", ")
        );
    }

    log_handshake_summary(&mut awg, &cfg).await;

    let tracked = build_tracked_interfaces(&rt, &cfg).await?;
    tracing::info!(
        tracked_interfaces = tracked.len(),
        "startup converged, entering handshake/route tracking loop"
    );
    handshake::run(rt, awg, tracked).await;
}

/// One-time diagnostic dump of every peer's handshake state right after convergence - not just
/// tracked (explicit-`allowed_ips`) peers, since a full-tunnel peer's connection health is still
/// worth a log line even though it gets no route tracking. Best-effort: a failed dump on one
/// interface is logged and skipped, never fatal.
async fn log_handshake_summary(awg: &mut AwgClient, cfg: &config::AwgConfig) {
    for iface in &cfg.interfaces {
        match handshake::dump_handshakes(awg, &iface.name).await {
            Ok(handshakes) => {
                for peer in &iface.peers {
                    let last_handshake = handshakes.get(&peer.public_key).copied().unwrap_or(0);
                    tracing::info!(
                        iface = iface.name,
                        public_key = peer.public_key,
                        last_handshake_unix = last_handshake,
                        "peer handshake status at startup"
                    );
                }
            }
            Err(e) => {
                tracing::warn!(iface = iface.name, error = %e, "failed to read handshake summary");
            }
        }
    }
}

/// Builds the list of interfaces (and the subset of their peers) that need handshake polling and
/// kernel route management - only peers whose config entry had an explicit `allowed_ips`. Runs
/// after every interface has already converged, so `RtClient::link_index` is expected to succeed
/// for every interface named in the config.
///
/// Every interface from `cfg` is included here, even ones with an empty `peers` map (no peer
/// currently has an explicit `allowed_ips`) - `reconcile_pass`/`run` in `handshake.rs` treat "no
/// entries stayed fresh this pass" and "there were never any tracked peers" identically, removing
/// every previously-installed `ROUTE_PROTOCOL` route for the interface either way. Skipping an
/// empty-peers interface here used to drop it from `tracked` entirely, which meant a route
/// installed while it *did* have a tracked peer was never seen again by either the startup route
/// seeding or the reconcile loop - `gc.rs` only ever removes whole links, not individual routes -
/// leaking it in the kernel indefinitely across every future restart.
async fn build_tracked_interfaces(
    rt: &RtClient,
    cfg: &config::AwgConfig,
) -> Result<Vec<handshake::TrackedInterface>> {
    let mut out = Vec::new();
    for iface in &cfg.interfaces {
        let mut peers = HashMap::new();
        for peer in &iface.peers {
            if let Some(allowed_ips) = &peer.allowed_ips {
                peers.insert(peer.public_key.clone(), allowed_ips.clone());
            }
        }
        let index = rt
            .link_index(&iface.name)
            .await?
            .with_context(|| format!("interface {:?} missing after converging", iface.name))?;
        out.push(handshake::TrackedInterface {
            name: iface.name.clone(),
            index,
            stale_secs: iface
                .handshake_stale_secs
                .unwrap_or(config::DEFAULT_HANDSHAKE_STALE_SECS),
            peers,
        });
    }
    Ok(out)
}
