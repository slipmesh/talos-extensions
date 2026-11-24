use awg::handshake::ReconcileSnapshot;
use awg::{gc, handshake, interface, metrics};
use common::daemon::{AwgDaemonConfig, MetricsConfig};
use sliplib_config::awg as config;

use anyhow::{Context, Result};
use common::netlink::awg::AwgClient;
use common::netlink::rt::RtClient;
use std::collections::HashSet;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::watch;

/// Fixed path, matching `extension-services/awg.yaml`'s `configFiles[].mountPath` - never an env
/// var or CLI flag: everything comes from the `ExtensionServiceConfig`, nothing else.
const CONFIG_PATH: &str = "/etc/talos-extensions/awg.yaml";

/// Inside the 10 s Talos waits after SIGTERM before it sends SIGKILL.
const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(5);

#[tokio::main]
async fn main() -> Result<()> {
    sliplib_runtime::init_tracing();
    tracing::info!("{} {}", env!("CARGO_BIN_NAME"), env!("CARGO_PKG_VERSION"));
    // Nothing to wind down: the interfaces, peers and routes stay as they are, so a restart does
    // not take the mesh down, and the next start picks its routes up again by protocol.
    sliplib_runtime::serve("awg", SHUTDOWN_TIMEOUT, async |shutdown| {
        tokio::select! {
            result = run() => result,
            () = shutdown.requested() => {
                tracing::info!("SIGTERM received, exiting with the mesh left up");
                Ok(())
            }
        }
    })
    .await
}

async fn run() -> Result<()> {
    let daemon =
        AwgDaemonConfig::read(Path::new(CONFIG_PATH)).context("failed to read the config file")?;
    daemon.validate().context("config validation failed")?;
    let cfg = Arc::new(daemon.mesh);

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
            tracing::error!(
                iface = iface.name,
                error = %format_args!("{e:#}"),
                "failed to converge interface"
            );
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
    let (verdict_tx, verdict_rx) = tokio::sync::watch::channel(ReconcileSnapshot::default());
    spawn_metrics(daemon.metrics.as_ref(), &cfg, verdict_rx);

    tracing::info!(
        tracked_interfaces = tracked.len(),
        "startup converged, entering handshake/route tracking loop"
    );
    handshake::run(rt, awg, tracked, verdict_tx).await;
}

/// Starts the metrics endpoint, if this node is configured for one. A task of its own with its own
/// lifecycle: it gets its own `AwgClient` inside `metrics::run` rather than sharing the routing
/// loop's, so a diagnostic side channel can never wedge or slow the loop it exists to observe.
///
/// A failure here is logged and dropped rather than returned. Reconciliation is the daemon's job
/// and must survive a listener that could not bind; the scrape failing is itself the signal, which
/// is the whole reason this serves rather than writing a file.
fn spawn_metrics(
    metrics: Option<&MetricsConfig>,
    cfg: &Arc<config::AwgConfig>,
    verdict: watch::Receiver<ReconcileSnapshot>,
) {
    let Some(metrics) = metrics else {
        tracing::info!("no metrics section in the config - not listening");
        return;
    };
    let listen = metrics.listen;
    let cfg = Arc::clone(cfg);
    tokio::spawn(async move {
        if let Err(e) = metrics::run(listen, cfg, verdict).await {
            tracing::error!(error = %e, "metrics endpoint stopped - routing continues");
        }
    });
}

/// One-time diagnostic dump of every peer's handshake state right after convergence - not just
/// tracked (explicit-`allowed_ips`) peers, since a full-tunnel peer's connection health is still
/// worth a log line even though it gets no route tracking. Best-effort: a failed dump on one
/// interface is logged and skipped, never fatal.
async fn log_handshake_summary(awg: &mut AwgClient, cfg: &config::AwgConfig) {
    for iface in &cfg.interfaces {
        match handshake::dump_peers(awg, &iface.name).await {
            Ok(peers) => {
                for peer in &iface.peers {
                    let last_handshake =
                        peers.get(&peer.public_key).map_or(0, |p| p.last_handshake);
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
        let index = rt
            .link_index(&iface.name)
            .await?
            .with_context(|| format!("interface {:?} missing after converging", iface.name))?;
        out.push(tracked(iface, index));
    }
    Ok(out)
}

fn tracked(iface: &config::InterfaceEntry, index: u32) -> handshake::TrackedInterface {
    let peers = iface
        .peers
        .iter()
        .filter_map(|peer| {
            let allowed_ips = peer.allowed_ips.as_ref()?;
            Some((
                peer.public_key.clone(),
                allowed_ips.iter().map(|prefix| prefix.0).collect(),
            ))
        })
        .collect();
    handshake::TrackedInterface {
        name: iface.name.clone(),
        index,
        peers,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sliplib_config::Obfuscation;
    use sliplib_config::awg::{InterfaceEntry, PeerEntry};
    use std::collections::HashMap;

    fn peer(public_key: &str, allowed_ips: Option<&[&str]>) -> PeerEntry {
        PeerEntry {
            public_key: public_key.to_owned(),
            name: None,
            endpoint: None,
            allowed_ips: allowed_ips.map(|cidrs| {
                cidrs
                    .iter()
                    .map(|c| sliplib_config::Prefix::try_from((*c).to_owned()).unwrap())
                    .collect()
            }),
            persistent_keepalive: None,
        }
    }

    #[test]
    fn an_interface_tracks_the_peers_with_allowed_ips() {
        let iface = InterfaceEntry {
            name: "rw-north".to_owned(),
            listen_port: 51820,
            addresses: vec![],
            private_key: "private".into(),
            obfuscation: Obfuscation::default(),
            mtu: None,
            peers: vec![
                peer("tracked", Some(&["203.0.113.2/32"])),
                peer("mesh", None),
            ],
        };
        assert_eq!(
            tracked(&iface, 7).peers,
            HashMap::from([(
                "tracked".to_owned(),
                vec!["203.0.113.2/32".parse().unwrap()]
            )])
        );
    }

    #[tokio::test]
    async fn the_metrics_endpoint_is_served_at_its_listen_address() {
        let free = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let listen = free.local_addr().unwrap();
        drop(free);
        let (_tx, rx) = watch::channel(ReconcileSnapshot::default());
        let cfg = Arc::new(config::AwgConfig { interfaces: vec![] });
        spawn_metrics(Some(&MetricsConfig { listen }), &cfg, rx);
        for _ in 0..200 {
            if tokio::net::TcpStream::connect(listen).await.is_ok() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!("nothing listens at {listen}");
    }
}
