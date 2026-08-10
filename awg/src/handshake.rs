//! Handshake polling + kernel route management for "tracked" peers (config entries with an
//! explicit `allowed_ips` - see `config::PeerEntry`). Ported from slipmesh-operators'
//! `roadwarriors::handshake` (github.com/slipmesh/operators), generalized from one fixed shared
//! interface to any number of interfaces, and with two changes this daemon's restart-heavy
//! lifecycle needs that the original (a long-lived pod, rarely restarted) didn't:
//!
//! - Routes are tagged with `common::ROUTE_PROTOCOL` on add/delete, and the in-memory
//!   "what did I already install" tracking is *seeded from the kernel's own routes carrying that
//!   tag* at startup, not assumed empty - `handleRestart()` (see AGENTS.md) restarts this whole
//!   process on every config change, far more often than a k8s pod restarts, so a route installed
//!   by a previous run and left behind must still be recognized as ours.
//! - The very first reconciliation pass runs immediately, not after waiting for the first 1Hz
//!   tick - a route that went stale while the process was down (crashed, or between the old and
//!   new instance across a config-driven restart) needs cleaning up as soon as the daemon starts
//!   watching again, not up to a second later.
//!
//! No CRD status patch (the original's `RoadWarrior.status.connectedNode`/`lastHandshakeTime`) -
//! not available without Kubernetes, and not needed: the route's mere presence in the kernel is
//! itself the observable "this peer is currently connected" signal, visible via `talosctl get
//! routes` with no code here at all.

use anyhow::Result;
use common::ROUTE_PROTOCOL;
use common::netlink::awg::AwgClient;
use common::netlink::rt::RtClient;
use netlink_packet_amnezia_wireguard::{AmneziaWireguardAttribute, AmneziaWireguardPeerAttribute};
use std::collections::{HashMap, HashSet};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// One interface's worth of peers this daemon should be tracking handshakes/routes for - built
/// once at startup from the config plus the ifindex `interface::ensure_interface` already
/// resolved (see `main.rs`).
pub struct TrackedInterface {
    pub name: String,
    pub index: u32,
    pub stale_secs: u64,
    /// public_key (base64) -> allowed_ips (CIDR strings) - only peers with an explicit
    /// `allowed_ips` in the config belong here at all.
    pub peers: HashMap<String, Vec<String>>,
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before epoch")
        .as_secs()
}

/// public_key (base64) -> latest handshake, unix seconds (0 if the kernel never reported one).
///
/// `pub`, not just used internally by `reconcile_pass`: the `awg` binary's own `main.rs` (a
/// separate crate from this lib target - see `lib.rs`) also calls this once at startup, for every
/// peer on every interface (not just tracked ones), purely to log a diagnostic handshake summary -
/// full-tunnel peers get no route tracking, but their connection health is still worth a log line,
/// and this is the only place that already knows how to read it back.
pub async fn dump_handshakes(awg: &mut AwgClient, iface: &str) -> Result<HashMap<String, u64>> {
    use base64::Engine;

    let attrs = awg.get_device(iface).await?;
    let mut out = HashMap::new();
    for attr in attrs {
        let AmneziaWireguardAttribute::Peers(device_peers) = attr else {
            continue;
        };
        for peer in device_peers {
            let mut public_key = None;
            let mut latest_handshake = 0u64;
            for pattr in peer.0 {
                match pattr {
                    AmneziaWireguardPeerAttribute::PublicKey(k) => {
                        public_key = Some(base64::engine::general_purpose::STANDARD.encode(k));
                    }
                    AmneziaWireguardPeerAttribute::LastHandshake(ts) => {
                        latest_handshake = ts.seconds.max(0) as u64;
                    }
                    _ => {}
                }
            }
            if let Some(public_key) = public_key {
                out.insert(public_key, latest_handshake);
            }
        }
    }
    Ok(out)
}

async fn reconcile_pass(
    rt: &RtClient,
    awg: &mut AwgClient,
    tracked: &[TrackedInterface],
    installed: &mut HashMap<u32, HashSet<String>>,
) {
    let now = now_unix();
    for iface in tracked {
        let handshakes = match dump_handshakes(awg, &iface.name).await {
            Ok(h) => h,
            Err(e) => {
                tracing::warn!(iface = iface.name, error = %e, "failed to read handshake state");
                continue;
            }
        };

        let entry = installed.entry(iface.index).or_default();
        let mut still_fresh: HashSet<String> = HashSet::new();

        for (public_key, allowed_ips) in &iface.peers {
            let is_fresh = handshakes
                .get(public_key)
                .is_some_and(|ts| *ts > 0 && now.saturating_sub(*ts) < iface.stale_secs);
            if !is_fresh {
                continue;
            }
            for cidr in allowed_ips {
                if !entry.contains(cidr)
                    && let Err(e) = rt.route_add(iface.index, cidr, ROUTE_PROTOCOL).await
                {
                    tracing::warn!(iface = iface.name, cidr, error = %e, "failed to install route");
                    continue;
                }
                entry.insert(cidr.clone());
                still_fresh.insert(cidr.clone());
            }
        }

        let stale: Vec<String> = entry.difference(&still_fresh).cloned().collect();
        for cidr in stale {
            if let Err(e) = rt.route_del(iface.index, &cidr, ROUTE_PROTOCOL).await {
                tracing::warn!(iface = iface.name, cidr, error = %e, "failed to remove stale route");
                continue;
            }
            entry.remove(&cidr);
        }
    }
}

/// Runs forever, at 1Hz. The first pass runs as part of the loop's first iteration - `tokio::time
/// ::interval`'s first `tick()` completes immediately, not after a full period - so route state is
/// actualized right away, not up to a second after startup. Seeds `installed` from the kernel's own
/// `ROUTE_PROTOCOL`-tagged routes before that first pass, so a route left behind by a previous
/// instance of this process is recognized as ours from the very first reconciliation, not just
/// eventually.
pub async fn run(rt: RtClient, mut awg: AwgClient, tracked: Vec<TrackedInterface>) -> ! {
    let mut installed: HashMap<u32, HashSet<String>> = HashMap::new();
    for iface in &tracked {
        match rt.routes_by_protocol(iface.index, ROUTE_PROTOCOL).await {
            Ok(routes) => {
                installed.insert(iface.index, routes.into_iter().collect());
            }
            Err(e) => {
                tracing::warn!(iface = iface.name, error = %e, "failed to read existing routes at startup - starting with an empty set for this interface");
            }
        }
    }

    let mut tick = tokio::time::interval(Duration::from_secs(1));
    loop {
        tick.tick().await;
        reconcile_pass(&rt, &mut awg, &tracked, &mut installed).await;
    }
}
