//! Handshake polling + kernel route management for "tracked" peers (config entries with an
//! explicit `allowed_ips` - see `config::PeerEntry`). Ported from slipmesh-operators'
//! `roadwarriors::handshake`, generalized from one fixed shared
//! interface to any number of interfaces, and with two changes this daemon's restart-heavy
//! lifecycle needs that the original (a long-lived pod, rarely restarted) didn't:
//!
//! - Routes are tagged with `common::ROUTE_PROTOCOL` on add/delete, and the in-memory
//!   "what did I already install" tracking is *seeded from the kernel's own routes carrying that
//!   tag* at startup, not assumed empty - Talos's own `handleRestart()` restarts this whole
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

/// Everything one peer's `GetDevice` dump says that anything here reads: the handshake the route
/// tracking below decides on, and the byte counters `metrics` reports. Deliberately not
/// `Endpoint`: on a roadwarrior that is a client's current address, and nothing in this daemon
/// may put it anywhere it could be retained.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct PeerStats {
    /// Unix seconds, `0` when the kernel has never reported a handshake for this peer.
    pub last_handshake: u64,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
}

/// public_key (base64) -> that peer's stats.
///
/// Folds attributes into an existing entry rather than replacing it, because one peer can span
/// several messages of a single dump: the kernel resumes a peer whose `allowed_ips` didn't fit by
/// re-emitting its `PublicKey` and nothing else, so replacing on every frame would reset a real
/// handshake and real counters to zero for exactly the peers that carry the most state.
pub fn merge_peer_attrs(attrs: &[AmneziaWireguardAttribute]) -> HashMap<String, PeerStats> {
    use base64::Engine;

    let mut out: HashMap<String, PeerStats> = HashMap::new();
    for attr in attrs {
        let AmneziaWireguardAttribute::Peers(device_peers) = attr else {
            continue;
        };
        for peer in device_peers {
            let Some(public_key) = peer.0.iter().find_map(|pattr| match pattr {
                AmneziaWireguardPeerAttribute::PublicKey(k) => {
                    Some(base64::engine::general_purpose::STANDARD.encode(k))
                }
                _ => None,
            }) else {
                continue;
            };
            let stats = out.entry(public_key).or_default();
            for pattr in &peer.0 {
                match pattr {
                    AmneziaWireguardPeerAttribute::LastHandshake(ts) => {
                        stats.last_handshake = ts.seconds.max(0) as u64;
                    }
                    AmneziaWireguardPeerAttribute::RxBytes(v) => stats.rx_bytes = *v,
                    AmneziaWireguardPeerAttribute::TxBytes(v) => stats.tx_bytes = *v,
                    _ => {}
                }
            }
        }
    }
    out
}

/// The dump itself: one `GetDevice` round trip, parsed by `merge_peer_attrs`.
///
/// `pub`, not just used internally by `reconcile_pass`: the `awg` binary's own `main.rs` (a
/// separate crate from this lib target - see `lib.rs`) also calls this once at startup, for every
/// peer on every interface (not just tracked ones), purely to log a diagnostic handshake summary -
/// full-tunnel peers get no route tracking, but their connection health is still worth a log line
/// - and `metrics` calls it on every scrape over its own connection.
pub async fn dump_peers(awg: &mut AwgClient, iface: &str) -> Result<HashMap<String, PeerStats>> {
    Ok(merge_peer_attrs(&awg.get_device(iface).await?))
}

/// What the loop concluded on its last completed pass, for `metrics` to report rather than
/// re-derive. Carries `taken_unix` because a snapshot that stopped being refreshed - a loop wedged
/// in netlink - stays plausible forever otherwise, and serving a stale verdict as fact is the one
/// thing the metrics endpoint exists to avoid.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct ReconcileSnapshot {
    pub taken_unix: u64,
    /// (interface name, peer public key) for every tracked peer this daemon currently has routes
    /// installed for.
    pub connected: HashSet<(String, String)>,
}

/// A peer counts as connected only when *every* one of its `allowed_ips` is installed - not when
/// its handshake merely looks fresh. The two differ whenever `route_add` failed: that is logged
/// and skipped, the loop carries on, and a verdict derived from the handshake alone would claim a
/// route that isn't there.
fn snapshot_from(
    tracked: &[TrackedInterface],
    installed: &HashMap<u32, HashSet<String>>,
    now: u64,
) -> ReconcileSnapshot {
    let mut connected = HashSet::new();
    for iface in tracked {
        let entry = installed.get(&iface.index);
        for (public_key, allowed_ips) in &iface.peers {
            let all_installed = !allowed_ips.is_empty()
                && allowed_ips
                    .iter()
                    .all(|cidr| entry.is_some_and(|e| e.contains(cidr)));
            if all_installed {
                connected.insert((iface.name.clone(), public_key.clone()));
            }
        }
    }
    ReconcileSnapshot {
        taken_unix: now,
        connected,
    }
}

async fn reconcile_pass(
    rt: &RtClient,
    awg: &mut AwgClient,
    tracked: &[TrackedInterface],
    installed: &mut HashMap<u32, HashSet<String>>,
) {
    let now = now_unix();
    for iface in tracked {
        let peers = match dump_peers(awg, &iface.name).await {
            Ok(p) => p,
            Err(e) => {
                tracing::warn!(iface = iface.name, error = %e, "failed to read handshake state");
                continue;
            }
        };

        let entry = installed.entry(iface.index).or_default();
        let mut still_fresh: HashSet<String> = HashSet::new();

        for (public_key, allowed_ips) in &iface.peers {
            let is_fresh = peers.get(public_key).is_some_and(|p| {
                p.last_handshake > 0 && now.saturating_sub(p.last_handshake) < iface.stale_secs
            });
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
///
/// Publishes a `ReconcileSnapshot` after every pass for `metrics` to read. A `watch` send never
/// awaits and never blocks on a reader, so nothing a scrape does can hold up reconciliation; a
/// receiver that has gone away (the metrics task died, or was never started) makes `send` return
/// an error that is deliberately ignored - the loop's job does not depend on anyone listening.
pub async fn run(
    rt: RtClient,
    mut awg: AwgClient,
    tracked: Vec<TrackedInterface>,
    verdict: tokio::sync::watch::Sender<ReconcileSnapshot>,
) -> ! {
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
        let _ = verdict.send(snapshot_from(&tracked, &installed, now_unix()));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use netlink_packet_amnezia_wireguard::{AmneziaWireguardPeer, AmneziaWireguardTimeSpec};

    const KEY: [u8; 32] = [7u8; 32];

    fn key_b64() -> String {
        use base64::Engine;
        base64::engine::general_purpose::STANDARD.encode(KEY)
    }

    fn handshake_at(seconds: i64) -> AmneziaWireguardPeerAttribute {
        AmneziaWireguardPeerAttribute::LastHandshake(AmneziaWireguardTimeSpec {
            seconds,
            nano_seconds: 0,
        })
    }

    #[test]
    fn reads_handshake_and_byte_counters_for_one_peer() {
        let attrs = vec![AmneziaWireguardAttribute::Peers(vec![
            AmneziaWireguardPeer(vec![
                AmneziaWireguardPeerAttribute::PublicKey(KEY),
                handshake_at(1_700_000_000),
                AmneziaWireguardPeerAttribute::RxBytes(4096),
                AmneziaWireguardPeerAttribute::TxBytes(2048),
            ]),
        ])];
        assert_eq!(
            merge_peer_attrs(&attrs).get(&key_b64()),
            Some(&PeerStats {
                last_handshake: 1_700_000_000,
                rx_bytes: 4096,
                tx_bytes: 2048,
            })
        );
    }

    #[test]
    fn a_continuation_frame_does_not_reset_what_an_earlier_one_reported() {
        // The kernel splits a peer whose AllowedIPs don't fit one message, resuming it in the
        // next with just the public key again - the shape that used to zero a live peer's
        // handshake and counters.
        let attrs = vec![
            AmneziaWireguardAttribute::Peers(vec![AmneziaWireguardPeer(vec![
                AmneziaWireguardPeerAttribute::PublicKey(KEY),
                handshake_at(1_700_000_000),
                AmneziaWireguardPeerAttribute::RxBytes(4096),
                AmneziaWireguardPeerAttribute::TxBytes(2048),
            ])]),
            AmneziaWireguardAttribute::Peers(vec![AmneziaWireguardPeer(vec![
                AmneziaWireguardPeerAttribute::PublicKey(KEY),
            ])]),
        ];
        assert_eq!(
            merge_peer_attrs(&attrs).get(&key_b64()),
            Some(&PeerStats {
                last_handshake: 1_700_000_000,
                rx_bytes: 4096,
                tx_bytes: 2048,
            })
        );
    }

    #[test]
    fn a_negative_handshake_timestamp_reads_as_never() {
        let attrs = vec![AmneziaWireguardAttribute::Peers(vec![
            AmneziaWireguardPeer(vec![
                AmneziaWireguardPeerAttribute::PublicKey(KEY),
                handshake_at(-1),
            ]),
        ])];
        assert_eq!(merge_peer_attrs(&attrs)[&key_b64()].last_handshake, 0);
    }

    fn tracked(index: u32, peers: &[(&str, &[&str])]) -> TrackedInterface {
        TrackedInterface {
            name: format!("iface{index}"),
            index,
            stale_secs: 180,
            peers: peers
                .iter()
                .map(|(k, cidrs)| {
                    (
                        (*k).to_string(),
                        cidrs.iter().map(|c| (*c).to_string()).collect(),
                    )
                })
                .collect(),
        }
    }

    fn installed(index: u32, cidrs: &[&str]) -> HashMap<u32, HashSet<String>> {
        HashMap::from([(index, cidrs.iter().map(|c| (*c).to_string()).collect())])
    }

    #[test]
    fn a_peer_with_every_route_installed_is_connected() {
        let snap = snapshot_from(
            &[tracked(4, &[("peer-a", &["10.0.0.1/32", "10.0.0.2/32"])])],
            &installed(4, &["10.0.0.1/32", "10.0.0.2/32"]),
            1_700_000_000,
        );
        assert_eq!(snap.taken_unix, 1_700_000_000);
        assert!(
            snap.connected
                .contains(&("iface4".to_string(), "peer-a".to_string()))
        );
    }

    #[test]
    fn a_peer_missing_one_of_its_routes_is_not_connected() {
        // What a failed `route_add` looks like: the pass logged it and carried on, so the verdict
        // must not claim a route that isn't in the kernel.
        let snap = snapshot_from(
            &[tracked(4, &[("peer-a", &["10.0.0.1/32", "10.0.0.2/32"])])],
            &installed(4, &["10.0.0.1/32"]),
            1_700_000_000,
        );
        assert!(snap.connected.is_empty());
    }

    #[test]
    fn an_interface_with_no_installed_routes_at_all_yields_nothing() {
        let snap = snapshot_from(
            &[tracked(4, &[("peer-a", &["10.0.0.1/32"])])],
            &HashMap::new(),
            1_700_000_000,
        );
        assert!(snap.connected.is_empty());
    }

    #[test]
    fn a_peer_with_an_empty_allowed_ips_list_is_never_connected() {
        // `all()` over an empty list is vacuously true - a peer with nothing to install must not
        // read as connected on the strength of that.
        let snap = snapshot_from(
            &[tracked(4, &[("peer-a", &[])])],
            &installed(4, &["10.0.0.1/32"]),
            1_700_000_000,
        );
        assert!(snap.connected.is_empty());
    }

    #[test]
    fn a_peer_frame_without_a_public_key_is_skipped() {
        let attrs = vec![AmneziaWireguardAttribute::Peers(vec![
            AmneziaWireguardPeer(vec![AmneziaWireguardPeerAttribute::RxBytes(1)]),
        ])];
        assert!(merge_peer_attrs(&attrs).is_empty());
    }
}
