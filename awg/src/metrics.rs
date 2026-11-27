//! Prometheus endpoint: `GET /metrics` over the node's own mesh loopback address.
//!
//! Serving rather than writing a node-exporter textfile is deliberate. A file has no liveness - a
//! daemon that dies leaves its last write on disk and node-exporter keeps serving handshake
//! timestamps that look healthy forever. A failing scrape takes `up` to 0, which every alert and
//! dashboard already understands.
//!
//! Read on scrape, never on a timer: the netlink dump is cheap, the truth is whatever the kernel
//! says now, and a cache would only add a staleness window. Nothing is carried between scrapes -
//! a `Registry` is built fresh each time, so a peer removed from the config is simply never
//! registered again.

use crate::handshake::{PeerStats, ReconcileSnapshot, dump_peers, now_unix};
use anyhow::{Context, Result};
use common::netlink::awg::AwgClient;
use prometheus_client::encoding::EncodeLabelSet;
use prometheus_client::encoding::text::encode;
use prometheus_client::metrics::counter::Counter;
use prometheus_client::metrics::family::Family;
use prometheus_client::metrics::gauge::Gauge;
use prometheus_client::registry::Registry;
use sliplib_config::awg::AwgConfig;
use sliplib_runtime::metrics::{OPENMETRICS, Page, Rendering};
use std::collections::{BTreeMap, HashMap};
use std::net::SocketAddr;
use std::num::NonZeroUsize;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{Mutex, watch};
use tokio::time::timeout;

/// How stale the routing loop's snapshot may be before `peer_connected` stops being emitted. The
/// loop runs at 1 Hz, so this is a few missed passes - long enough not to flap, short enough that
/// a loop wedged in netlink stops being reported as fact.
const SNAPSHOT_MAX_AGE_SECS: u64 = 5;

/// A `GetDevice` dump is a local round trip that normally takes microseconds. This is not a
/// latency budget but a liveness one: netlink offers no cancellation, so a request that never
/// completes would otherwise hold the only client this task has for the life of the process.
const DUMP_TIMEOUT: Duration = Duration::from_secs(2);

/// Scrapes served at once; past it a client waits in the listen backlog.
const CONNECTIONS: NonZeroUsize = NonZeroUsize::new(4).unwrap();

/// One interface's dump, or `None` when reading it failed this scrape.
pub type Dumps = BTreeMap<String, Option<HashMap<String, PeerStats>>>;

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
struct PeerLabels {
    interface: String,
    /// `mesh` or `roadwarrior`, from the config's `allowed_ips` and nothing else - see `kind_of`.
    kind: String,
    /// The peer's base64 public key. Public keys are not secret; private keys never appear here or
    /// anywhere else in this output.
    peer: String,
    /// The config's own name for the peer, empty when it has none - what a dashboard shows
    /// instead of a base64 key. An empty value still occupies the label in the exposition; it
    /// simply reads as "no name", and Prometheus considers the resulting series identical to one
    /// carrying no `peer_name` at all.
    peer_name: String,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
struct InterfaceKindLabels {
    interface: String,
    kind: String,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
struct InterfaceLabels {
    interface: String,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
struct BuildLabels {
    component: String,
    version: String,
}

/// A peer with an explicit `allowed_ips` is a roadwarrior; anything else is a mesh peer. That is
/// the config's only discriminator, and it is exactly what makes a peer handshake-tracked, so
/// "tracked" and `kind="roadwarrior"` coincide by definition. Deliberately not `endpoint` (nothing
/// forbids a peer carrying both) and deliberately not the interface name (which would work today
/// and break the first time something is named differently).
fn kind_of(peer: &sliplib_config::awg::PeerEntry) -> &'static str {
    if peer.allowed_ips.is_some() {
        "roadwarrior"
    } else {
        "mesh"
    }
}

/// The whole exposition, from the config (labels), the dump (values) and the loop's own verdict.
/// Pure: everything that can be got wrong here is got wrong without a kernel in the room.
pub fn render(
    cfg: &AwgConfig,
    dumps: &Dumps,
    snapshot: &ReconcileSnapshot,
    now: u64,
) -> Result<String> {
    let mut registry = Registry::with_prefix("slipmesh");

    let build_info = Family::<BuildLabels, Gauge>::default();
    build_info
        .get_or_create(&BuildLabels {
            component: "awg".to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
        })
        .set(1);
    registry.register(
        "build_info",
        "Version of the running daemon, by component",
        build_info,
    );

    // A verdict is only worth reporting while the loop that produced it is still running. A
    // snapshot that stopped being refreshed stays plausible forever, and serving that as fact is
    // the failure mode this endpoint exists to avoid.
    let verdict_is_fresh =
        snapshot.taken_unix > 0 && now.saturating_sub(snapshot.taken_unix) <= SNAPSHOT_MAX_AGE_SECS;

    let awg = registry.sub_registry_with_prefix("awg");

    let last_handshake = Family::<PeerLabels, Gauge>::default();
    let rx_bytes = Family::<PeerLabels, Counter>::default();
    let tx_bytes = Family::<PeerLabels, Counter>::default();
    let connected = Family::<PeerLabels, Gauge>::default();
    let interface_peers = Family::<InterfaceKindLabels, Gauge>::default();
    let dump_ok = Family::<InterfaceLabels, Gauge>::default();

    for iface in &cfg.interfaces {
        let dump = dumps.get(&iface.name).and_then(Option::as_ref);
        dump_ok
            .get_or_create(&InterfaceLabels {
                interface: iface.name.clone(),
            })
            .set(i64::from(dump.is_some()));

        for peer in &iface.peers {
            let kind = kind_of(peer);
            let labels = PeerLabels {
                interface: iface.name.clone(),
                kind: kind.to_string(),
                peer: peer.public_key.clone(),
                peer_name: peer.name.clone().unwrap_or_default(),
            };
            interface_peers
                .get_or_create(&InterfaceKindLabels {
                    interface: iface.name.clone(),
                    kind: kind.to_string(),
                })
                .inc();

            // The verdict is the loop's, not a re-derivation from the handshake: it says a route
            // is installed, which a failed route replace makes false while the handshake still looks
            // fresh. Its absence for a mesh peer is meaningful - nothing tracks those - so no
            // series is emitted rather than a zero.
            if kind == "roadwarrior" && verdict_is_fresh {
                let is_connected = snapshot
                    .connected
                    .contains(&(iface.name.clone(), peer.public_key.clone()));
                connected
                    .get_or_create(&labels)
                    .set(i64::from(is_connected));
            }

            // Labels come from the config, values from the dump: a peer the kernel still has but
            // the config no longer names has no `kind` and no meaning here.
            let Some(stats) = dump.and_then(|d| d.get(&peer.public_key)) else {
                continue;
            };
            // No series at all for a peer that never handshook. Emitting `0` would make every
            // alerting rule special-case `time() - 0`, roughly 54 years of staleness.
            if stats.last_handshake > 0 {
                last_handshake
                    .get_or_create(&labels)
                    .set(stats.last_handshake as i64);
            }
            rx_bytes.get_or_create(&labels).inc_by(stats.rx_bytes);
            tx_bytes.get_or_create(&labels).inc_by(stats.tx_bytes);
        }
    }

    awg.register(
        "peer_last_handshake_seconds",
        "Unix time of a peer's last completed handshake",
        last_handshake,
    );
    awg.register("peer_rx_bytes", "Bytes received from a peer", rx_bytes);
    awg.register("peer_tx_bytes", "Bytes sent to a peer", tx_bytes);
    awg.register(
        "peer_connected",
        "Whether this daemon currently has routes installed for a tracked peer",
        connected,
    );
    awg.register(
        "interface_peers",
        "Peers this interface is configured with",
        interface_peers,
    );
    awg.register(
        "interface_dump_ok",
        "Whether this scrape could read the interface from the kernel",
        dump_ok,
    );

    if snapshot.taken_unix > 0 {
        let reconcile = <Gauge>::default();
        reconcile.set(snapshot.taken_unix as i64);
        awg.register(
            "reconcile_last_success_seconds",
            "Unix time of the routing loop's last completed pass",
            reconcile,
        );
    }

    let mut out = String::new();
    encode(&mut out, &registry).context("encoding the metrics")?;
    Ok(out)
}

/// Dumps every configured interface for one scrape.
///
/// Holds the task's own `AwgClient` - `get_device` takes `&mut self`, so scrapes serialize on it,
/// which is deliberate: one diagnostic connection, never the routing loop's. A dump that times out
/// drops the client so the next scrape reconnects, rather than inheriting a session that may never
/// answer again. A failure on one interface is recorded as that interface's own, never as a failed
/// scrape: a 500 would make the whole node look dead because one link could not be read.
async fn collect(client: &Mutex<Option<AwgClient>>, cfg: &AwgConfig) -> Dumps {
    let mut guard = client.lock().await;
    let mut dumps = Dumps::new();

    // One connect attempt per scrape, not per interface: if opening the socket fails it will fail
    // the same way for every interface behind it, and retrying down the list would only multiply
    // the log line and the latency by however many interfaces the node has.
    if guard.is_none() {
        match AwgClient::connect() {
            Ok(client) => *guard = Some(client),
            Err(e) => {
                tracing::warn!(error = %e, "metrics: failed to open its own genetlink socket");
                return cfg
                    .interfaces
                    .iter()
                    .map(|iface| (iface.name.clone(), None))
                    .collect();
            }
        }
    }

    for iface in &cfg.interfaces {
        let Some(awg) = guard.as_mut() else {
            // An earlier interface timed out and dropped the client. Reconnecting mid-scrape would
            // only risk waiting out the same timeout again, so the rest of this scrape reports
            // itself unread and the next one starts with a fresh socket.
            dumps.insert(iface.name.clone(), None);
            continue;
        };

        let dump = match timeout(DUMP_TIMEOUT, dump_peers(awg, &iface.name)).await {
            Ok(Ok(peers)) => Some(peers),
            Ok(Err(e)) => {
                tracing::warn!(iface = iface.name, error = %e, "metrics: dump failed");
                None
            }
            Err(_) => {
                tracing::warn!(
                    iface = iface.name,
                    "metrics: dump timed out, reconnecting for the next scrape"
                );
                *guard = None;
                None
            }
        };
        dumps.insert(iface.name.clone(), dump);
    }
    dumps
}

/// Serves `GET /metrics` until the process ends.
///
/// Errors from here never reach the routing loop's error handling, and the loop keeps reconciling
/// if this task dies outright - the scrape failing is then the signal, which is the whole point of
/// serving rather than writing a file.
///
/// The mesh loopback belongs to `ext-router`, which Talos may start after this one: the listener
/// binds before the address exists and answers once it appears, Prometheus reading `up=0` until
/// then.
pub async fn run(
    listen: SocketAddr,
    cfg: Arc<AwgConfig>,
    verdict: watch::Receiver<ReconcileSnapshot>,
) -> Result<()> {
    let listener = sliplib_runtime::metrics::bind(listen)
        .with_context(|| format!("failed to bind the metrics socket to {listen}"))?;
    tracing::info!(%listen, "metrics endpoint listening");
    // Connected lazily, in `collect`: at startup this would race `ext-router` for nothing, and a
    // client that has to be rebuilt after a timeout needs the same path anyway.
    let client: Arc<Mutex<Option<AwgClient>>> = Arc::new(Mutex::new(None));
    sliplib_runtime::metrics::serve(listener, CONNECTIONS, move |path| {
        if path != "/metrics" {
            return None;
        }
        let (cfg, client, verdict) = (Arc::clone(&cfg), Arc::clone(&client), verdict.clone());
        let page: Rendering<anyhow::Error> = Box::pin(async move {
            let dumps = collect(&client, &cfg).await;
            let snapshot = verdict.borrow().clone();
            let body = render(&cfg, &dumps, &snapshot, now_unix())?;
            Ok(Page {
                content_type: OPENMETRICS,
                body,
            })
        });
        Some(page)
    })
    .await;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use sliplib_config::Obfuscation;
    use sliplib_config::awg::{InterfaceEntry, PeerEntry};

    // Public keys are opaque identifiers to everything in this module - nothing here decodes them,
    // they only join a config entry to its dump entry - so the fixtures say what they are instead
    // of imitating base64.
    const MESH_PEER: &str = "peer-mesh";
    const RW_PEER: &str = "peer-roadwarrior";
    const PRIVATE_KEY: &str = "private-key-must-never-be-emitted";
    const NOW: u64 = 1_700_000_000;

    fn peer(public_key: &str, name: Option<&str>, allowed_ips: Option<&[&str]>) -> PeerEntry {
        PeerEntry {
            public_key: public_key.to_string(),
            name: name.map(str::to_string),
            endpoint: Some("192.0.2.7:51820".to_string()),
            allowed_ips: allowed_ips.map(|cidrs| {
                cidrs
                    .iter()
                    .map(|c| sliplib_config::Prefix::try_from((*c).to_owned()).unwrap())
                    .collect()
            }),
            persistent_keepalive: None,
        }
    }

    fn iface(name: &str, peers: Vec<PeerEntry>) -> InterfaceEntry {
        InterfaceEntry {
            name: name.to_string(),
            listen_port: 51820,
            addresses: vec![],
            private_key: PRIVATE_KEY.into(),
            obfuscation: Obfuscation::default(),
            mtu: None,
            peers,
        }
    }

    /// One mesh interface (a single full-tunnel peer) and one roadwarrior pool - the shape every
    /// node in the fleet actually has.
    fn config() -> AwgConfig {
        AwgConfig {
            interfaces: vec![
                iface("mesh-node-a", vec![peer(MESH_PEER, Some("node-a"), None)]),
                iface(
                    "rw-north",
                    vec![peer(RW_PEER, Some("client-one"), Some(&["203.0.113.5/32"]))],
                ),
            ],
        }
    }

    fn stats(last_handshake: u64, rx_bytes: u64, tx_bytes: u64) -> PeerStats {
        PeerStats {
            last_handshake,
            rx_bytes,
            tx_bytes,
        }
    }

    fn dumps(mesh: Option<PeerStats>, rw: Option<PeerStats>) -> Dumps {
        Dumps::from([
            (
                "mesh-node-a".to_string(),
                Some(HashMap::from_iter(mesh.map(|s| (MESH_PEER.to_string(), s)))),
            ),
            (
                "rw-north".to_string(),
                Some(HashMap::from_iter(rw.map(|s| (RW_PEER.to_string(), s)))),
            ),
        ])
    }

    fn snapshot(pairs: &[(&str, &str)], taken_unix: u64) -> ReconcileSnapshot {
        ReconcileSnapshot {
            taken_unix,
            connected: pairs
                .iter()
                .map(|(i, p)| ((*i).to_string(), (*p).to_string()))
                .collect(),
        }
    }

    fn series(out: &str, name: &str) -> Vec<String> {
        out.lines()
            .filter(|l| l.starts_with(name))
            .map(str::to_string)
            .collect()
    }

    #[test]
    fn a_peer_is_labelled_with_its_kind_from_its_allowed_ips_and_its_name() {
        let out = render(
            &config(),
            &dumps(Some(stats(NOW - 10, 1, 2)), Some(stats(NOW - 10, 3, 4))),
            &snapshot(&[("rw-north", RW_PEER)], NOW),
            NOW,
        )
        .unwrap();
        let handshakes = series(&out, "slipmesh_awg_peer_last_handshake_seconds{");
        for (interface, kind) in [("mesh-node-a", "mesh"), ("rw-north", "roadwarrior")] {
            assert!(
                handshakes
                    .iter()
                    .any(|l| l.contains(&format!("interface=\"{interface}\""))
                        && l.contains(&format!("kind=\"{kind}\""))),
                "{out}"
            );
        }
        // A base64 public key is unreadable on a dashboard; the name is what a human picks a
        // series by. It never decides anything - the key stays the identity.
        assert!(out.contains("peer_name=\"node-a\""), "{out}");
        assert!(out.contains("peer_name=\"client-one\""), "{out}");
        assert!(out.contains("peer=\"peer-roadwarrior\""), "{out}");
    }

    #[test]
    fn a_roadwarrior_alone_has_a_verdict_and_none_from_a_stale_snapshot() {
        // A loop wedged in netlink leaves a snapshot that stays plausible forever; serving it is
        // the exact failure the textfile collector was rejected for.
        for (mesh, connected_to, taken, verdict) in [
            (
                Some(stats(NOW - 10, 1, 2)),
                &[("rw-north", RW_PEER)][..],
                NOW,
                Some(" 1"),
            ),
            (None, &[][..], NOW, Some(" 0")),
            (None, &[("rw-north", RW_PEER)][..], NOW - 600, None),
        ] {
            let out = render(
                &config(),
                &dumps(mesh, Some(stats(NOW - 10, 3, 4))),
                &snapshot(connected_to, taken),
                NOW,
            )
            .unwrap();
            let connected = series(&out, "slipmesh_awg_peer_connected{");
            assert_eq!(connected.len(), usize::from(verdict.is_some()), "{out}");
            if let Some(value) = verdict {
                assert!(connected[0].ends_with(value), "{out}");
                assert!(!connected[0].contains("mesh-node-a"), "{out}");
            }
        }
    }

    #[test]
    fn a_peer_that_never_handshaked_emits_no_handshake_series() {
        let out = render(
            &config(),
            &dumps(Some(stats(0, 0, 0)), Some(stats(NOW - 10, 3, 4))),
            &snapshot(&[], NOW),
            NOW,
        )
        .unwrap();
        assert!(
            !series(&out, "slipmesh_awg_peer_last_handshake_seconds{")
                .iter()
                .any(|l| l.contains("mesh-node-a")),
            "{out}"
        );
    }

    #[test]
    fn a_failed_dump_marks_that_interface_and_leaves_the_others_alone() {
        let mut d = dumps(Some(stats(NOW - 10, 1, 2)), Some(stats(NOW - 10, 3, 4)));
        d.insert("mesh-node-a".to_string(), None);
        let out = render(&config(), &d, &snapshot(&[], NOW), NOW).unwrap();
        let ok = series(&out, "slipmesh_awg_interface_dump_ok{");
        assert!(
            ok.iter()
                .any(|l| l.contains("mesh-node-a") && l.ends_with(" 0")),
            "{out}"
        );
        assert!(
            ok.iter()
                .any(|l| l.contains("rw-north") && l.ends_with(" 1")),
            "{out}"
        );
        assert!(
            series(&out, "slipmesh_awg_peer_rx_bytes_total{")
                .iter()
                .any(|l| l.contains("rw-north")),
            "{out}"
        );
    }

    #[test]
    fn interface_peers_counts_what_the_config_declares_by_kind() {
        let out = render(&config(), &dumps(None, None), &snapshot(&[], NOW), NOW).unwrap();
        let counts = series(&out, "slipmesh_awg_interface_peers{");
        assert!(
            counts.iter().any(|l| l.contains("mesh-node-a")
                && l.contains("kind=\"mesh\"")
                && l.ends_with(" 1")),
            "{out}"
        );
        assert!(
            counts.iter().any(|l| l.contains("rw-north")
                && l.contains("kind=\"roadwarrior\"")
                && l.ends_with(" 1")),
            "{out}"
        );
    }

    #[test]
    fn byte_counters_come_through_as_counters() {
        let out = render(
            &config(),
            &dumps(Some(stats(NOW - 10, 4096, 2048)), None),
            &snapshot(&[], NOW),
            NOW,
        )
        .unwrap();
        assert!(
            out.contains("# TYPE slipmesh_awg_peer_rx_bytes counter"),
            "{out}"
        );
        assert!(
            series(&out, "slipmesh_awg_peer_rx_bytes_total{")
                .iter()
                .any(|l| l.ends_with(" 4096")),
            "{out}"
        );
        assert!(
            series(&out, "slipmesh_awg_peer_tx_bytes_total{")
                .iter()
                .any(|l| l.ends_with(" 2048")),
            "{out}"
        );
    }

    #[test]
    fn build_info_is_reported_and_freshness_once_a_pass_completed() {
        for (snapshot, fresh) in [
            (snapshot(&[], NOW), true),
            (ReconcileSnapshot::default(), false),
        ] {
            let out = render(&config(), &dumps(None, None), &snapshot, NOW).unwrap();
            assert!(out.contains("component=\"awg\""), "{out}");
            let freshness = series(&out, "slipmesh_awg_reconcile_last_success_seconds ");
            assert_eq!(
                freshness.iter().any(|l| l.ends_with(&format!(" {NOW}"))),
                fresh,
                "{out}"
            );
            assert!(fresh || freshness.is_empty(), "{out}");
        }
    }
}
