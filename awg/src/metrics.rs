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

use crate::config::AwgConfig;
use crate::handshake::{PeerStats, ReconcileSnapshot, dump_peers};
use anyhow::{Context, Result};
use bytes::Bytes;
use common::netlink::awg::AwgClient;
use http_body_util::Full;
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use prometheus_client::encoding::EncodeLabelSet;
use prometheus_client::encoding::text::encode;
use prometheus_client::metrics::counter::Counter;
use prometheus_client::metrics::family::Family;
use prometheus_client::metrics::gauge::Gauge;
use prometheus_client::registry::Registry;
use socket2::{Domain, Protocol, Socket, Type};
use std::collections::{BTreeMap, HashMap};
use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::net::TcpListener;
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

/// Ceiling on a single connection, so a client that opens a socket and then says nothing cannot
/// hold a scrape slot indefinitely.
const CONNECTION_TIMEOUT: Duration = Duration::from_secs(30);

/// What `prometheus-client`'s text encoder actually emits. Prometheus chooses its parser from this
/// header, so it must say OpenMetrics rather than the older text format.
const CONTENT_TYPE: &str = "application/openmetrics-text; version=1.0.0; charset=utf-8";

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
fn kind_of(peer: &crate::config::PeerEntry) -> &'static str {
    if peer.allowed_ips.is_some() {
        "roadwarrior"
    } else {
        "mesh"
    }
}

/// The whole exposition, from the config (labels), the dump (values) and the loop's own verdict.
/// Pure: everything that can be got wrong here is got wrong without a kernel in the room.
pub fn render(cfg: &AwgConfig, dumps: &Dumps, snapshot: &ReconcileSnapshot, now: u64) -> String {
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
            // is installed, which a failed `route_add` makes false while the handshake still looks
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
    // The encoder only fails if the sink does, and a String sink cannot.
    encode(&mut out, &registry).expect("writing exposition into a String cannot fail");
    out
}

/// Binds the listening socket, tolerating an address that does not exist yet.
///
/// The mesh loopback belongs to a *different* extension - `ext-router` creates `router-lo` and puts
/// `node.loopback_addresses` on it - and Talos does not order extension startup, so this often
/// reaches `bind()` first and would get `EADDRNOTAVAIL`. `IP_FREEBIND` permits binding an address
/// that is not present, and the listener starts answering once it appears; until then Prometheus
/// reports `up=0` for the node, which is the correct reading rather than a fault to paper over.
/// It requires no capability, and has no tokio API, which is why the socket is built through
/// socket2 first.
fn bind(listen: SocketAddr) -> Result<TcpListener> {
    let socket = Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP))
        .context("failed to create the metrics socket")?;
    socket
        .set_freebind_v4(true)
        .context("failed to set IP_FREEBIND on the metrics socket")?;
    socket
        .set_reuse_address(true)
        .context("failed to set SO_REUSEADDR on the metrics socket")?;
    socket.set_nonblocking(true)?;
    socket
        .bind(&listen.into())
        .with_context(|| format!("failed to bind the metrics socket to {listen}"))?;
    socket.listen(128).context("failed to listen")?;
    TcpListener::from_std(socket.into()).context("failed to hand the metrics socket to tokio")
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before epoch")
        .as_secs()
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

fn respond(status: StatusCode, content_type: &str, body: &str) -> Response<Full<Bytes>> {
    Response::builder()
        .status(status)
        .header(hyper::header::CONTENT_TYPE, content_type)
        .body(Full::new(Bytes::from(body.to_string())))
        .expect("a response built from constants cannot be invalid")
}

/// Serves `GET /metrics` until the process ends.
///
/// Errors from here never reach the routing loop's error handling, and the loop keeps reconciling
/// if this task dies outright - the scrape failing is then the signal, which is the whole point of
/// serving rather than writing a file.
pub async fn run(
    listen: SocketAddr,
    cfg: Arc<AwgConfig>,
    verdict: watch::Receiver<ReconcileSnapshot>,
) -> Result<()> {
    let listener = bind(listen)?;
    tracing::info!(%listen, "metrics endpoint listening");
    serve(listener, cfg, verdict).await
}

/// The accept loop, split from `run` so it can be driven over an already-bound listener - which is
/// what keeps the HTTP surface testable with no kernel in the room.
async fn serve(
    listener: TcpListener,
    cfg: Arc<AwgConfig>,
    verdict: watch::Receiver<ReconcileSnapshot>,
) -> Result<()> {
    // Connected lazily, in `collect`: at startup this would race `ext-router` for nothing, and a
    // client that has to be rebuilt after a timeout needs the same path anyway.
    let client: Arc<Mutex<Option<AwgClient>>> = Arc::new(Mutex::new(None));

    loop {
        let (stream, _peer) = match listener.accept().await {
            Ok(accepted) => accepted,
            Err(e) => {
                // A single failed accept says nothing about the next one; tearing the listener
                // down here would take `up` to 0 for a node whose routing is perfectly healthy.
                tracing::warn!(error = %e, "metrics: accept failed");
                continue;
            }
        };

        let cfg = Arc::clone(&cfg);
        let client = Arc::clone(&client);
        let verdict = verdict.clone();
        tokio::spawn(async move {
            let service = service_fn(move |req: Request<Incoming>| {
                let cfg = Arc::clone(&cfg);
                let client = Arc::clone(&client);
                let verdict = verdict.clone();
                async move {
                    if req.method() != Method::GET || req.uri().path() != "/metrics" {
                        // Answered without touching the kernel: nothing else here is a route, and
                        // a wrong path must not cost a netlink round trip.
                        return Ok::<_, Infallible>(respond(
                            StatusCode::NOT_FOUND,
                            "text/plain; charset=utf-8",
                            "not found\n",
                        ));
                    }
                    let dumps = collect(&client, &cfg).await;
                    let body = render(&cfg, &dumps, &verdict.borrow().clone(), now_unix());
                    Ok(respond(StatusCode::OK, CONTENT_TYPE, &body))
                }
            });

            let served = timeout(
                CONNECTION_TIMEOUT,
                http1::Builder::new().serve_connection(TokioIo::new(stream), service),
            )
            .await;
            match served {
                Ok(Err(e)) => tracing::debug!(error = %e, "metrics: connection ended in error"),
                Err(_) => tracing::debug!("metrics: connection timed out"),
                Ok(Ok(())) => {}
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{InterfaceEntry, MetricsConfig, PeerEntry};
    use common::Obfuscation;

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
            endpoint: Some("203.0.113.7:51820".to_string()),
            allowed_ips: allowed_ips.map(|cidrs| cidrs.iter().map(|c| (*c).to_string()).collect()),
            advanced_security: false,
        }
    }

    fn iface(name: &str, peers: Vec<PeerEntry>) -> InterfaceEntry {
        InterfaceEntry {
            name: name.to_string(),
            listen_port: 51820,
            addresses: vec![],
            private_key: PRIVATE_KEY.to_string(),
            obfuscation: Obfuscation::default(),
            handshake_stale_secs: None,
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
                    "rw-eu",
                    vec![peer(RW_PEER, Some("client-one"), Some(&["10.99.0.5/32"]))],
                ),
            ],
            metrics: Some(MetricsConfig {
                listen: "10.62.0.1:9586".to_string(),
            }),
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
                "rw-eu".to_string(),
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
    fn kind_comes_from_allowed_ips_alone() {
        let out = render(
            &config(),
            &dumps(Some(stats(NOW - 10, 1, 2)), Some(stats(NOW - 10, 3, 4))),
            &snapshot(&[("rw-eu", RW_PEER)], NOW),
            NOW,
        );
        let handshakes = series(&out, "slipmesh_awg_peer_last_handshake_seconds{");
        assert!(
            handshakes
                .iter()
                .any(|l| l.contains("interface=\"mesh-node-a\"") && l.contains("kind=\"mesh\"")),
            "{out}"
        );
        assert!(
            handshakes
                .iter()
                .any(|l| l.contains("interface=\"rw-eu\"") && l.contains("kind=\"roadwarrior\"")),
            "{out}"
        );
    }

    #[test]
    fn a_peer_name_is_carried_through_as_its_own_label() {
        // A base64 public key is unreadable on a dashboard; the name is what a human picks a
        // series by. It never decides anything - the key stays the identity.
        let out = render(
            &config(),
            &dumps(Some(stats(NOW - 10, 1, 2)), Some(stats(NOW - 10, 3, 4))),
            &snapshot(&[("rw-eu", RW_PEER)], NOW),
            NOW,
        );
        assert!(out.contains("peer_name=\"node-a\""), "{out}");
        assert!(out.contains("peer_name=\"client-one\""), "{out}");
        assert!(out.contains("peer=\"peer-roadwarrior\""), "{out}");
    }

    #[test]
    fn an_unnamed_peer_still_gets_every_series() {
        let cfg = AwgConfig {
            interfaces: vec![iface(
                "rw-eu",
                vec![peer(RW_PEER, None, Some(&["10.9.0.1/32"]))],
            )],
            metrics: None,
        };
        let out = render(
            &cfg,
            &Dumps::from([(
                "rw-eu".to_string(),
                Some(HashMap::from([(RW_PEER.to_string(), stats(NOW - 5, 1, 1))])),
            )]),
            &snapshot(&[], NOW),
            NOW,
        );
        // Still labelled, with an empty value - the series is identical to one with no
        // `peer_name` at all as far as Prometheus is concerned.
        assert!(out.contains("peer_name=\"\""), "{out}");
        assert!(
            !series(&out, "slipmesh_awg_peer_last_handshake_seconds{").is_empty(),
            "{out}"
        );
    }

    #[test]
    fn a_peer_carrying_both_an_endpoint_and_allowed_ips_is_still_a_roadwarrior() {
        // Every fixture peer has an endpoint, so the roadwarrior carries both - the rule is
        // `allowed_ips` alone, and nothing else may sway it.
        let out = render(
            &config(),
            &dumps(None, Some(stats(NOW - 10, 0, 0))),
            &snapshot(&[], NOW),
            NOW,
        );
        assert!(
            series(&out, "slipmesh_awg_peer_connected{")
                .iter()
                .all(|l| l.contains("kind=\"roadwarrior\"")),
            "{out}"
        );
    }

    #[test]
    fn peer_connected_is_emitted_for_roadwarriors_only() {
        let out = render(
            &config(),
            &dumps(Some(stats(NOW - 10, 1, 2)), Some(stats(NOW - 10, 3, 4))),
            &snapshot(&[("rw-eu", RW_PEER)], NOW),
            NOW,
        );
        let connected = series(&out, "slipmesh_awg_peer_connected{");
        assert_eq!(connected.len(), 1, "{out}");
        assert!(connected[0].ends_with(" 1"), "{out}");
        assert!(!connected[0].contains("mesh-node-a"), "{out}");
    }

    #[test]
    fn a_roadwarrior_without_its_routes_reads_as_disconnected_not_missing() {
        let out = render(
            &config(),
            &dumps(None, Some(stats(NOW - 10, 3, 4))),
            &snapshot(&[], NOW),
            NOW,
        );
        let connected = series(&out, "slipmesh_awg_peer_connected{");
        assert_eq!(connected.len(), 1, "{out}");
        assert!(connected[0].ends_with(" 0"), "{out}");
    }

    #[test]
    fn a_stale_snapshot_emits_no_verdict_at_all() {
        // A loop wedged in netlink leaves a snapshot that stays plausible forever; serving it is
        // the exact failure the textfile collector was rejected for.
        let out = render(
            &config(),
            &dumps(None, Some(stats(NOW - 10, 3, 4))),
            &snapshot(&[("rw-eu", RW_PEER)], NOW - 600),
            NOW,
        );
        assert!(
            series(&out, "slipmesh_awg_peer_connected{").is_empty(),
            "{out}"
        );
    }

    #[test]
    fn a_peer_that_never_handshaked_emits_no_handshake_series() {
        let out = render(
            &config(),
            &dumps(Some(stats(0, 0, 0)), Some(stats(NOW - 10, 3, 4))),
            &snapshot(&[], NOW),
            NOW,
        );
        assert!(
            !series(&out, "slipmesh_awg_peer_last_handshake_seconds{")
                .iter()
                .any(|l| l.contains("mesh-node-a")),
            "{out}"
        );
    }

    #[test]
    fn a_peer_in_the_kernel_but_not_in_the_config_is_not_emitted() {
        let mut d = dumps(Some(stats(NOW - 10, 1, 2)), Some(stats(NOW - 10, 3, 4)));
        d.get_mut("rw-eu")
            .unwrap()
            .as_mut()
            .unwrap()
            .insert("peer-not-in-the-config".to_string(), stats(NOW, 9, 9));
        let out = render(&config(), &d, &snapshot(&[], NOW), NOW);
        assert!(!out.contains("peer-not-in-the-config"), "{out}");
    }

    #[test]
    fn a_failed_dump_marks_that_interface_and_leaves_the_others_alone() {
        let mut d = dumps(Some(stats(NOW - 10, 1, 2)), Some(stats(NOW - 10, 3, 4)));
        d.insert("mesh-node-a".to_string(), None);
        let out = render(&config(), &d, &snapshot(&[], NOW), NOW);
        let ok = series(&out, "slipmesh_awg_interface_dump_ok{");
        assert!(
            ok.iter()
                .any(|l| l.contains("mesh-node-a") && l.ends_with(" 0")),
            "{out}"
        );
        assert!(
            ok.iter().any(|l| l.contains("rw-eu") && l.ends_with(" 1")),
            "{out}"
        );
        assert!(
            series(&out, "slipmesh_awg_peer_rx_bytes_total{")
                .iter()
                .any(|l| l.contains("rw-eu")),
            "{out}"
        );
    }

    #[test]
    fn interface_peers_counts_what_the_config_declares_by_kind() {
        let out = render(&config(), &dumps(None, None), &snapshot(&[], NOW), NOW);
        let counts = series(&out, "slipmesh_awg_interface_peers{");
        assert!(
            counts.iter().any(|l| l.contains("mesh-node-a")
                && l.contains("kind=\"mesh\"")
                && l.ends_with(" 1")),
            "{out}"
        );
        assert!(
            counts.iter().any(|l| l.contains("rw-eu")
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
        );
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
    fn build_info_and_reconcile_freshness_are_reported() {
        let out = render(&config(), &dumps(None, None), &snapshot(&[], NOW), NOW);
        assert!(out.contains("component=\"awg\""), "{out}");
        assert!(
            series(&out, "slipmesh_awg_reconcile_last_success_seconds ")
                .iter()
                .any(|l| l.ends_with(&format!(" {NOW}"))),
            "{out}"
        );
    }

    #[test]
    fn a_loop_that_has_never_completed_a_pass_reports_no_freshness() {
        let out = render(
            &config(),
            &dumps(None, None),
            &ReconcileSnapshot::default(),
            NOW,
        );
        assert!(
            series(&out, "slipmesh_awg_reconcile_last_success_seconds ").is_empty(),
            "{out}"
        );
    }

    /// One real request over a real socket, so the HTTP surface is exercised rather than assumed.
    /// A config with no interfaces never reaches netlink - `collect` iterates nothing - which is
    /// what makes this runnable anywhere.
    async fn request(path: &str) -> String {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let cfg = Arc::new(AwgConfig {
            interfaces: vec![],
            metrics: None,
        });
        let (_tx, rx) = watch::channel(ReconcileSnapshot::default());
        tokio::spawn(serve(listener, cfg, rx));

        let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        stream
            .write_all(
                format!("GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
                    .as_bytes(),
            )
            .await
            .unwrap();
        let mut response = String::new();
        stream.read_to_string(&mut response).await.unwrap();
        response
    }

    #[tokio::test]
    async fn a_scrape_is_answered_as_openmetrics() {
        let response = request("/metrics").await;
        assert!(response.starts_with("HTTP/1.1 200 OK"), "{response}");
        assert!(
            response.contains("content-type: application/openmetrics-text; version=1.0.0"),
            "{response}"
        );
        assert!(response.contains("slipmesh_build_info"), "{response}");
        assert!(response.trim_end().ends_with("# EOF"), "{response}");
    }

    #[tokio::test]
    async fn anything_that_is_not_the_metrics_path_is_a_404() {
        let response = request("/").await;
        assert!(response.starts_with("HTTP/1.1 404 Not Found"), "{response}");
        assert!(!response.contains("slipmesh_"), "{response}");
    }

    #[tokio::test]
    async fn binds_an_address_that_does_not_exist_on_any_interface() {
        // The whole reason the socket is built through socket2: ext-router has not created
        // router-lo yet, so this address is on no interface, and a plain bind would get
        // EADDRNOTAVAIL. Port 0 keeps the test from colliding with anything real.
        let listen: SocketAddr = "10.62.255.254:0".parse().unwrap();
        let listener = bind(listen).expect("IP_FREEBIND should permit binding an absent address");
        assert_eq!(listener.local_addr().unwrap().ip(), listen.ip());
    }

    #[test]
    fn no_private_key_and_no_endpoint_ever_reach_the_output() {
        let out = render(
            &config(),
            &dumps(Some(stats(NOW - 10, 1, 2)), Some(stats(NOW - 10, 3, 4))),
            &snapshot(&[("rw-eu", RW_PEER)], NOW),
            NOW,
        );
        assert!(!out.contains(PRIVATE_KEY), "{out}");
        assert!(!out.contains("203.0.113.7"), "{out}");
    }
}
