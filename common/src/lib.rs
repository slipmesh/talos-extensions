pub mod cidr;
pub mod keys;
/// Gated so that `taloscfg`, which only needs the config types, builds without the netlink stack -
/// it is Linux-only, and the generator has to build wherever it is run.
#[cfg(feature = "netlink")]
pub mod netlink;
pub mod obfuscation;

pub use obfuscation::Obfuscation;

/// Where a daemon serves its Prometheus endpoint. Shared rather than restated per daemon: the
/// address is the same kind of thing in each, and `taloscfg` derives every one of them the same
/// way from the node's own loopback.
#[derive(serde::Deserialize, serde::Serialize, Debug, PartialEq, Clone)]
pub struct MetricsConfig {
    /// `ip:port` - the node's own v4 mesh loopback, never `0.0.0.0`: that address exists only
    /// inside the overlay, so the endpoint is unreachable from outside without depending on a
    /// firewall rule being in place first. IPv4 because that is the address kubelet reports as
    /// `InternalIP`, which is how Prometheus discovers it.
    pub listen: String,
}

/// The `RouteProtocol` value every route this project's `awg` daemon installs is tagged with -
/// same mechanism BIRD/other routing daemons already use on this stack to mark their own routes
/// (`RouteProtocol::Bird`, `::Ospf`, `::Bgp`, ...). `200` sits outside every value the
/// `netlink-packet-route` enum currently names (highest named value in the 0.31 series is `Eigrp`
/// = 192) - picked from the "locally administered" range `iproute2` reserves (128-255) for
/// protocols with no kernel-assigned number.
///
/// This is what makes route bookkeeping across a process restart correct: on startup, only routes
/// carrying this exact protocol are treated as "ours" (`RtClient::routes_by_protocol`) - anything
/// else on the same interface (a routing daemon, a static route) is left alone, and a route this
/// daemon installed in a *previous* run (before the config change that triggered this restart)
/// is still recognizable as ours even though no in-memory state survived the restart.
#[cfg(feature = "netlink")]
pub const ROUTE_PROTOCOL: rtnetlink::packet_route::route::RouteProtocol =
    rtnetlink::packet_route::route::RouteProtocol::Other(200);
