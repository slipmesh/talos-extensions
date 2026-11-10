/// Gated so that `router`'s template code, which the generator builds on, needs no netlink stack:
/// it is Linux-only, and the generator has to build wherever it is run.
#[cfg(feature = "netlink")]
pub mod netlink;
pub mod template;

/// The protocol number every route this project's `awg` daemon installs is tagged with -
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
/// is still recognizable as ours even though no in-memory state survived the restart. It is also
/// how `router`'s BIRD picks them up: by `krt_source`, the same number read back.
pub const ROUTE_PROTOCOL_ID: u8 = 200;

#[cfg(feature = "netlink")]
pub const ROUTE_PROTOCOL: rtnetlink::packet_route::route::RouteProtocol =
    rtnetlink::packet_route::route::RouteProtocol::Other(ROUTE_PROTOCOL_ID);
