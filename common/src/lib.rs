pub mod keys;
pub mod netlink;
pub mod obfuscation;

pub use obfuscation::Obfuscation;

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
pub const ROUTE_PROTOCOL: rtnetlink::packet_route::route::RouteProtocol =
    rtnetlink::packet_route::route::RouteProtocol::Other(200);
