//! Renders `bird.conf` from a template given to the daemon at runtime, and the context that
//! template reads. Pure, with no netlink or BIRD process behind it, so that `taloscfg` renders a
//! node's template the same way the node will and refuses one that does not render.

use anyhow::Result;
use common::template::Template;
use serde::Serialize;
use std::net::{Ipv4Addr, Ipv6Addr};

/// Dedicated dummy interface carrying this node's router identity /32 and IPv6 loopback /128 -
/// kept separate from the real `lo` and from `ext-awg`-managed interfaces so nothing but this
/// daemon ever touches it.
pub const ROUTER_LOOPBACK_IFACE: &str = "router-lo";

/// This node's own OSPF/BGP-standard IPv4 loopback plus its IPv6 loopback (the OSPFv3/RFC 8950
/// underlay's session-source address) - grouped into one param rather than two loose ones purely
/// to keep `render`/`reconcile` under this workspace's `too-many-arguments-threshold`, not because
/// the two are used together for any other reason. Both come straight from
/// `config::NodeIdentity::loopback_addresses` - unlike the k8s original, there's no
/// network+node_id derivation step; whoever authors `router.yaml` gives each node its own
/// loopbacks directly, the same "config-authoring concern" `awg`'s README documents for private
/// keys.
pub struct RouterIdentity {
    pub loopback: Ipv4Addr,
    pub ipv6_loopback: Ipv6Addr,
}

/// One iBGP peer, straight from `config::BgpPeerEntry` - `name` is free-form (unlike the k8s
/// original's `short_id`, which was hex-only by construction from a `node_id`), so it goes through
/// `sanitize_protocol_id` before becoming part of a BIRD protocol name.
pub struct BgpPeer {
    pub name: String,
    pub address: Ipv6Addr,
}

/// A BIRD quoted string ends at the first `"` - an embedded quote breaks out into the surrounding
/// block and lets whatever follows be parsed as real config. `ospf_interfaces` name/glob entries
/// come from `router.yaml`, so they go through this before being quoted.
fn sanitize_quoted(raw: &str) -> String {
    raw.chars()
        .filter(|&c| c != '"' && c != '\n' && c != '\r')
        .collect()
}

/// A BIRD `#` comment runs to the end of the line - an embedded newline breaks out of the comment
/// into real config. `BypassRoute`/`AnnounceRoute` labels are config-supplied, so strip line
/// breaks before writing one into a comment.
fn sanitize_comment(raw: &str) -> String {
    raw.chars()
        .map(|c| if c == '\n' || c == '\r' { ' ' } else { c })
        .collect()
}

/// A BIRD protocol identifier (`ibgp6_<id>`) must be alphanumeric-plus-underscore and not start
/// with a digit - `config::BgpPeerEntry::name` is a free-form config string, unlike the k8s
/// original's `short_id` (hex digits only by construction from a `node_id`), so it needs
/// sanitizing here instead of being usable verbatim. Conservative by construction (only the
/// characters BIRD's identifier grammar is known to accept survive unchanged) rather than an
/// exhaustive validator - **verify against the pinned BIRD version's actual grammar before relying
/// on an edge case not covered by this workspace's own tests**, same "verify before writing it
/// down" rule this codebase applies to every other assumption about BIRD's syntax/output.
fn sanitize_protocol_id(raw: &str) -> String {
    let mut out: String = raw
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect();
    let starts_with_digit = out.chars().next().is_none_or(|c| c.is_ascii_digit());
    if starts_with_digit {
        out.insert(0, '_');
    }
    out
}

#[derive(Clone)]
pub struct BypassRoute {
    pub net: String,
    pub label: String,
}

/// A network to redistribute into the iBGP mesh as a static blackhole route - same shape as
/// `BypassRoute`, but for statically-declared infrastructure ranges (`router.yaml`'s `announce`)
/// rather than VPN egress-bypass exits. Collapsed into one shared `ANNOUNCE` protocol - a plain
/// alias since the two have never needed to diverge in shape.
pub type AnnounceRoute = BypassRoute;

/// A `net`/sanitized-`label` pair - the view-model shape `bird.conf` actually iterates over for
/// both `BYPASS` and `ANNOUNCE` blocks. Sanitization happens here, building the template's input,
/// rather than in the template itself - `bird.conf` stays pure formatting, with zero
/// string-safety logic for a template author to get wrong.
#[derive(Serialize)]
struct SanitizedRoute {
    net: String,
    label: String,
}

impl SanitizedRoute {
    fn from_routes(routes: &[BypassRoute]) -> Vec<Self> {
        routes
            .iter()
            .map(|r| Self {
                net: r.net.clone(),
                label: sanitize_comment(&r.label),
            })
            .collect()
    }
}

/// Renders one interface-matching entry (`ospf_interfaces` or `direct_interfaces`) as BIRD would
/// need it written in an `interface` clause: a bare (unquoted) CIDR literal if it parses as one -
/// BIRD's interface-pattern grammar takes a prefix as its own token type, not a quoted string - or
/// a quoted, sanitized name/glob pattern otherwise. Shared by both config fields - same grammar,
/// same `protocol { interface ...; }` clause shape either way. **This split needs verifying against
/// the pinned BIRD version's real grammar before relying on it** (see `config.rs`'s
/// `ospf_interfaces` doc comment) - if CIDR-by-address matching turns out not to work the way this
/// assumes, falling back to name/glob-only entries doesn't change anything else in this module.
fn render_iface_pattern(entry: &str) -> String {
    if common::cidr::parse_cidr(entry).is_ok() {
        entry.to_string()
    } else {
        format!("\"{}\"", sanitize_quoted(entry))
    }
}

/// The desired-state inputs that vary independently of `identity`/`as_number` - one struct
/// rather than five loose slice params, to stay under the workspace's `too-many-arguments`
/// clippy threshold.
pub struct RenderInputs<'a> {
    /// OSPFv3 runs over the mesh links plus the loopback stub, and never re-exports
    /// kernel or BGP routes back into the IGP (`export none`).
    pub ospf_interfaces: &'a [String],
    /// iBGP full mesh over the loopbacks (`multihop` + RFC 8950). It carries this node's own
    /// IPv4 loopback (`source = RTS_DEVICE`), its BYPASS/ANNOUNCE statics (`RTS_STATIC`) and any
    /// kernel route inside a `learn` range (`RTS_INHERIT`) - but never OSPF-learned routes, which
    /// would put the two protocols in a preference fight over the same prefix.
    ///
    /// BGP is the only possible carrier for the IPv4 loopbacks: OSPFv3 is IPv6-only by design.
    /// The IPv4 kernel protocol's export filter therefore sets `krt_prefsrc` to this node's own
    /// loopback on every exported route - mesh links carry no IPv4 address, so a BGP-learned
    /// route's next-hop interface offers Linux no source address to pick, and without the hint a
    /// reply leaves with whatever address route selection chose and is dropped by the peer as a
    /// bogon.
    pub bgp_peers: &'a [BgpPeer],
    /// Exported to iBGP peers only, never installed in this node's own kernel table: unlike the
    /// service subnet, `bypass.include` resolves to real Internet prefixes that this node also
    /// reaches on its own behalf (image pulls, DNS). Installing the blackhole/relay routes
    /// locally would hijack that traffic too.
    pub bypass: &'a [BypassRoute],
    /// Matched by protocol name in the kernel export filter rather than by `source = RTS_STATIC`,
    /// which would catch `bypass` as well. A local route matters here: with no encapsulation on
    /// the mesh, a host-network process connecting to a ClusterIP picks its source address at
    /// connect time, in a route lookup against the pre-DNAT destination - earlier than
    /// kube-proxy's rewrite. Without a local route covering the service subnet that lookup falls
    /// through to the default route and the connection leaves with the node's public address.
    /// Installing it locally is safe precisely because the service subnet is never a real
    /// Internet destination.
    pub announce: &'a [AnnounceRoute],
    /// IPv4 CIDR *ranges*. Each is rendered with a trailing `+` (`net ~ [ 10.99.0.0/24+ ]`) -
    /// the network and everything more specific inside it, not an exact-match list of
    /// individual `/32`s. An empty list turns kernel learning off entirely.
    ///
    /// Rendered as `learn all`, not a bare `learn`: a bare `learn` is `KRT_LEARN_ALIEN` and picks
    /// up only routes installed by other daemons, while `learn all` is `KRT_LEARN_ALL` and also
    /// takes `KRT_SRC_KERNEL` - what the kernel stamps on a connected route derived from an
    /// interface address (`sysdep/unix/krt.h`'s `KRT_LEARN_*`, the `case KRT_SRC_KERNEL` guard in
    /// `krt.c`, and `krt.Y`'s `kern_learn` grammar, in BIRD 2.19.2 and unchanged in 3.3.2).
    /// A node's own
    /// podCIDR route is exactly that under every CNI, so a bare `learn` silently learns nothing
    /// and the node stops announcing its pods. `all` widens the *source* of learnable routes, not
    /// the scope: the import filter still rejects everything outside these prefixes.
    pub learn: &'a [String],
    /// Extra interfaces (exact name, glob, or CIDR - same grammar as `ospf_interfaces`) to treat
    /// as `protocol direct` sources, each exported over iBGP by the existing `RTS_DEVICE` clause
    /// (the same one that already carries `router-lo`'s own loopback) - no separate wiring needed
    /// per entry. Not specific to any one purpose: a pod-network bridge (`cni0`, written by a
    /// separate component - see `slipmesh/cni-config`) is the motivating case, but this field
    /// doesn't know or care what the interface is for.
    pub direct_interfaces: &'a [String],
    /// Requests BFD sessions on every OSPF link, with the intervals the mesh chose. A WireGuard
    /// interface stays up whether or not packets still cross it, so without BFD a dead path is
    /// only noticed when OSPF's dead timer expires; the cost is constant control traffic through
    /// every tunnel, which is why this is a `mesh.yaml` switch rather than always on.
    pub bfd: Option<&'a crate::config::BfdSettings>,
}

/// Where the template reaches the daemon - a `configFiles` entry of its `ExtensionServiceConfig`,
/// next to `router.yaml`.
pub const TEMPLATE_PATH: &str = "/etc/talos-extensions/router.conf.j2";

/// The template a mesh starts from: `taloscfg` writes it into `slipmesh.yaml` when that file has
/// none, and from then on the copy there is the one in force.
pub const REFERENCE_TEMPLATE: &str = include_str!("../templates/router.conf.j2");

/// Every variable `render` supplies - the fields of `BirdConfigContext`.
pub const VARIABLES: &[&str] = &[
    "loopback",
    "ipv6_loopback",
    "as_number",
    "router_loopback_iface",
    "ospf_interfaces",
    "bgp_peers",
    "bypass",
    "announce",
    "learn",
    "direct_interfaces",
    "bfd",
];

/// Compiles a `bird.conf` template, refusing one that reads anything outside `VARIABLES`.
pub fn compile(source: impl Into<String>) -> Result<Template> {
    Template::new(source, VARIABLES)
}

pub fn render(
    template: &Template,
    identity: RouterIdentity,
    as_number: u32,
    inputs: &RenderInputs,
) -> Result<String> {
    template.render(BirdConfigContext::new(identity, as_number, inputs))
}

#[derive(Serialize)]
struct RenderedBgpPeer {
    protocol_id: String,
    address: Ipv6Addr,
}

#[derive(Serialize)]
struct RenderedDirectIface {
    protocol_id: String,
    pattern: String,
}

/// One `ospf_interfaces` entry, rendered, plus whether BFD is asked for on it.
#[derive(Serialize)]
struct RenderedOspfIface {
    pattern: String,
    bfd: bool,
}

/// What a template sees. Every value that came from config is already sanitized here, so the
/// template is formatting alone and has no string safety of its own to get wrong.
#[derive(Serialize)]
struct BirdConfigContext {
    loopback: Ipv4Addr,
    ipv6_loopback: Ipv6Addr,
    as_number: u32,
    router_loopback_iface: &'static str,
    ospf_interfaces: Vec<RenderedOspfIface>,
    bgp_peers: Vec<RenderedBgpPeer>,
    bypass: Vec<SanitizedRoute>,
    announce: Vec<SanitizedRoute>,
    learn: Vec<String>,
    direct_interfaces: Vec<RenderedDirectIface>,
    bfd: Option<crate::config::BfdSettings>,
}

impl BirdConfigContext {
    fn new(identity: RouterIdentity, as_number: u32, inputs: &RenderInputs) -> Self {
        let rendered_peers: Vec<RenderedBgpPeer> = inputs
            .bgp_peers
            .iter()
            .map(|p| RenderedBgpPeer {
                protocol_id: sanitize_protocol_id(&p.name),
                address: p.address,
            })
            .collect();
        let learn_patterns: Vec<String> =
            inputs.learn.iter().map(|cidr| format!("{cidr}+")).collect();
        let direct_interfaces: Vec<RenderedDirectIface> = inputs
            .direct_interfaces
            .iter()
            .map(|s| RenderedDirectIface {
                protocol_id: sanitize_protocol_id(s),
                pattern: render_iface_pattern(s),
            })
            .collect();

        Self {
            loopback: identity.loopback,
            ipv6_loopback: identity.ipv6_loopback,
            as_number,
            router_loopback_iface: ROUTER_LOOPBACK_IFACE,
            ospf_interfaces: inputs
                .ospf_interfaces
                .iter()
                .map(|s| RenderedOspfIface {
                    // The loopback is in this list too, and OSPF runs on it - but there is no
                    // neighbour on a dummy interface, so a BFD session there could only ever sit
                    // down. Asking for one would put a permanently-dead entry in `show bfd sessions`
                    // and teach whoever reads it to ignore that column.
                    bfd: inputs.bfd.is_some() && s != ROUTER_LOOPBACK_IFACE,
                    pattern: render_iface_pattern(s),
                })
                .collect(),
            bgp_peers: rendered_peers,
            bypass: SanitizedRoute::from_routes(inputs.bypass),
            announce: SanitizedRoute::from_routes(inputs.announce),
            learn: learn_patterns,
            bfd: inputs.bfd.cloned(),
            direct_interfaces,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn render(identity: RouterIdentity, as_number: u32, inputs: &RenderInputs) -> Result<String> {
        super::render(&compile(REFERENCE_TEMPLATE)?, identity, as_number, inputs)
    }

    /// `VARIABLES` is what a template is checked against, the context is what it gets - a field
    /// added to one and not the other would refuse a template that renders, or pass one that
    /// does not.
    #[test]
    fn variables_are_the_fields_of_the_context() {
        let bfd = crate::config::BfdSettings::default();
        let mut inputs = RenderInputs {
            ospf_interfaces: &[],
            bgp_peers: &[],
            bypass: &[],
            announce: &[],
            learn: &[],
            direct_interfaces: &[],
            bfd: None,
        };
        inputs.bfd = Some(&bfd);
        let context =
            serde_json::to_value(BirdConfigContext::new(identity(), 64512, &inputs)).unwrap();
        let mut fields: Vec<&str> = context
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        let mut variables = VARIABLES.to_vec();
        fields.sort();
        variables.sort();
        assert_eq!(fields, variables);
    }

    fn identity() -> RouterIdentity {
        RouterIdentity {
            loopback: "10.62.0.1".parse().unwrap(),
            ipv6_loopback: "fd00::1".parse().unwrap(),
        }
    }

    /// Positional test helper mirroring `render`/`reconcile`'s pre-`RenderInputs` shape, so each
    /// test case only names the slices it actually varies.
    fn inputs<'a>(
        ospf_interfaces: &'a [String],
        bgp_peers: &'a [BgpPeer],
        bypass: &'a [BypassRoute],
        announce: &'a [AnnounceRoute],
        learn: &'a [String],
    ) -> RenderInputs<'a> {
        inputs_with_direct(ospf_interfaces, bgp_peers, bypass, announce, learn, &[])
    }

    #[allow(clippy::too_many_arguments)]
    fn inputs_with_direct<'a>(
        ospf_interfaces: &'a [String],
        bgp_peers: &'a [BgpPeer],
        bypass: &'a [BypassRoute],
        announce: &'a [AnnounceRoute],
        learn: &'a [String],
        direct_interfaces: &'a [String],
    ) -> RenderInputs<'a> {
        RenderInputs {
            ospf_interfaces,
            bgp_peers,
            bypass,
            announce,
            learn,
            direct_interfaces,
            bfd: None,
        }
    }

    /// BFD is what makes a dead mesh link detectable in seconds rather than at OSPF's 40s dead
    /// timer: the tunnels are WireGuard, so the interface never goes down and there is no
    /// link-state event to react to - only a timer. Both halves are asserted together because
    /// either alone is inert: a `protocol bfd` nothing requests sessions from, or `bfd on` with
    /// no protocol to serve it. Both states of the switch are asserted because leaving it on
    /// unconditionally would put control traffic through every tunnel of every mesh.
    #[test]
    fn bfd_is_configured_and_requested_only_when_the_mesh_asks_for_it() {
        // The loopback is in `ospf_interfaces` on every real node, and a CIDR entry renders
        // unquoted - both shapes have to come out right in the BFD block as well as the OSPF one.
        let ifaces = vec![
            "mesh-*".to_string(),
            "10.99.0.0/24".to_string(),
            "router-lo".to_string(),
        ];
        let settings = crate::config::BfdSettings {
            min_rx_ms: 500,
            ..Default::default()
        };
        let mut with = inputs(&ifaces, &[], &[], &[], &[]);
        with.bfd = Some(&settings);
        let on = render(identity(), 64512, &with).unwrap();

        assert!(on.contains("protocol bfd"));
        // The chosen interval reaches the file, rather than a constant baked into the template.
        assert!(on.contains("min rx interval 500 ms"));
        assert!(on.contains("min tx interval 300 ms"));
        assert!(on.contains("multiplier 5;"));
        assert!(on.contains("interface \"mesh-*\" { type ptp; bfd on; };"));
        assert!(on.contains("interface 10.99.0.0/24 { type ptp; bfd on; };"));
        assert!(on.contains("interface \"router-lo\" { stub yes; };"));
        // No neighbour on a dummy interface, so no session to ask for.
        assert!(on.contains("interface \"router-lo\" { type ptp; };"));
        let bfd_block = on.split("protocol bfd {").nth(1).unwrap();
        let bfd_block = bfd_block
            .split(
                "
}",
            )
            .next()
            .unwrap();
        assert!(bfd_block.contains("interface \"mesh-*\""));
        assert!(bfd_block.contains("interface 10.99.0.0/24"));
        assert!(!bfd_block.contains("router-lo"));

        let off = render(identity(), 64512, &inputs(&ifaces, &[], &[], &[], &[])).unwrap();
        assert!(!off.contains("bfd"));
    }

    #[test]
    fn render_kernel_export_filter_installs_announce_locally_but_not_bypass() {
        let bypass = vec![BypassRoute {
            net: "203.0.113.0/24".to_string(),
            label: "some vendor".to_string(),
        }];
        let announce = vec![AnnounceRoute {
            net: "10.60.0.0/16".to_string(),
            label: "k8s-services".to_string(),
        }];
        let out = render(
            identity(),
            64512,
            &inputs(&[], &[], &bypass, &announce, &[]),
        )
        .unwrap();
        let kernel_block = out
            .split("protocol kernel {")
            .nth(1)
            .expect("an ipv4 protocol kernel block must be present")
            .split("ipv6 {")
            .next()
            .unwrap();
        // ANNOUNCE is named explicitly, gets krt_prefsrc, gets installed locally.
        let announce_clause = kernel_block
            .split("if proto = \"ANNOUNCE\" then {")
            .nth(1)
            .expect("kernel export filter must single out proto = \"ANNOUNCE\"")
            .split('}')
            .next()
            .unwrap();
        assert!(announce_clause.contains("krt_prefsrc = 10.62.0.1;"));
        assert!(announce_clause.contains("accept;"));
        // Nothing in the kernel export filter references BYPASS or the generic RTS_STATIC that
        // would also catch it - only ANNOUNCE gets singled out by name.
        assert!(!kernel_block.contains("BYPASS"));
        assert!(!kernel_block.contains("RTS_STATIC"));
    }

    /// Every branch of the template taken at once, and none - pinned byte for byte, so that a
    /// change of template engine is shown to change nothing in what BIRD reads.
    fn golden_cases() -> [(&'static str, String); 2] {
        let ospf = [
            "mesh-*".to_string(),
            "10.99.0.0/24".to_string(),
            "router-lo".to_string(),
        ];
        let peers = [
            BgpPeer {
                name: "node-b".to_string(),
                address: "fd00::2".parse().unwrap(),
            },
            BgpPeer {
                name: "3rd".to_string(),
                address: "fd00::3".parse().unwrap(),
            },
        ];
        let bypass = [BypassRoute {
            net: "203.0.113.0/24".to_string(),
            label: "AS64500
example"
                .to_string(),
        }];
        let announce = [AnnounceRoute {
            net: "10.60.0.0/16".to_string(),
            label: "k8s-services".to_string(),
        }];
        let learn = ["10.61.0.0/16".to_string(), "10.99.0.5/32".to_string()];
        let direct = ["cni0".to_string(), "198.51.100.0/24".to_string()];
        let bfd = crate::config::BfdSettings::default();
        let mut full = inputs_with_direct(&ospf, &peers, &bypass, &announce, &learn, &direct);
        full.bfd = Some(&bfd);
        [
            ("full", render(identity(), 64512, &full).unwrap()),
            (
                "minimal",
                render(identity(), 64512, &inputs(&[], &[], &[], &[], &[])).unwrap(),
            ),
        ]
    }

    #[test]
    fn renders_the_golden_files() {
        for (name, out) in golden_cases() {
            let path = format!("{}/testdata/{name}.bird.conf", env!("CARGO_MANIFEST_DIR"));
            let golden = std::fs::read_to_string(&path).unwrap();
            assert_eq!(out, golden, "{name} differs from {path}");
        }
    }

    #[test]
    fn render_includes_ospf_interfaces_as_names_and_cidrs() {
        let ifaces = ["mesh-*".to_string(), "10.99.0.0/24".to_string()];
        let out = render(identity(), 64512, &inputs(&ifaces, &[], &[], &[], &[])).unwrap();
        assert!(out.contains("interface \"mesh-*\" { type ptp;"));
        assert!(out.contains("interface 10.99.0.0/24 { type ptp;"));
        assert!(out.contains("interface \"router-lo\" { stub yes; };"));
    }

    #[test]
    fn render_direct_interfaces_is_empty_by_default() {
        let out = render(identity(), 64512, &inputs(&[], &[], &[], &[], &[])).unwrap();
        assert!(out.contains("protocol direct direct1 {"));
        assert!(!out.contains("protocol direct direct_"));
    }

    /// bird_exporter reads a protocol's "Since" field to compute uptime, and only understands
    /// this format - without it, every protocol reports zero uptime.
    #[test]
    fn render_sets_the_timeformat_bird_exporter_needs_for_uptime() {
        let out = render(identity(), 64512, &inputs(&[], &[], &[], &[], &[])).unwrap();
        assert!(out.contains("timeformat protocol iso long;"));
    }

    #[test]
    fn render_includes_a_protocol_direct_block_per_direct_interface() {
        let direct_interfaces = ["cni0".to_string()];
        let out = render(
            identity(),
            64512,
            &inputs_with_direct(&[], &[], &[], &[], &[], &direct_interfaces),
        )
        .unwrap();
        let block = out
            .split("protocol direct direct_cni0 {")
            .nth(1)
            .expect("a protocol direct block named after the interface must be present")
            .split("\n}\n")
            .next()
            .unwrap();
        assert!(block.contains("interface \"cni0\";"));
        assert!(block.contains("ipv4 { import all; };"));
    }

    #[test]
    fn render_direct_interfaces_get_distinct_sanitized_protocol_ids() {
        let direct_interfaces = ["cni0".to_string(), "my-bridge".to_string()];
        let out = render(
            identity(),
            64512,
            &inputs_with_direct(&[], &[], &[], &[], &[], &direct_interfaces),
        )
        .unwrap();
        assert!(out.contains("protocol direct direct_cni0 {"));
        assert!(out.contains("protocol direct direct_my_bridge {"));
        assert!(out.contains("interface \"my-bridge\";"));
    }

    #[test]
    fn render_includes_bgp_peer_with_sanitized_protocol_id() {
        let peers = vec![BgpPeer {
            name: "fra-1".to_string(),
            address: "fd00::2".parse().unwrap(),
        }];
        let out = render(identity(), 64512, &inputs(&[], &peers, &[], &[], &[])).unwrap();
        assert!(out.contains("protocol bgp ibgp6_fra_1 {"));
        assert!(out.contains("neighbor fd00::2 as 64512;"));
        assert!(out.contains("local fd00::1 as 64512;"));
    }

    #[test]
    fn bypass_and_announce_diverge_on_route_kind() {
        let bypass = vec![BypassRoute {
            net: "203.0.113.0/24".to_string(),
            label: "some vendor".to_string(),
        }];
        let announce = vec![AnnounceRoute {
            net: "10.96.0.0/12".to_string(),
            label: "k8s-services".to_string(),
        }];
        let out = render(
            identity(),
            64512,
            &inputs(&[], &[], &bypass, &announce, &[]),
        )
        .unwrap();

        let bypass_block = out
            .split("protocol static BYPASS {")
            .nth(1)
            .unwrap()
            .split("\n}\n")
            .next()
            .unwrap();
        assert!(bypass_block.contains("blackhole;"));
        assert!(!bypass_block.contains("via \"router-lo\""));

        let announce_block = out
            .split("protocol static ANNOUNCE {")
            .nth(1)
            .unwrap()
            .split("\n}\n")
            .next()
            .unwrap();
        assert!(announce_block.contains("via \"router-lo\";"));
        assert!(!announce_block.contains("blackhole"));
    }

    #[test]
    fn empty_learn_disables_kernel_learn_and_rts_inherit() {
        let peers = vec![BgpPeer {
            name: "peer1".to_string(),
            address: "fd00::2".parse().unwrap(),
        }];
        let conf = render(identity(), 64512, &inputs(&[], &peers, &[], &[], &[])).unwrap();
        assert!(conf.contains("learn no;"));
        assert!(!conf.contains("import filter"));
        assert!(!conf.contains("RTS_INHERIT"));
    }

    #[test]
    fn nonempty_learn_scopes_kernel_import_with_plus_modifier_and_exports_rts_inherit() {
        let peers = vec![BgpPeer {
            name: "peer1".to_string(),
            address: "fd00::2".parse().unwrap(),
        }];
        let learn = vec!["10.99.0.0/24".to_string()];
        let conf = render(identity(), 64512, &inputs(&[], &peers, &[], &[], &learn)).unwrap();
        // `all`, not a bare `learn` - see `RenderInputs`'s doc comment: without it BIRD skips
        // KRT_SRC_KERNEL routes, which is the only kind a node's own podCIDR route ever is.
        assert!(conf.contains("    learn all;\n"));
        assert!(!conf.contains("    learn;\n"));
        assert!(conf.contains("if net ~ [ 10.99.0.0/24+ ] then accept;"));
        assert!(conf.contains("if source = RTS_INHERIT then accept;"));
        assert!(!conf.contains("learn no;"));
    }

    #[test]
    fn comment_strips_embedded_newlines() {
        assert_eq!(
            sanitize_comment("legit label\nprotocol static evil { route 0.0.0.0/0 blackhole; }"),
            "legit label protocol static evil { route 0.0.0.0/0 blackhole; }"
        );
        assert_eq!(sanitize_comment("plain label"), "plain label");
    }

    #[test]
    fn sanitize_quoted_strips_quotes_and_newlines() {
        assert_eq!(
            sanitize_quoted("mesh-lon\"; protocol static evil { route 0.0.0.0/0 blackhole; } \""),
            "mesh-lon; protocol static evil { route 0.0.0.0/0 blackhole; } "
        );
        assert_eq!(sanitize_quoted("mesh-lon"), "mesh-lon");
    }

    #[test]
    fn sanitize_protocol_id_replaces_invalid_characters() {
        assert_eq!(sanitize_protocol_id("fra-1"), "fra_1");
        assert_eq!(sanitize_protocol_id("fra.eu"), "fra_eu");
    }

    #[test]
    fn sanitize_protocol_id_prefixes_a_leading_digit() {
        assert_eq!(sanitize_protocol_id("1fra"), "_1fra");
    }
}
