//! Renders `bird.conf` from a template given to the daemon at runtime, and the context that
//! template reads. Pure, with no netlink or BIRD process behind it, so that `taloscfg` renders a
//! node's template the same way the node will and refuses one that does not render.

use anyhow::Result;
use common::template::{Template, VALUES, Values, ValuesContext};
use serde::Serialize;
use sliplib_config::Prefix4;
use sliplib_config::router::{BgpPeerEntry, InterfacePattern, ROUTER_LOOPBACK, RouterConfig};
use std::net::{Ipv4Addr, Ipv6Addr};

/// This node's own OSPF/BGP-standard IPv4 loopback plus its IPv6 loopback (the OSPFv3/RFC 8950
/// underlay's session-source address) - grouped into one param rather than two loose ones purely
/// to keep `render`/`reconcile` under this workspace's `too-many-arguments-threshold`, not because
/// the two are used together for any other reason. Both come straight from
/// `config::NodeIdentity::loopback_addresses`.
#[derive(Clone, Copy)]
pub struct RouterIdentity {
    pub loopback: Ipv4Addr,
    pub ipv6_loopback: Ipv6Addr,
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

#[derive(Clone, Debug, PartialEq)]
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

/// BIRD's `interface` clause takes a name or a glob quoted; the pattern holds no `"` to break out.
fn render_iface_pattern(pattern: &InterfacePattern) -> String {
    format!("\"{}\"", pattern.as_str())
}

/// The desired-state inputs that vary independently of `identity`/`as_number` - one struct
/// rather than five loose slice params, to stay under the workspace's `too-many-arguments`
/// clippy threshold.
pub struct RenderInputs<'a> {
    /// OSPFv3 runs over the mesh links plus the loopback stub, and never re-exports
    /// kernel or BGP routes back into the IGP (`export none`).
    pub ospf_interfaces: &'a [InterfacePattern],
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
    pub bgp_peers: &'a [BgpPeerEntry],
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
    /// IPv4 CIDR *ranges*. Each is rendered with a trailing `+`
    /// (`net ~ [ 203.0.113.128/26+ ]`) - the network and everything more specific inside it, not
    /// an exact-match list of individual `/32`s. The routes `awg` installs are learned whatever
    /// this holds, by their protocol number rather than by range.
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
    pub learn: &'a [Prefix4],
    /// Extra interfaces (exact name or glob, as `ospf_interfaces`) to treat
    /// as `protocol direct` sources, each exported over iBGP by the existing `RTS_DEVICE` clause
    /// (the same one that already carries `router-lo`'s own loopback) - no separate wiring needed
    /// per entry. Not specific to any one purpose: a pod-network bridge (`cni0`, written by a
    /// separate component - see `slipmesh/cni-config`) is the motivating case, but this field
    /// doesn't know or care what the interface is for.
    pub direct_interfaces: &'a [InterfacePattern],
    /// Requests BFD sessions on every OSPF link, with the intervals the mesh chose. A WireGuard
    /// interface stays up whether or not packets still cross it, so without BFD a dead path is
    /// only noticed when OSPF's dead timer expires; the cost is constant control traffic through
    /// every tunnel, which is why this is a `mesh.yaml` switch rather than always on.
    pub bfd: Option<&'a sliplib_config::router::BfdSettings>,
}

/// Where the template reaches the daemon - a `configFiles` entry of its `ExtensionServiceConfig`,
/// next to `router.yaml`.
pub const TEMPLATE_PATH: &str = "/etc/talos-extensions/router.conf.j2";

/// The template a mesh starts from: `taloscfg` writes it into `slipmesh.yaml` when that file has
/// none, and from then on the copy there is the one in force.
pub const REFERENCE_TEMPLATE: &str = include_str!("../templates/router.conf.j2");

/// Every variable `render` supplies - the fields of `BirdConfigContext`.
pub const VARIABLES: [&str; 14] = [
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
    "awg_route_protocol",
    VALUES[0],
    VALUES[1],
];

/// Compiles a `bird.conf` template, refusing one that reads anything outside `VARIABLES`.
pub fn compile(source: impl Into<String>) -> Result<Template> {
    Template::new(source, &VARIABLES)
}

pub fn render(
    template: &Template,
    identity: RouterIdentity,
    as_number: u32,
    inputs: &RenderInputs,
    values: &Values,
) -> Result<String> {
    template.render(BirdConfigContext::new(identity, as_number, inputs, values))
}

/// `cfg`, what `router.yaml` fixes for the life of the process, with the bypass routes only the node
/// can resolve.
pub fn render_config(
    template: &Template,
    cfg: &RouterConfig,
    values: &Values,
    bypass: &[BypassRoute],
) -> Result<String> {
    let loopbacks = cfg.node.loopback_addresses;
    let identity = RouterIdentity {
        loopback: loopbacks.ipv4.0.addr(),
        ipv6_loopback: loopbacks.ipv6.0.addr(),
    };
    let announce: Vec<AnnounceRoute> = cfg
        .announce
        .iter()
        .map(|a| AnnounceRoute {
            net: a.net.0.to_string(),
            label: a.label.clone().unwrap_or_default(),
        })
        .collect();
    let inputs = RenderInputs {
        ospf_interfaces: &cfg.ospf_interfaces,
        bgp_peers: &cfg.bgp_peers,
        bypass,
        announce: &announce,
        learn: &cfg.learn,
        direct_interfaces: &cfg.direct_interfaces,
        bfd: cfg.bfd.as_ref(),
    };
    render(template, identity, cfg.bgp_as, &inputs, values)
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
struct BirdConfigContext<'a> {
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
    bfd: Option<sliplib_config::router::BfdSettings>,
    awg_route_protocol: u8,
    #[serde(flatten)]
    values: ValuesContext<'a>,
}

impl<'a> BirdConfigContext<'a> {
    fn new(
        identity: RouterIdentity,
        as_number: u32,
        inputs: &RenderInputs,
        values: &'a Values,
    ) -> Self {
        let rendered_peers: Vec<RenderedBgpPeer> = inputs
            .bgp_peers
            .iter()
            .map(|p| RenderedBgpPeer {
                protocol_id: sanitize_protocol_id(&p.name),
                address: p.address,
            })
            .collect();
        let learn_patterns: Vec<String> = inputs
            .learn
            .iter()
            .map(|cidr| format!("{}+", cidr.0))
            .collect();
        let direct_interfaces: Vec<RenderedDirectIface> = inputs
            .direct_interfaces
            .iter()
            .map(|s| RenderedDirectIface {
                protocol_id: sanitize_protocol_id(s.as_str()),
                pattern: render_iface_pattern(s),
            })
            .collect();

        Self {
            loopback: identity.loopback,
            ipv6_loopback: identity.ipv6_loopback,
            as_number,
            router_loopback_iface: ROUTER_LOOPBACK,
            ospf_interfaces: inputs
                .ospf_interfaces
                .iter()
                .map(|s| RenderedOspfIface {
                    // The loopback is in this list too, and OSPF runs on it - but there is no
                    // neighbour on a dummy interface, so a BFD session there could only ever sit
                    // down. Asking for one would put a permanently-dead entry in `show bfd sessions`
                    // and teach whoever reads it to ignore that column.
                    bfd: inputs.bfd.is_some() && !s.is_router_loopback(),
                    pattern: render_iface_pattern(s),
                })
                .collect(),
            bgp_peers: rendered_peers,
            bypass: SanitizedRoute::from_routes(inputs.bypass),
            announce: SanitizedRoute::from_routes(inputs.announce),
            learn: learn_patterns,
            bfd: inputs.bfd.cloned(),
            awg_route_protocol: common::ROUTE_PROTOCOL_ID,
            direct_interfaces,
            values: values.context(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn render(identity: RouterIdentity, as_number: u32, inputs: &RenderInputs) -> Result<String> {
        super::render(
            &compile(REFERENCE_TEMPLATE)?,
            identity,
            as_number,
            inputs,
            &Values::default(),
        )
    }

    #[test]
    fn the_classes_and_vars_of_router_yaml_reach_the_template() {
        let text = "node:\n  loopback_addresses: [\"198.51.100.1/32\", \"3fff::1/128\"]\n\
                    bgp_as: 64496\nclasses: {egress: {protocol: 152, table: 152}}\n\
                    vars: {source: 203.0.113.0/26}\n";
        let cfg: RouterConfig = sliplib_yaml::from_str(text).unwrap();
        let values: Values = sliplib_yaml::from_str(text).unwrap();
        let template = compile("{{ classes.egress.table }} {{ vars.source }}").unwrap();
        assert_eq!(
            render_config(&template, &cfg, &values, &[]).unwrap(),
            "152 203.0.113.0/26"
        );
    }

    #[test]
    fn a_config_renders_what_router_yaml_declares() {
        let cfg: RouterConfig = sliplib_yaml::from_str(
            r#"
node:
  loopback_addresses: ["198.51.100.1/32", "3fff::1/128"]
bgp_as: 64496
bgp_peers:
  - {name: node-b, address: "3fff::2"}
bfd: {min_rx_ms: 300, min_tx_ms: 300, multiplier: 5}
ospf_interfaces: [mesh-*]
direct_interfaces: [lan0, mesh-*, eth0.100]
announce:
  - {net: 203.0.113.192/26}
learn: [203.0.113.128/26]
"#,
        )
        .unwrap();
        let bypass = [BypassRoute {
            net: "192.0.2.0/24".to_string(),
            label: "example".to_string(),
        }];
        let out = render_config(
            &compile(REFERENCE_TEMPLATE).unwrap(),
            &cfg,
            &Values::default(),
            &bypass,
        )
        .unwrap();
        assert!(out.contains("router id 198.51.100.1;"));
        assert!(out.contains("local 3fff::1 as 64496;"));
        assert!(out.contains("protocol bgp ibgp6_node_b {"));
        assert!(out.contains("neighbor 3fff::2 as 64496;"));
        assert!(out.contains("route 203.0.113.192/26 via \"router-lo\";"));
        assert!(out.contains("if net ~ [ 203.0.113.128/26+ ] then accept;"));
        assert!(out.contains("route 192.0.2.0/24 blackhole; # example"));
        assert!(out.contains("interface \"mesh-*\" { type ptp; bfd on; };"));
        assert!(out.contains("min rx interval 300 ms;"));
        assert!(out.contains("timeformat protocol iso long;"));
        assert!(out.contains(
            "protocol direct direct1 {\n    interface \"router-lo\";\n    ipv4 { import all; };\n}"
        ));
        assert!(out.contains(
            "protocol direct direct_lan0 {\n    interface \"lan0\";\n    ipv4 { import all; };\n}"
        ));
        assert!(out.contains("protocol direct direct_mesh__ {"));
        assert!(out.contains("protocol direct direct_eth0_100 {"));
    }

    /// The reference render: one iBGP peer, bypass `192.0.2.0/24`, `values`.
    fn reference_with(values: &str) -> String {
        let cfg: RouterConfig = sliplib_yaml::from_str(
            "node:\n  loopback_addresses: [\"198.51.100.1/32\", \"3fff::1/128\"]\n\
             bgp_as: 64496\nbgp_peers:\n  - {name: node-b, address: \"3fff::2\"}\n",
        )
        .unwrap();
        let bypass = [BypassRoute {
            net: "192.0.2.0/24".to_string(),
            label: "example".to_string(),
        }];
        render_config(
            &compile(REFERENCE_TEMPLATE).unwrap(),
            &cfg,
            &sliplib_yaml::from_str(values).unwrap(),
            &bypass,
        )
        .unwrap()
    }

    const EGRESS: &str = "classes: {egress: {protocol: 150, table: 152, rules: {}}}";

    /// Lines an `egress` class with a table adds.
    const EGRESS_PARTS: [&str; 8] = [
        "ipv4 table egress4;\nipv6 table egress6;\n",
        "protocol pipe {\n    table master4;\n    peer table egress4;\n    import none;\n    \
         export filter {\n        if source = RTS_BGP && (64496, 152, 0) ~ bgp_large_community then \
         accept;\n        reject;\n    };\n}\n",
        "protocol pipe {\n    table master6;\n    peer table egress6;\n    import none;\n    \
         export filter {\n        if source = RTS_BGP && (64496, 152, 0) ~ bgp_large_community then \
         accept;\n        reject;\n    };\n}\n",
        "protocol kernel {\n    kernel table 152;\n    ipv4 {\n        table egress4;\n        \
         export filter {\n            krt_prefsrc = 198.51.100.1;\n            accept;\n        \
         };\n    };\n}\n",
        "protocol kernel {\n    kernel table 152;\n    ipv6 {\n        table egress6;\n        \
         export filter {\n            krt_prefsrc = 3fff::1;\n            accept;\n        \
         };\n    };\n}\n",
        "            if source = RTS_BGP then {\n                \
         if (64496, 152, 0) ~ bgp_large_community then reject;\n",
        "            if proto = \"BYPASS\" then {\n                \
         bgp_large_community.add((64496, 152, 0));\n                accept;\n            }\n",
        // Before the general static accept.
        "accept;\n            }\n            if source = RTS_STATIC then accept;",
    ];

    #[test]
    fn an_egress_class_with_a_table_routes_its_community_into_that_table_for_both_families() {
        let out = reference_with(EGRESS);
        for part in EGRESS_PARTS {
            assert!(out.contains(part), "{part}\n---\n{out}");
        }
    }

    #[test]
    fn without_an_egress_class_that_has_a_table_nothing_of_it_is_rendered() {
        for values in ["{}", "classes: {egress: {protocol: 152, rules: {}}}"] {
            let out = reference_with(values);
            for absent in ["egress4", "egress6", "bgp_large_community", "kernel table"] {
                assert!(!out.contains(absent), "{values}: {absent}\n---\n{out}");
            }
        }
    }

    #[test]
    fn every_ibgp_session_carries_ipv6_beside_ipv4() {
        let out = reference_with("{}");
        assert!(
            out.contains(
                "        next hop self;\n    };\n    ipv6 {\n        import all;\n        \
                 export none;\n        next hop self;\n    };\n}"
            ),
            "{out}"
        );
    }

    /// `VARIABLES` is what a template is checked against, the context is what it gets - a field
    /// added to one and not the other would refuse a template that renders, or pass one that
    /// does not.
    #[test]
    fn variables_are_the_fields_of_the_context() {
        let bfd = sliplib_config::router::BfdSettings::default();
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
        let values = Values::default();
        let context =
            serde_json::to_value(BirdConfigContext::new(identity(), 64496, &inputs, &values))
                .unwrap();
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
            loopback: "198.51.100.1".parse().unwrap(),
            ipv6_loopback: "3fff::1".parse().unwrap(),
        }
    }

    fn patterns(list: &[&str]) -> Vec<InterfacePattern> {
        list.iter()
            .map(|p| InterfacePattern::try_from((*p).to_owned()).unwrap())
            .collect()
    }

    /// Positional test helper mirroring `render`/`reconcile`'s pre-`RenderInputs` shape, so each
    /// test case only names the slices it actually varies.
    fn inputs<'a>(
        ospf_interfaces: &'a [InterfacePattern],
        bgp_peers: &'a [BgpPeerEntry],
        bypass: &'a [BypassRoute],
        announce: &'a [AnnounceRoute],
        learn: &'a [Prefix4],
    ) -> RenderInputs<'a> {
        inputs_with_direct(ospf_interfaces, bgp_peers, bypass, announce, learn, &[])
    }

    #[allow(clippy::too_many_arguments)]
    fn inputs_with_direct<'a>(
        ospf_interfaces: &'a [InterfacePattern],
        bgp_peers: &'a [BgpPeerEntry],
        bypass: &'a [BypassRoute],
        announce: &'a [AnnounceRoute],
        learn: &'a [Prefix4],
        direct_interfaces: &'a [InterfacePattern],
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
        // The loopback is in `ospf_interfaces` on every real node.
        let ifaces = patterns(&["mesh-*", "router-lo"]);
        let settings = sliplib_config::router::BfdSettings {
            min_rx_ms: 500,
            ..Default::default()
        };
        let mut with = inputs(&ifaces, &[], &[], &[], &[]);
        with.bfd = Some(&settings);
        let on = render(identity(), 64496, &with).unwrap();

        assert!(on.contains("protocol bfd"));
        // The chosen interval reaches the file, rather than a constant baked into the template.
        assert!(on.contains("min rx interval 500 ms"));
        assert!(on.contains("min tx interval 300 ms"));
        assert!(on.contains("multiplier 5;"));
        assert!(on.contains("interface \"mesh-*\" { type ptp; bfd on; };"));
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
        assert!(!bfd_block.contains("router-lo"));

        let off = render(identity(), 64496, &inputs(&ifaces, &[], &[], &[], &[])).unwrap();
        assert!(!off.contains("bfd"));
    }

    #[test]
    fn render_kernel_export_filter_installs_announce_locally_but_not_bypass() {
        let bypass = vec![BypassRoute {
            net: "192.0.2.0/24".to_string(),
            label: "some vendor".to_string(),
        }];
        let announce = vec![AnnounceRoute {
            net: "203.0.113.192/26".to_string(),
            label: "k8s-services".to_string(),
        }];
        let out = render(
            identity(),
            64496,
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
        assert!(announce_clause.contains("krt_prefsrc = 198.51.100.1;"));
        assert!(announce_clause.contains("accept;"));
        // Nothing in the kernel export filter references BYPASS or the generic RTS_STATIC that
        // would also catch it - only ANNOUNCE gets singled out by name.
        assert!(!kernel_block.contains("BYPASS"));
        assert!(!kernel_block.contains("RTS_STATIC"));
    }

    #[test]
    fn render_direct_interfaces_get_distinct_sanitized_protocol_ids() {
        let direct_interfaces = patterns(&["cni0", "my-bridge"]);
        let out = render(
            identity(),
            64496,
            &inputs_with_direct(&[], &[], &[], &[], &[], &direct_interfaces),
        )
        .unwrap();
        assert!(out.contains("protocol direct direct_cni0 {"));
        assert!(out.contains("protocol direct direct_my_bridge {"));
        assert!(out.contains("interface \"my-bridge\";"));
    }

    #[test]
    fn empty_learn_still_learns_and_announces_the_routes_awg_installs() {
        let peers = vec![BgpPeerEntry {
            name: "peer1".to_string(),
            address: "3fff::2".parse().unwrap(),
        }];
        let conf = render(identity(), 64496, &inputs(&[], &peers, &[], &[], &[])).unwrap();
        // A bare `learn` takes only routes other daemons installed - awg's are exactly that.
        assert!(conf.contains("    learn;\n"), "{conf}");
        assert!(conf.contains("if krt_source = 200 then accept;"), "{conf}");
        assert!(!conf.contains("if net ~"), "{conf}");
        assert!(
            conf.contains("if source = RTS_INHERIT then accept;"),
            "{conf}"
        );
        assert!(!conf.contains("learn no;"), "{conf}");
    }

    #[test]
    fn nonempty_learn_scopes_kernel_import_with_plus_modifier_and_exports_rts_inherit() {
        let peers = vec![BgpPeerEntry {
            name: "peer1".to_string(),
            address: "3fff::2".parse().unwrap(),
        }];
        let learn = vec![Prefix4::try_from("203.0.113.128/26".to_owned()).unwrap()];
        let conf = render(identity(), 64496, &inputs(&[], &peers, &[], &[], &learn)).unwrap();
        // `all`, not a bare `learn` - see `RenderInputs`'s doc comment: without it BIRD skips
        // KRT_SRC_KERNEL routes, which is the only kind a node's own podCIDR route ever is.
        assert!(conf.contains("    learn all;\n"));
        assert!(!conf.contains("    learn;\n"));
        assert!(conf.contains("if net ~ [ 203.0.113.128/26+ ] then accept;"));
        assert!(conf.contains("if krt_source = 200 then accept;"));
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
    fn sanitize_protocol_id_prefixes_a_leading_digit() {
        assert_eq!(sanitize_protocol_id("1fra"), "_1fra");
    }
}
