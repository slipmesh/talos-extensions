//! Renders the full BIRD config from the current desired state on every reconcile pass (not
//! patched incrementally) and reloads it via `birdc configure` - a live reload, not a restart, so
//! it doesn't flap sessions unaffected by whatever changed. OSPFv3 over the mesh links (IPv6
//! link-local neighbors, carrying only IPv6 loopbacks), an iBGP full mesh over those loopbacks
//! using `multihop` + RFC 8950 (`extended next hop on`) to carry the same IPv4 payload prefixes
//! BYPASS/ANNOUNCE/road-warrior `learn` always have, just with an IPv6 next-hop. The kernel
//! protocol's scoped `learn` picks up kernel routes inside the configured `learn` CIDR ranges
//! (installed by `ext-awg`'s own handshake/route tracking for road-warrior peers - see
//! `talos-extensions/awg`) and re-announces them over iBGP as `RTS_INHERIT`. Still out of scope:
//! eBGP peers.
//!
//! Ported from `slipmesh/operators`' `router/src/bird.rs`, with
//! the Kubernetes-only pieces dropped (CNI conflist rendering, the `DIRECT_CNI` protocol block,
//! `ospf_ifaces`/`bgp_peers` derived from CRDs) and replaced by what `router.yaml` declares
//! directly - see `talos-extensions/README.md`'s design notes and `config.rs`'s doc comments for
//! the static-config shape this now renders from.

use anyhow::{Context, Result};
use askama::Template;
use common::netlink::rt::RtClient;
use std::collections::HashSet;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::Path;

/// Dedicated dummy interface carrying this node's router identity /32 and IPv6 loopback /128 -
/// kept separate from the real `lo` and from `ext-awg`-managed interfaces so nothing but this
/// daemon ever touches it.
pub const ROUTER_LOOPBACK_IFACE: &str = "router-lo";

/// This daemon spawns `bird` itself (see `main.rs`) and always launches it with `-s
/// BIRD_CONTROL_SOCKET`, so the two agree on this path by construction rather than by convention.
pub const BIRD_CONTROL_SOCKET: &str = "/run/bird.ctl";

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
    if common::netlink::rt::parse_cidr(entry).is_ok() {
        entry.to_string()
    } else {
        format!("\"{}\"", sanitize_quoted(entry))
    }
}

/// The subset of `ospf_interfaces` that are exact interface names - no `*`/`?` glob characters,
/// and not a CIDR. Used by `protocols_healthy` to check `show ospf interface` against a concrete
/// expected set; glob/CIDR entries have no single expected name to diff against, so they're
/// excluded here rather than guessed at (see this module's `protocols_healthy` doc comment).
pub fn exact_iface_names(ospf_interfaces: &[String]) -> Vec<String> {
    ospf_interfaces
        .iter()
        .filter(|entry| {
            !entry.contains('*')
                && !entry.contains('?')
                && common::netlink::rt::parse_cidr(entry).is_err()
        })
        .cloned()
        .collect()
}

/// OSPFv3 over the mesh links + loopback stub (`export none` - OSPF must never re-export
/// kernel/BGP routes back into the IGP) plus an iBGP full mesh over loopbacks (`multihop` +
/// RFC 8950), exporting this node's own IPv4 loopback (`source = RTS_DEVICE`, `direct1`/
/// `router-lo` is a `protocol direct` instance), this node's own BYPASS/ANNOUNCE statics
/// (`source = RTS_STATIC`), and any kernel-learned route inside a `learn` CIDR range
/// (`source = RTS_INHERIT`) - not OSPF-learned routes, which would risk a route-preference fight
/// between the two protocols for the same prefix.
///
/// `RTS_DEVICE` matters specifically because OSPFv3 is IPv6-only by protocol design - it can never
/// carry an IPv4 loopback, so mesh-wide IPv4 loopback-to-loopback reachability has nowhere to come
/// from *except* BGP. The IPv4 kernel protocol's export filter sets `krt_prefsrc` to this node's
/// own loopback on every exported (`RTS_BGP`) route: mesh links carry no IPv4 address at all
/// (link-local IPv6 only), so a BGP-learned route's next-hop interface has nothing for Linux to
/// pick a source address from on its own - without an explicit hint, the kernel would default to
/// whatever address its normal route-selection picks, and a reply sent with that source gets
/// dropped by the peer as a bogon.
///
/// The `ANNOUNCE` protocol instance (not `BYPASS`) additionally gets its own `if proto =
/// "ANNOUNCE" then { krt_prefsrc = ...; accept; }` clause, by name rather than by `source =
/// RTS_STATIC` (which would catch `BYPASS` too - deliberately not done, see below). Confirmed
/// directly this matters, not just for symmetry: there's no overlay here, mesh links carry no
/// encapsulation, so a host-network process's *own* connection to a Service ClusterIP (e.g.
/// `10.60.234.252`, inside the cluster.service_subnet `ANNOUNCE`s) picks its source address at
/// socket-connect time, in a route lookup against the *pre*-DNAT destination - a separate, earlier
/// step than kube-proxy's own DNAT rewrite. Without a specific local route to the whole service
/// subnet, that lookup falls through to the node's real default route (its public WAN interface),
/// so the connection leaves with the node's public IP as source regardless of how correctly
/// kube-proxy rewrites the destination afterwards. Safe to install locally precisely because
/// `cluster.service_subnet` is never a real Internet destination - nothing else could ever
/// legitimately compete for it.
///
/// `BYPASS` is deliberately excluded from this - unlike the service subnet, `bypass.include`
/// resolves to *real* Internet prefixes (GitHub, Google, Yandex, ...), and this same node also
/// makes its own genuine outbound connections to some of them (image pulls, DNS, etc.). Installing
/// `BYPASS`'s `blackhole`/relay routes into this node's *own* kernel table would hijack that
/// traffic too, not just what's meant to be relayed for peers - a real regression, not a fix. Only
/// the export to iBGP peers matters for `BYPASS` (already unconditional on `source = RTS_STATIC`
/// there, unaffected by this filter), not local kernel installation.
///
/// `learn` entries get a trailing `+` in the rendered prefix-set pattern (`net ~ [ 10.99.0.0/24+
/// ]`) - "this network and everything more specific inside it", not an exact-match list of every
/// individual road-warrior `/32` (the k8s original's shape). Empty `learn` means `learn` stays off
/// entirely in the kernel protocol.
///
/// `learn all`, not a bare `learn`: BIRD's two learn modes differ in exactly the case this needs.
/// A bare `learn` is `KRT_LEARN_ALIEN` and picks up only routes installed by *other daemons*;
/// `learn all` is `KRT_LEARN_ALL` and additionally picks up `KRT_SRC_KERNEL` - routes carrying
/// `RTPROT_KERNEL`, which is what the kernel stamps on a connected route it derives from an
/// interface address (`sysdep/unix/krt.h`'s `KRT_LEARN_*`, the `case KRT_SRC_KERNEL: if
/// (KRT_CF->learn != KRT_LEARN_ALL) goto ignore;` in `krt.c`, and `krt.Y`'s `kern_learn` grammar,
/// all as of the BIRD 2.18 this extension pins). A node's own podCIDR route is precisely such a
/// route under every CNI tried - `10.61.x.0/24 dev cni0` under bridge/host-local, `10.61.x.0/24
/// via 10.61.x.1 dev cilium_host` under Cilium - so a bare `learn` silently learns nothing and the
/// node stops announcing its pods to the mesh: the filter matches and the route sits in the FIB,
/// but nothing reaches any peer.
///
/// `all` widens the *source* of learnable routes, not the *scope*: the `import filter` above still
/// rejects everything outside the configured prefixes, so this is not "learn the whole table".
///
/// The desired-state inputs that vary independently of `identity`/`as_number` - bundled into one
/// struct (rather than five loose slice params) purely to keep `render`/`reconcile` under this
/// workspace's default clippy `too-many-arguments` threshold, not because these five are used
/// together for any other reason.
pub struct RenderInputs<'a> {
    pub ospf_interfaces: &'a [String],
    pub bgp_peers: &'a [BgpPeer],
    pub bypass: &'a [BypassRoute],
    pub announce: &'a [AnnounceRoute],
    pub learn: &'a [String],
    /// Extra interfaces (exact name, glob, or CIDR - same grammar as `ospf_interfaces`) to treat
    /// as `protocol direct` sources, each exported over iBGP by the existing `RTS_DEVICE` clause
    /// (the same one that already carries `router-lo`'s own loopback) - no separate wiring needed
    /// per entry. Not specific to any one purpose: a pod-network bridge (`cni0`, written by a
    /// separate component - see `slipmesh/cni-config`) is the motivating case, but this field
    /// doesn't know or care what the interface is for.
    pub direct_interfaces: &'a [String],
}

/// Rendered via `templates/bird.conf` (askama) - `escape = "none"` since this is plain BIRD
/// syntax, not HTML.
pub fn render(identity: RouterIdentity, as_number: u32, inputs: &RenderInputs) -> Result<String> {
    let rendered_peers: Vec<RenderedBgpPeer> = inputs
        .bgp_peers
        .iter()
        .map(|p| RenderedBgpPeer {
            protocol_id: sanitize_protocol_id(&p.name),
            address: p.address,
        })
        .collect();
    let learn_patterns: Vec<String> = inputs.learn.iter().map(|cidr| format!("{cidr}+")).collect();
    let direct_interfaces: Vec<RenderedDirectIface> = inputs
        .direct_interfaces
        .iter()
        .map(|s| RenderedDirectIface {
            protocol_id: sanitize_protocol_id(s),
            pattern: render_iface_pattern(s),
        })
        .collect();

    BirdConfigTemplate {
        loopback: identity.loopback,
        ipv6_loopback: identity.ipv6_loopback,
        as_number,
        router_loopback_iface: ROUTER_LOOPBACK_IFACE,
        ospf_interfaces: inputs
            .ospf_interfaces
            .iter()
            .map(|s| render_iface_pattern(s))
            .collect(),
        bgp_peers: rendered_peers,
        bypass: SanitizedRoute::from_routes(inputs.bypass),
        announce: SanitizedRoute::from_routes(inputs.announce),
        learn: learn_patterns,
        direct_interfaces,
    }
    .render()
    .context("failed to render bird.conf")
}

struct RenderedBgpPeer {
    protocol_id: String,
    address: Ipv6Addr,
}

struct RenderedDirectIface {
    protocol_id: String,
    pattern: String,
}

#[derive(askama::Template)]
#[template(path = "bird.conf", escape = "none")]
struct BirdConfigTemplate {
    loopback: Ipv4Addr,
    ipv6_loopback: Ipv6Addr,
    as_number: u32,
    router_loopback_iface: &'static str,
    ospf_interfaces: Vec<String>,
    bgp_peers: Vec<RenderedBgpPeer>,
    bypass: Vec<SanitizedRoute>,
    announce: Vec<SanitizedRoute>,
    learn: Vec<String>,
    direct_interfaces: Vec<RenderedDirectIface>,
}

/// Name of this daemon's rendered OSPFv3 protocol block - see `render()`.
const OSPF_PROTOCOL: &str = "mesh6";

async fn run_birdc_configure() -> Result<()> {
    let reply = crate::birdc::command(Path::new(BIRD_CONTROL_SOCKET), "configure").await?;
    anyhow::ensure!(!reply.is_error(), "birdc configure failed: {}", reply.text);
    Ok(())
}

async fn birdc_show(command: &str) -> Result<String> {
    let reply = crate::birdc::command(Path::new(BIRD_CONTROL_SOCKET), command).await?;
    anyhow::ensure!(!reply.is_error(), "birdc {command} failed: {}", reply.text);
    Ok(reply.text)
}

/// For a BIRD 2.19.1 `strict bind yes` protocol whose local address doesn't exist yet at bind
/// time, `show protocols`' Info column reads exactly `Error: No
/// listening socket`, a terminal failure state distinct from the normal `Connect`/`Active`/
/// `OpenSent` states a still-negotiating-but-healthy session passes through - so matching this
/// substring anywhere in `show protocols` can't false-positive on a peer that's simply not up yet.
fn has_no_listening_socket(show_protocols_output: &str) -> bool {
    show_protocols_output.contains("No listening socket")
}

/// Every interface name BIRD's OSPF instance has actually attached to, per a real
/// `birdc show ospf interface <proto>` (verified against BIRD 2.19.1): each configured interface
/// prints as a `Interface <name> (<network>)` line, in a block that's entirely absent (just the
/// `<proto>:` header) when nothing has been attached yet.
fn ospf_configured_interfaces(show_ospf_interface_output: &str) -> HashSet<&str> {
    show_ospf_interface_output
        .lines()
        .filter_map(|l| l.strip_prefix("Interface "))
        .filter_map(|l| l.split_whitespace().next())
        .collect()
}

/// True if BIRD's live state (queried fresh via `birdc show ...`, never the rendered config text)
/// shows no protocol stuck in `Error: No listening socket`, and every name in
/// `exact_ospf_ifaces` (see `exact_iface_names` - only literal names, not glob/CIDR entries, since
/// those have no single expected name to diff against here) has a working OSPF interface attached.
/// Both are symptoms of the same interface-notification race `force_reconfigure`'s doc comment
/// describes - a config that already lists an interface/peer doesn't mean BIRD's interface manager
/// actually caught up to it yet, and a config-diff-gated `reconcile()` alone can never detect or
/// retry that on its own.
pub async fn protocols_healthy(exact_ospf_ifaces: &[String]) -> Result<bool> {
    let protocols = birdc_show("show protocols").await?;
    if has_no_listening_socket(&protocols) {
        return Ok(false);
    }
    if exact_ospf_ifaces.is_empty() {
        return Ok(true);
    }
    let ospf = birdc_show(&format!("show ospf interface {OSPF_PROTOCOL}")).await?;
    let configured = ospf_configured_interfaces(&ospf);
    Ok(exact_ospf_ifaces
        .iter()
        .all(|iface| configured.contains(iface.as_str())))
}

pub async fn reconcile(
    path: &Path,
    identity: RouterIdentity,
    as_number: u32,
    inputs: &RenderInputs<'_>,
) -> Result<()> {
    let desired = render(identity, as_number, inputs)?;
    let current = tokio::fs::read_to_string(path).await.unwrap_or_default();
    if current == desired {
        return Ok(());
    }
    tokio::fs::write(path, &desired)
        .await
        .with_context(|| format!("failed to write {}", path.display()))?;
    run_birdc_configure().await
}

/// Unconditional reload, bypassing the config-text diff `reconcile()` uses to skip redundant
/// reloads: `strict bind yes` BGP protocols and OSPF interfaces can both lose a race against the
/// kernel's own (asynchronous) interface/address-change notification reaching BIRD's interface
/// manager, landing in a permanent "No listening socket" / never-attaches state from the first
/// reload even though the config text already lists them correctly. Since the config text never
/// changes again afterward, `reconcile()`'s diff check would never retry on its own - called by
/// `main.rs`'s `bird_health_watchdog` whenever `protocols_healthy` reports a drift, not on a fixed
/// startup-only timer. Cheap and safe even as a false-positive nudge: BIRD re-applying the same
/// config doesn't tear down any session already up.
pub async fn force_reconfigure() -> Result<()> {
    run_birdc_configure().await
}

/// This node's deterministic IPv6 link-local address for `router-lo`, derived from the low 32
/// bits of its own configured `ipv6_loopback` (`fe80::<hex>`, e.g. `fd00::a1b2c3d4` ->
/// `fe80::a1b2:c3d4`) - not a separately-configured `node_id` the way the k8s original derived it
/// (that concept doesn't exist here; `router.yaml` gives each node's loopbacks directly, see
/// `RouterIdentity`'s doc comment), just reusing the same digits already unique to this node by
/// construction (they're a real, config-supplied loopback address).
///
/// `pub`, not just used internally by `ensure_loopback`: the `patches` crate (a separate crate
/// from this lib target, generating the `ipv6_loopback` this daemon reads rather than reading it)
/// calls this too, for its mesh-interface link-locals - it computes an `ipv6_loopback`-shaped
/// value from a node's `node_id` first (see `patches::addressing::ipv6_loopback`), whose low 32
/// bits are `node_id`'s bits by construction, so this same function derives the identical
/// `fe80::<hex node_id>` the old k8s system computed directly from `node_id`.
pub fn link_local_from_loopback(ipv6_loopback: Ipv6Addr) -> Ipv6Addr {
    let bits = u128::from(ipv6_loopback) as u32;
    let mut segments = [0u16; 8];
    segments[0] = 0xfe80;
    segments[6] = (bits >> 16) as u16;
    segments[7] = bits as u16;
    Ipv6Addr::from(segments)
}

/// Ensures the dedicated router loopback (`router-lo`, a dummy interface) exists and carries this
/// node's IPv4 loopback /32, IPv6 loopback /128, and a deterministic IPv6 link-local - all three
/// in one `ensure_addresses` call (unlike the k8s original's separate `ensure_address`/
/// `ensure_address_v6` calls - this repo's `common::netlink::rt` already generalized that into one
/// call taking any mix of IPv4/IPv6 CIDRs, see its own doc comment).
///
/// The link-local is not optional: OSPFv3 (RFC 5340) sources every packet it sends from an
/// interface's link-local address, even on a `stub yes` interface that never sends Hello, so
/// without one BIRD never registers `router-lo` as an OSPF interface at all - silently, with no
/// log line - and never originates this node's stub network. A dummy interface normally gets one
/// for free from the kernel's own EUI-64 autoconfiguration, but passing only the global /128 in
/// `ensure_addresses`'s desired set would delete that autoconfigured address on the very next
/// reconcile pass as "stale" (every address of a given family not in the desired set gets
/// removed) - deriving one explicitly here, the same way `awg::interface::ensure_interface` does
/// for its own interfaces, keeps a link-local present across every reconcile instead of depending
/// on the kernel to generate and then keep one.
///
/// Deliberately does **not** attempt to write `net.ipv6.conf.router-lo.keep_addr_on_down` itself:
/// `talos-awg-extension/docs/extension-services.md` documents this failing on a real node for
/// `ext-awg`'s own interfaces (an extension-service container isn't permitted to write
/// `/proc/sys` there) - the fix is the same one already required for `ext-awg`, setting
/// `machine.sysctls: net.ipv6.conf.default.keep_addr_on_down: "1"` once in machine config, which
/// the kernel copies into every interface's own devconf at creation time (including `router-lo`,
/// created after that sysctl is applied) with no code needed here at all.
pub async fn ensure_loopback(
    rt: &RtClient,
    loopback: Ipv4Addr,
    ipv6_loopback: Ipv6Addr,
) -> Result<()> {
    let (index, _created) = rt.ensure_link(ROUTER_LOOPBACK_IFACE, "dummy").await?;
    let link_local = link_local_from_loopback(ipv6_loopback);
    rt.ensure_addresses(
        index,
        &[
            format!("{loopback}/32"),
            format!("{ipv6_loopback}/128"),
            format!("{link_local}/64"),
        ],
    )
    .await?;
    rt.set_up(index).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

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
        }
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

    #[test]
    fn render_includes_ospf_interfaces_as_names_and_cidrs() {
        let ifaces = ["mesh-*".to_string(), "10.99.0.0/24".to_string()];
        let out = render(identity(), 64512, &inputs(&ifaces, &[], &[], &[], &[])).unwrap();
        assert!(out.contains("interface \"mesh-*\" { type ptp; };"));
        assert!(out.contains("interface 10.99.0.0/24 { type ptp; };"));
        assert!(out.contains("interface \"router-lo\" { stub yes; };"));
    }

    #[test]
    fn render_direct_interfaces_is_empty_by_default() {
        let out = render(identity(), 64512, &inputs(&[], &[], &[], &[], &[])).unwrap();
        assert!(out.contains("protocol direct direct1 {"));
        assert!(!out.contains("protocol direct direct_"));
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

    #[test]
    fn exact_iface_names_excludes_globs_and_cidrs() {
        let entries = vec![
            "mesh-fra".to_string(),
            "mesh-*".to_string(),
            "10.99.0.0/24".to_string(),
        ];
        assert_eq!(exact_iface_names(&entries), vec!["mesh-fra".to_string()]);
    }

    #[test]
    fn link_local_from_loopback_derives_fe80_from_low_32_bits() {
        assert_eq!(
            link_local_from_loopback("fd00::a1b2:c3d4".parse().unwrap()).to_string(),
            "fe80::a1b2:c3d4"
        );
    }

    // Fixtures below are real `birdc` output, captured against BIRD 2.19.1 running in a container
    // with a deliberately reproduced "strict bind yes local address not present yet" / "OSPF
    // interface not attached yet" race - not hand-guessed from memory of BIRD's CLI format.
    const SHOW_PROTOCOLS_NO_LISTENING_SOCKET: &str = "\
BIRD 2.19.1 ready.
Name       Proto      Table      State  Since         Info
device1    Device     ---        up     22:24:15.259
ospf1      OSPF       master4    up     22:24:15.259  Alone
ibgp_test  BGP        ---        down   22:24:15.266  Error: No listening socket
";

    const SHOW_PROTOCOLS_HEALTHY: &str = "\
BIRD 2.19.1 ready.
Name       Proto      Table      State  Since         Info
device1    Device     ---        up     22:30:37.362
mesh       OSPF       master4    up     22:30:37.362  Alone
ibgp_test  BGP        ---        start  22:31:14.133  Connect
";

    const SHOW_OSPF_INTERFACE_NONE_CONFIGURED: &str = "BIRD 2.19.1 ready.\nmesh:\n";

    const SHOW_OSPF_INTERFACE_TWO_CONFIGURED: &str = "\
BIRD 2.19.1 ready.
mesh:
Interface lo (10.0.0.1/32)
\tType: nbma
\tArea: 0.0.0.0 (0)
\tState: Waiting (stub)
Interface mesh-a (10.99.0.0/31)
\tType: ptp
\tArea: 0.0.0.0 (0)
\tState: PtP (stub)
Interface mesh-b (10.99.0.2/31)
\tType: ptp
\tArea: 0.0.0.0 (0)
\tState: PtP (stub)
";

    #[test]
    fn detects_no_listening_socket() {
        assert!(has_no_listening_socket(SHOW_PROTOCOLS_NO_LISTENING_SOCKET));
    }

    #[test]
    fn no_listening_socket_absent_when_healthy() {
        assert!(!has_no_listening_socket(SHOW_PROTOCOLS_HEALTHY));
    }

    #[test]
    fn parses_configured_ospf_interfaces() {
        let configured = ospf_configured_interfaces(SHOW_OSPF_INTERFACE_TWO_CONFIGURED);
        assert_eq!(configured, HashSet::from(["lo", "mesh-a", "mesh-b"]));
    }

    #[test]
    fn no_configured_ospf_interfaces_parses_as_empty() {
        assert!(ospf_configured_interfaces(SHOW_OSPF_INTERFACE_NONE_CONFIGURED).is_empty());
    }
}
