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

use crate::bird_conf::{self, ROUTER_LOOPBACK_IFACE, RenderInputs, RouterIdentity};
use anyhow::{Context, Result};
use common::netlink::rt::RtClient;
use common::template::Template;
use std::collections::HashSet;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::Path;

/// This daemon spawns `bird` itself (see `main.rs`) and always launches it with `-s
/// BIRD_CONTROL_SOCKET`, so the two agree on this path by construction rather than by convention.
pub const BIRD_CONTROL_SOCKET: &str = "/run/bird.ctl";

/// The subset of `ospf_interfaces` that are exact interface names - no `*`/`?` glob characters,
/// and not a CIDR. Used by `protocols_healthy` to check `show ospf interface` against a concrete
/// expected set; glob/CIDR entries have no single expected name to diff against, so they're
/// excluded here rather than guessed at (see this module's `protocols_healthy` doc comment).
pub fn exact_iface_names(ospf_interfaces: &[String]) -> Vec<String> {
    ospf_interfaces
        .iter()
        .filter(|entry| {
            !entry.contains('*') && !entry.contains('?') && common::cidr::parse_cidr(entry).is_err()
        })
        .cloned()
        .collect()
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

/// For a `strict bind yes` protocol whose local address doesn't exist yet at bind
/// time, `show protocols`' Info column reads exactly `Error: No
/// listening socket`, a terminal failure state distinct from the normal `Connect`/`Active`/
/// `OpenSent` states a still-negotiating-but-healthy session passes through - so matching this
/// substring anywhere in `show protocols` can't false-positive on a peer that's simply not up yet.
fn has_no_listening_socket(show_protocols_output: &str) -> bool {
    show_protocols_output.contains("No listening socket")
}

/// Every interface name BIRD's OSPF instance has actually attached to, per a real
/// `birdc show ospf interface <proto>`: each configured interface
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
    template: &Template,
    identity: RouterIdentity,
    as_number: u32,
    inputs: &RenderInputs<'_>,
) -> Result<()> {
    let desired = bird_conf::render(template, identity, as_number, inputs)?;
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
    let link_local = crate::cidr::link_local_from_loopback(ipv6_loopback);
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

    #[test]
    fn exact_iface_names_excludes_globs_and_cidrs() {
        let entries = vec![
            "mesh-fra".to_string(),
            "mesh-*".to_string(),
            "10.99.0.0/24".to_string(),
        ];
        assert_eq!(exact_iface_names(&entries), vec!["mesh-fra".to_string()]);
    }

    // Fixtures below are real `birdc` output, captured against BIRD 2.19.1 running in a container
    // with a deliberately reproduced "strict bind yes local address not present yet" / "OSPF
    // interface not attached yet" race - not hand-guessed from memory of BIRD's CLI format.
    //
    // The extension shipped 2.19.2 then, one patch release on from the capture. They would hold for 3.3.2
    // as well: all three formats are byte-identical in its sources - `nest/proto.c`'s
    // `cli_msg(-1002, "%-10s %-10s %-10s %-6s %-12s  %s")` with the same header row,
    // `proto/ospf/iface.c`'s `cli_msg(-1015, "Interface %s (%N)")`, and "No listening socket"
    // in `proto/bgp/bgp.c`'s `bgp_misc_errors[]`. Only the version in the greeting differs, and
    // nothing here reads it. That comparison is kept for whenever 3.x is attempted again: it is
    // not pinned now, its own filter_test having died with SIGILL in slipmesh/bird's static
    // build.
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
