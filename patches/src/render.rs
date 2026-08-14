//! Per-node computation: `mesh.yaml` -> this node's `awg`/`router`/`nftables` config. Ported from
//! `slipmesh-core::desired_state`'s full-mesh-minus-self BGP/OSPF derivation, adapted to a static
//! config file instead of live `NodeConfig`/`MeshLink` CRDs.
//!
//! Two secrets need resolving *once for the whole topology*, not independently per node, before
//! any single node's config can be rendered:
//! - A mesh link's obfuscation (`h1-h4` especially) is declared once per link in `mesh.yaml`
//!   because AmneziaWG's magic-header substitution requires both peers to agree on the same
//!   values - generating it independently on each end would produce two different, incompatible
//!   values and break the link.
//! - A node's mesh private key is one identity shared across every `mesh.links` interface on that
//!   node; the *other* end of each link needs that node's *public* key, derived from it - so
//!   rendering node A's config requires already knowing node B's resolved private key, not just
//!   A's own.
//!
//! `ExistingState` abstracts "what's already on disk" (the idempotency tiers' middle rung) behind
//! a trait so this module's logic stays pure and unit-testable without real file I/O; `main.rs`
//! supplies the real implementation, reading `patches/<node>.yaml` via `segments`/`awg::config`.

use crate::addressing;
use crate::keys;
use crate::mesh_config::{BypassSourceEntry, MeshConfig};
use crate::obfuscation_gen;
use anyhow::{Context, Result};
use awg::config::{AwgConfig, InterfaceEntry, PeerEntry};
use common::Obfuscation;
use nftables::config::NftablesConfig;
use router::config::{AnnounceEntry, BgpPeerEntry, BypassConfig, NodeIdentity, RouterConfig};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// What's already on disk, for the idempotency tiers that fall back to a *previous* value before
/// generating a fresh one. `pair`/`node_name`/`pool_name` always come from `mesh.yaml` itself.
pub trait ExistingState {
    fn mesh_private_key(&self, node_name: &str) -> Option<String>;
    fn mesh_link_obfuscation(&self, pair: &[String; 2]) -> Option<Obfuscation>;
    fn roadwarrior_private_key(&self, pool_name: &str) -> Option<String>;
    fn roadwarrior_obfuscation(&self, pool_name: &str) -> Option<Obfuscation>;
}

/// Resolved once for the whole topology - see this module's doc comment for why these two can't
/// be resolved independently per node.
pub struct ResolvedSecrets {
    pub mesh_private_keys: HashMap<String, String>,
    pub mesh_link_obfuscation: HashMap<String, Obfuscation>,
    pub roadwarrior_private_keys: HashMap<String, String>,
    pub roadwarrior_obfuscation: HashMap<String, Obfuscation>,
}

/// Canonical, order-independent key for a mesh link's maps (`pair`'s two names, sorted).
fn link_key(pair: &[String; 2]) -> String {
    let mut sorted = pair.clone();
    sorted.sort();
    format!("{}|{}", sorted[0], sorted[1])
}

fn resolve_string(
    specific: Option<&str>,
    existing: Option<String>,
    generate: impl FnOnce() -> String,
) -> String {
    specific
        .map(str::to_string)
        .or(existing)
        .unwrap_or_else(generate)
}

/// Layers `specific` (e.g. a mesh link's own `obfuscation`) over `global` (`mesh.yaml`'s top-level
/// default) field by field, then over `existing` (the previous patch's value), then generates
/// fresh values for whatever's still unset - see `obfuscation_gen`'s own doc comment for why that
/// only ever fills in the "original nine" fields.
fn resolve_obfuscation(
    specific: &Obfuscation,
    global: &Obfuscation,
    existing: Option<&Obfuscation>,
) -> Obfuscation {
    let existing = existing.cloned().unwrap_or_default();
    let generated = obfuscation_gen::generate();
    macro_rules! field {
        ($f:ident) => {
            specific
                .$f
                .clone()
                .or_else(|| global.$f.clone())
                .or_else(|| existing.$f.clone())
                .or_else(|| generated.$f.clone())
        };
    }
    Obfuscation {
        jc: field!(jc),
        jmin: field!(jmin),
        jmax: field!(jmax),
        s1: field!(s1),
        s2: field!(s2),
        s3: field!(s3),
        s4: field!(s4),
        h1: field!(h1),
        h2: field!(h2),
        h3: field!(h3),
        h4: field!(h4),
        i1: field!(i1),
        i2: field!(i2),
        i3: field!(i3),
        i4: field!(i4),
        i5: field!(i5),
        header_protection_key: field!(header_protection_key),
        content_padding_addition: field!(content_padding_addition),
        rekey_after_time: field!(rekey_after_time),
        rekey_timeout: field!(rekey_timeout),
        reject_after_time: field!(reject_after_time),
        keepalive_timeout: field!(keepalive_timeout),
        max_handshake_attempts: field!(max_handshake_attempts),
    }
}

pub fn resolve_secrets(mesh: &MeshConfig, existing: &impl ExistingState) -> ResolvedSecrets {
    let mut mesh_private_keys = HashMap::new();
    for node in &mesh.nodes {
        let key = resolve_string(
            node.mesh_private_key.as_deref(),
            existing.mesh_private_key(&node.name),
            keys::generate_private_key,
        );
        mesh_private_keys.insert(node.name.clone(), key);
    }

    let mut mesh_link_obfuscation = HashMap::new();
    for link in &mesh.mesh.links {
        // `plain` links (e.g. a RouterOS peer that can't speak AmneziaWG's extensions at all) skip
        // resolution entirely - `resolve_obfuscation` always fills every still-unset field from a
        // fresh random generation, which would silently turn a "no obfuscation" link back into an
        // obfuscated one.
        let resolved = if link.plain {
            Obfuscation::default()
        } else {
            resolve_obfuscation(
                &link.obfuscation,
                &mesh.obfuscation,
                existing.mesh_link_obfuscation(&link.pair).as_ref(),
            )
        };
        mesh_link_obfuscation.insert(link_key(&link.pair), resolved);
    }

    let mut roadwarrior_private_keys = HashMap::new();
    let mut roadwarrior_obfuscation = HashMap::new();
    for pool in &mesh.roadwarriors {
        let key = resolve_string(
            pool.private_key.as_deref(),
            existing.roadwarrior_private_key(&pool.name),
            keys::generate_private_key,
        );
        roadwarrior_private_keys.insert(pool.name.clone(), key);

        let obfuscation = resolve_obfuscation(
            &pool.obfuscation,
            &mesh.obfuscation,
            existing.roadwarrior_obfuscation(&pool.name).as_ref(),
        );
        roadwarrior_obfuscation.insert(pool.name.clone(), obfuscation);
    }

    ResolvedSecrets {
        mesh_private_keys,
        mesh_link_obfuscation,
        roadwarrior_private_keys,
        roadwarrior_obfuscation,
    }
}

fn parse_loopback_networks(mesh: &MeshConfig) -> Result<(Ipv4Addr, u8, Ipv6Addr, u8)> {
    let (v4_addr, v4_prefix) =
        common::netlink::rt::parse_cidr(&mesh.cluster.loopback_networks.ipv4)
            .context("cluster.loopback_networks.ipv4")?;
    let IpAddr::V4(v4) = v4_addr else {
        anyhow::bail!("cluster.loopback_networks.ipv4 must be an IPv4 CIDR");
    };
    let (v6_addr, v6_prefix) =
        common::netlink::rt::parse_cidr(&mesh.cluster.loopback_networks.ipv6)
            .context("cluster.loopback_networks.ipv6")?;
    let IpAddr::V6(v6) = v6_addr else {
        anyhow::bail!("cluster.loopback_networks.ipv6 must be an IPv6 CIDR");
    };
    Ok((v4, v4_prefix, v6, v6_prefix))
}

fn parse_tunnel_networks(mesh: &MeshConfig) -> Result<Option<(Ipv4Addr, u8, Ipv6Addr, u8)>> {
    let Some(tn) = &mesh.cluster.tunnel_networks else {
        return Ok(None);
    };
    let (v4_addr, v4_prefix) =
        common::netlink::rt::parse_cidr(&tn.ipv4).context("cluster.tunnel_networks.ipv4")?;
    let IpAddr::V4(v4) = v4_addr else {
        anyhow::bail!("cluster.tunnel_networks.ipv4 must be an IPv4 CIDR");
    };
    let (v6_addr, v6_prefix) =
        common::netlink::rt::parse_cidr(&tn.ipv6).context("cluster.tunnel_networks.ipv6")?;
    let IpAddr::V6(v6) = v6_addr else {
        anyhow::bail!("cluster.tunnel_networks.ipv6 must be an IPv6 CIDR");
    };
    Ok(Some((v4, v4_prefix, v6, v6_prefix)))
}

fn node_id_of(mesh: &MeshConfig, node_name: &str) -> Result<Ipv4Addr> {
    let node = mesh
        .nodes
        .iter()
        .find(|n| n.name == node_name)
        .with_context(|| format!("unknown node {node_name:?}"))?;
    node.node_id.parse().with_context(|| {
        format!("node {node_name:?}: node_id must be a valid IPv4-shaped identity")
    })
}

/// This node's (v4, v6) loopback identity, derived from its `node_id` OR'd onto
/// `cluster.loopback_networks` - see `addressing`'s module doc comment for the formula.
pub fn node_loopbacks(mesh: &MeshConfig, node_name: &str) -> Result<(Ipv4Addr, Ipv6Addr)> {
    let (v4_net, v4_prefix, v6_net, v6_prefix) = parse_loopback_networks(mesh)?;
    let node_id = node_id_of(mesh, node_name)?;
    Ok((
        addressing::ipv4_loopback(v4_net, v4_prefix, node_id),
        addressing::ipv6_loopback(v6_net, v6_prefix, node_id),
    ))
}

/// This node's (v4, v6) tunnel identity, same derivation as `node_loopbacks` but from
/// `cluster.tunnel_networks` - `None` when that section isn't configured (see
/// `ClusterConfig::tunnel_networks`'s doc comment).
pub fn node_tunnel_addresses(
    mesh: &MeshConfig,
    node_name: &str,
) -> Result<Option<(Ipv4Addr, Ipv6Addr)>> {
    let Some((v4_net, v4_prefix, v6_net, v6_prefix)) = parse_tunnel_networks(mesh)? else {
        return Ok(None);
    };
    let node_id = node_id_of(mesh, node_name)?;
    Ok(Some((
        addressing::ipv4_loopback(v4_net, v4_prefix, node_id),
        addressing::ipv6_loopback(v6_net, v6_prefix, node_id),
    )))
}

/// Full mesh minus self: every other node in `mesh.yaml`'s `nodes`, addressed by its IPv6
/// loopback - ported from `slipmesh-core::desired_state::bgp_peers_from`.
pub fn bgp_peers_for(mesh: &MeshConfig, node_name: &str) -> Result<Vec<BgpPeerEntry>> {
    mesh.nodes
        .iter()
        .filter(|n| n.name != node_name)
        .map(|n| {
            let (_, v6) = node_loopbacks(mesh, &n.name)?;
            Ok(BgpPeerEntry {
                name: n.name.clone(),
                address: v6.to_string(),
            })
        })
        .collect()
}

fn convert_bypass_source(e: &BypassSourceEntry) -> router::resolver::BypassSourceEntry {
    router::resolver::BypassSourceEntry {
        kind: e.kind.clone(),
        label: e.label.clone(),
        asns: e.asns.clone(),
        prefixes: e.prefixes.as_ref().map(|ps| {
            ps.iter()
                .map(|p| router::resolver::LabeledPrefix {
                    net: p.net.clone(),
                    label: p.label.clone(),
                })
                .collect()
        }),
        country: e.country.clone(),
        hostnames: e.hostnames.clone(),
    }
}

const DEFAULT_BYPASS_REFRESH_INTERVAL_SECS: u64 = 24 * 60 * 60;

/// This node's bypass rules: every `mesh.yaml` `bypass[]` entry where `node == node_name`,
/// converted to `router::config`'s shape. `None` if this node has no bypass entries at all (a
/// `router.yaml` with no `bypass` key is a normal, supported configuration).
pub fn bypass_for(mesh: &MeshConfig, node_name: &str) -> Option<BypassConfig> {
    let entries: Vec<_> = mesh.bypass.iter().filter(|b| b.node == node_name).collect();
    if entries.is_empty() {
        return None;
    }
    let mut include = Vec::new();
    let mut exclude = Vec::new();
    for entry in entries {
        include.extend(entry.include.iter().map(convert_bypass_source));
        exclude.extend(entry.exclude.iter().map(convert_bypass_source));
    }
    Some(BypassConfig {
        refresh_interval_secs: mesh
            .cluster
            .bypass_refresh_interval_secs
            .unwrap_or(DEFAULT_BYPASS_REFRESH_INTERVAL_SECS),
        include,
        exclude,
    })
}

/// Fixed generator-side convention, not a `mesh.yaml` field - every rendered node gets the same
/// two OSPF interface patterns (see the plan's "Пер-нодовое вычисление" section for why this isn't
/// user-configurable in this first version).
pub const OSPF_INTERFACES: [&str; 2] = ["mesh-*", "router-lo"];

/// This node's `direct_interfaces`: its own override if set, else `cluster.direct_interfaces` - an
/// override *replaces* the global default rather than extending it (a node opting out of the
/// fleet-wide CNI-bridge convention need not also list `"cni*"` itself).
fn direct_interfaces_for(mesh: &MeshConfig, node_name: &str) -> Result<Vec<String>> {
    let node = mesh
        .nodes
        .iter()
        .find(|n| n.name == node_name)
        .with_context(|| format!("unknown node {node_name:?}"))?;
    Ok(node
        .direct_interfaces
        .clone()
        .unwrap_or_else(|| mesh.cluster.direct_interfaces.clone()))
}

/// This cluster's `announce` routes - currently just the Kubernetes service CIDR, if configured
/// (see `ClusterConfig::service_subnet`'s doc comment for why it's static here rather than
/// live-discovered the way the old k8s-CRD `router` did it). Same on every node, matching
/// `direct_interfaces_for`'s reasoning for `cni*`: this isn't a per-node concern.
fn announce_for(mesh: &MeshConfig) -> Vec<AnnounceEntry> {
    mesh.cluster
        .service_subnet
        .as_ref()
        .map(|net| {
            vec![AnnounceEntry {
                net: net.clone(),
                label: Some("k8s-services".to_string()),
            }]
        })
        .unwrap_or_default()
}

pub fn render_router_config(mesh: &MeshConfig, node_name: &str) -> Result<RouterConfig> {
    let (v4, v6) = node_loopbacks(mesh, node_name)?;
    let mut direct_interfaces = direct_interfaces_for(mesh, node_name)?;
    // OSPF here is `ospf v3` (IPv6-only - see `bird.conf`'s `protocol ospf v3 mesh6`): it never sees,
    // let alone redistributes, an IPv4 address on a `mesh-*` interface at all (BIRD's own
    // `ospf_get_af` filters out addresses of the "wrong" family before stub-network advertisement
    // even runs). So the tunnel IPv4 address `mesh_interfaces_for` puts on every `mesh-*` interface
    // (see `node_tunnel_addresses`) would otherwise exist purely locally - reachable on no other
    // node, meaning replies masqueraded through it can never route back. `protocol direct` doesn't
    // have this family restriction (that's exactly how `router-lo`'s own IPv4 loopback already
    // reaches the rest of the mesh, via the `direct1` block `bird.conf` always renders) - so once
    // `tunnel_networks` is configured, `mesh-*` needs the same `protocol direct` treatment
    // `direct_interfaces` already gives `cni*`/other node-local interfaces.
    if node_tunnel_addresses(mesh, node_name)?.is_some()
        && !direct_interfaces.iter().any(|s| s == "mesh-*")
    {
        direct_interfaces.push("mesh-*".to_string());
    }
    Ok(RouterConfig {
        node: NodeIdentity {
            loopback_addresses: vec![format!("{v4}/32"), format!("{v6}/128")],
        },
        bgp_as: mesh.cluster.bgp_as,
        bgp_peers: bgp_peers_for(mesh, node_name)?,
        ospf_interfaces: OSPF_INTERFACES.iter().map(|s| s.to_string()).collect(),
        direct_interfaces,
        learn: vec![],
        announce: announce_for(mesh),
        bypass: bypass_for(mesh, node_name),
    })
}

/// This node's mesh-link interfaces: one full-tunnel `InterfaceEntry` per `mesh.links` entry it's
/// party to, named after the *peer's own node name* (`mesh-<peer_name>`) - purely a local, kernel-
/// side label, never exchanged over the wire (AmneziaWG/WireGuard identify peers by public key, not
/// interface name), so there's no interop reason to keep it opaque/hex like the old system's
/// `short_id`-based naming did. `awg::config::validate`'s `IFNAMSIZ` check (name.len() <= 15) still
/// applies - `mesh-` (5 bytes) plus a node name over 10 bytes fails generation loudly rather than
/// silently truncating; every current `mesh.yaml` node name fits comfortably.
fn mesh_interfaces_for(
    mesh: &MeshConfig,
    node_name: &str,
    resolved: &ResolvedSecrets,
) -> Result<Vec<InterfaceEntry>> {
    let (_, own_loopback) = node_loopbacks(mesh, node_name)?;
    let own_link_local = router::bird::link_local_from_loopback(own_loopback);
    let own_tunnel = node_tunnel_addresses(mesh, node_name)?;
    // When `tunnel_networks` is configured, its IPv6 half does double duty as the interface's sole
    // scope-link address, replacing the loopback-derived one - both are equally valid SCOPE_LINK
    // candidates for OSPFv3 (`ospf_ifa_notify3` only cares about scope, not which address), and
    // carrying two at once leaves it ambiguous which one BIRD actually sources Hello/LSA packets
    // from. Falls back to the loopback-derived link-local when `tunnel_networks` isn't set, so OSPF
    // keeps working unchanged for any `mesh.yaml` that hasn't opted into the new scheme.
    let (interface_link_local, tunnel_v4) = match own_tunnel {
        Some((v4, v6)) => (v6, Some(v4)),
        None => (own_link_local, None),
    };
    let own_private_key = resolved
        .mesh_private_keys
        .get(node_name)
        .with_context(|| format!("no resolved mesh private key for node {node_name:?}"))?;

    let mut out = Vec::new();
    for link in &mesh.mesh.links {
        let peer_name = if link.pair[0] == node_name {
            &link.pair[1]
        } else if link.pair[1] == node_name {
            &link.pair[0]
        } else {
            continue;
        };
        let peer_node = mesh
            .nodes
            .iter()
            .find(|n| &n.name == peer_name)
            .with_context(|| format!("unknown node {peer_name:?}"))?;
        let peer_private_key = resolved
            .mesh_private_keys
            .get(peer_name)
            .with_context(|| format!("no resolved mesh private key for node {peer_name:?}"))?;
        let obfuscation = resolved
            .mesh_link_obfuscation
            .get(&link_key(&link.pair))
            .cloned()
            .unwrap_or_default();

        let mut addresses = vec![format!("{interface_link_local}/64")];
        if let Some(tunnel_v4) = tunnel_v4 {
            addresses.push(format!("{tunnel_v4}/32"));
        }

        out.push(InterfaceEntry {
            name: format!("mesh-{peer_name}"),
            listen_port: link.port,
            addresses,
            private_key: own_private_key.clone(),
            obfuscation,
            handshake_stale_secs: None,
            peers: vec![PeerEntry {
                public_key: keys::public_key_from_private(peer_private_key)?,
                endpoint: peer_node
                    .endpoint
                    .as_ref()
                    .map(|host| format!("{host}:{}", link.port)),
                allowed_ips: None,
                advanced_security: false,
            }],
        });
    }
    Ok(out)
}

/// This node's roadwarriors-pool interfaces: one `InterfaceEntry` per pool that lists this node in
/// `node_hostnames`, tracked (`allowed_ips` set) peers built straight from `clients`.
fn roadwarrior_interfaces_for(
    mesh: &MeshConfig,
    node_name: &str,
    resolved: &ResolvedSecrets,
) -> Vec<InterfaceEntry> {
    mesh.roadwarriors
        .iter()
        .filter(|pool| pool.node_hostnames.iter().any(|h| h == node_name))
        .map(|pool| {
            let mut addresses = vec![pool.address.clone()];
            addresses.extend(pool.address6.clone());
            InterfaceEntry {
                name: pool.iface.clone(),
                listen_port: pool.listen_port,
                addresses,
                private_key: resolved
                    .roadwarrior_private_keys
                    .get(&pool.name)
                    .cloned()
                    .unwrap_or_default(),
                obfuscation: resolved
                    .roadwarrior_obfuscation
                    .get(&pool.name)
                    .cloned()
                    .unwrap_or_default(),
                handshake_stale_secs: pool.handshake_stale_secs,
                peers: pool
                    .clients
                    .iter()
                    .map(|c| PeerEntry {
                        public_key: c.public_key.clone(),
                        endpoint: None,
                        allowed_ips: Some(c.allowed_ips.clone()),
                        advanced_security: c.advanced_security,
                    })
                    .collect(),
            }
        })
        .collect()
}

pub fn render_awg_config(
    mesh: &MeshConfig,
    node_name: &str,
    resolved: &ResolvedSecrets,
) -> Result<AwgConfig> {
    let mut interfaces = mesh_interfaces_for(mesh, node_name, resolved)?;
    interfaces.extend(roadwarrior_interfaces_for(mesh, node_name, resolved));
    Ok(AwgConfig { interfaces })
}

/// The single global `nftables.ruleset`, verbatim, for every node - `None` if `mesh.yaml` has no
/// `nftables` section at all (this node simply gets no rendered nftables segment).
pub fn render_nftables_config(mesh: &MeshConfig) -> Option<NftablesConfig> {
    mesh.nftables.as_ref().map(|n| NftablesConfig {
        ruleset: n.ruleset.clone(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_string_prefers_specific() {
        let s = resolve_string(Some("explicit"), Some("existing".to_string()), || {
            "generated".to_string()
        });
        assert_eq!(s, "explicit");
    }

    #[test]
    fn resolve_string_falls_back_to_existing() {
        let s = resolve_string(None, Some("existing".to_string()), || {
            "generated".to_string()
        });
        assert_eq!(s, "existing");
    }

    #[test]
    fn resolve_string_falls_back_to_generated() {
        let s = resolve_string(None, None, || "generated".to_string());
        assert_eq!(s, "generated");
    }

    #[test]
    fn resolve_obfuscation_prefers_specific_field_over_global() {
        let specific = Obfuscation {
            jc: Some(9),
            ..Obfuscation::default()
        };
        let global = Obfuscation {
            jc: Some(1),
            jmin: Some(10),
            ..Obfuscation::default()
        };
        let resolved = resolve_obfuscation(&specific, &global, None);
        assert_eq!(resolved.jc, Some(9));
        assert_eq!(resolved.jmin, Some(10));
    }

    #[test]
    fn resolve_obfuscation_prefers_existing_over_generating_fresh() {
        let existing = Obfuscation {
            h1: Some(42),
            ..Obfuscation::default()
        };
        let resolved = resolve_obfuscation(
            &Obfuscation::default(),
            &Obfuscation::default(),
            Some(&existing),
        );
        assert_eq!(resolved.h1, Some(42));
    }

    #[test]
    fn resolve_obfuscation_generates_when_nothing_else_is_set() {
        let resolved = resolve_obfuscation(&Obfuscation::default(), &Obfuscation::default(), None);
        assert!(resolved.jc.is_some());
        assert!(resolved.h1.is_some());
    }

    #[test]
    fn resolve_obfuscation_never_generates_header_protection_key() {
        let resolved = resolve_obfuscation(&Obfuscation::default(), &Obfuscation::default(), None);
        assert_eq!(resolved.header_protection_key, None);
    }

    struct FakeExisting {
        mesh_keys: HashMap<String, String>,
    }

    impl ExistingState for FakeExisting {
        fn mesh_private_key(&self, node_name: &str) -> Option<String> {
            self.mesh_keys.get(node_name).cloned()
        }
        fn mesh_link_obfuscation(&self, _pair: &[String; 2]) -> Option<Obfuscation> {
            None
        }
        fn roadwarrior_private_key(&self, _pool_name: &str) -> Option<String> {
            None
        }
        fn roadwarrior_obfuscation(&self, _pool_name: &str) -> Option<Obfuscation> {
            None
        }
    }

    fn minimal_mesh_yaml() -> &'static str {
        r#"
cluster:
  bgp_as: 64512
  loopback_networks: {ipv4: "10.62.0.0/16", ipv6: "fd00:62::/32"}
nodes:
  - {name: a, node_id: "10.62.0.1"}
  - {name: b, node_id: "10.62.0.2"}
mesh:
  links:
    - {pair: [a, b], port: 51820}
"#
    }

    #[test]
    fn resolve_secrets_shares_the_same_generated_key_for_a_node_across_calls() {
        let mesh: MeshConfig = serde_yaml::from_str(minimal_mesh_yaml()).unwrap();
        let existing = FakeExisting {
            mesh_keys: HashMap::new(),
        };
        let resolved = resolve_secrets(&mesh, &existing);
        assert!(resolved.mesh_private_keys.contains_key("a"));
        assert!(resolved.mesh_private_keys.contains_key("b"));
        assert_ne!(
            resolved.mesh_private_keys["a"],
            resolved.mesh_private_keys["b"]
        );
    }

    #[test]
    fn resolve_secrets_uses_explicit_node_private_key() {
        let mut mesh: MeshConfig = serde_yaml::from_str(minimal_mesh_yaml()).unwrap();
        mesh.nodes[0].mesh_private_key = Some("explicit-key".to_string());
        let existing = FakeExisting {
            mesh_keys: HashMap::new(),
        };
        let resolved = resolve_secrets(&mesh, &existing);
        assert_eq!(resolved.mesh_private_keys["a"], "explicit-key");
    }

    #[test]
    fn resolve_secrets_shares_one_obfuscation_value_across_both_ends_of_a_link() {
        let mesh: MeshConfig = serde_yaml::from_str(minimal_mesh_yaml()).unwrap();
        let existing = FakeExisting {
            mesh_keys: HashMap::new(),
        };
        let resolved = resolve_secrets(&mesh, &existing);
        // Only one entry per link, keyed order-independently - not one per node.
        assert_eq!(resolved.mesh_link_obfuscation.len(), 1);
    }

    #[test]
    fn resolve_secrets_plain_link_skips_obfuscation_generation_entirely() {
        let mut mesh: MeshConfig = serde_yaml::from_str(minimal_mesh_yaml()).unwrap();
        mesh.mesh.links[0].plain = true;
        let existing = FakeExisting {
            mesh_keys: HashMap::new(),
        };
        let resolved = resolve_secrets(&mesh, &existing);
        let obfuscation = &resolved.mesh_link_obfuscation[&link_key(&mesh.mesh.links[0].pair)];
        assert_eq!(obfuscation, &Obfuscation::default());
    }

    #[test]
    fn resolve_secrets_non_plain_link_still_generates_obfuscation() {
        let mesh: MeshConfig = serde_yaml::from_str(minimal_mesh_yaml()).unwrap();
        let existing = FakeExisting {
            mesh_keys: HashMap::new(),
        };
        let resolved = resolve_secrets(&mesh, &existing);
        let obfuscation = &resolved.mesh_link_obfuscation[&link_key(&mesh.mesh.links[0].pair)];
        assert_ne!(obfuscation, &Obfuscation::default());
    }

    fn three_node_mesh_yaml() -> &'static str {
        r#"
cluster:
  bgp_as: 64512
  loopback_networks: {ipv4: "10.62.0.0/16", ipv6: "fd00:62::/32"}
  bypass_refresh_interval_secs: 3600
nodes:
  - {name: a, node_id: "10.62.0.1"}
  - {name: b, node_id: "10.62.0.2"}
  - {name: c, node_id: "10.62.0.3"}
mesh:
  links:
    - {pair: [a, b], port: 51820}
bypass:
  - node: a
    include:
      - kind: literal
        prefixes: [{net: "10.0.0.0/8"}]
"#
    }

    #[test]
    fn node_loopbacks_ors_node_id_onto_cluster_networks() {
        let mesh: MeshConfig = serde_yaml::from_str(three_node_mesh_yaml()).unwrap();
        let (v4, v6) = node_loopbacks(&mesh, "a").unwrap();
        assert_eq!(v4.to_string(), "10.62.0.1");
        // node_id "10.62.0.1" is the full 32-bit value (0x0a3e0001), not just its last octet, so
        // it ORs into the v6 host bits as "a3e:1" - matches `ipv6_loopback`'s ported formula.
        assert_eq!(v6.to_string(), "fd00:62::a3e:1");
    }

    #[test]
    fn node_loopbacks_rejects_unknown_node() {
        let mesh: MeshConfig = serde_yaml::from_str(three_node_mesh_yaml()).unwrap();
        assert!(node_loopbacks(&mesh, "nonexistent").is_err());
    }

    #[test]
    fn bgp_peers_for_excludes_self_and_covers_full_mesh() {
        let mesh: MeshConfig = serde_yaml::from_str(three_node_mesh_yaml()).unwrap();
        let peers = bgp_peers_for(&mesh, "a").unwrap();
        let names: Vec<&str> = peers.iter().map(|p| p.name.as_str()).collect();
        assert_eq!(names.len(), 2);
        assert!(names.contains(&"b"));
        assert!(names.contains(&"c"));
        assert!(!names.contains(&"a"));
    }

    #[test]
    fn bgp_peers_for_addresses_are_ipv6_loopbacks() {
        let mesh: MeshConfig = serde_yaml::from_str(three_node_mesh_yaml()).unwrap();
        let peers = bgp_peers_for(&mesh, "a").unwrap();
        let b = peers.iter().find(|p| p.name == "b").unwrap();
        assert_eq!(b.address, "fd00:62::a3e:2");
    }

    #[test]
    fn bypass_for_filters_by_node() {
        let mesh: MeshConfig = serde_yaml::from_str(three_node_mesh_yaml()).unwrap();
        assert!(bypass_for(&mesh, "a").is_some());
        assert!(bypass_for(&mesh, "b").is_none());
    }

    #[test]
    fn bypass_for_converts_literal_prefixes() {
        let mesh: MeshConfig = serde_yaml::from_str(three_node_mesh_yaml()).unwrap();
        let bypass = bypass_for(&mesh, "a").unwrap();
        assert_eq!(bypass.include.len(), 1);
        assert_eq!(bypass.include[0].kind, "literal");
        assert_eq!(
            bypass.include[0].prefixes.as_ref().unwrap()[0].net,
            "10.0.0.0/8"
        );
        assert_eq!(bypass.refresh_interval_secs, 3600);
    }

    #[test]
    fn render_router_config_is_valid() {
        let mesh: MeshConfig = serde_yaml::from_str(three_node_mesh_yaml()).unwrap();
        let cfg = render_router_config(&mesh, "a").unwrap();
        router::config::validate(&cfg).unwrap();
        assert_eq!(cfg.bgp_as, 64512);
        assert_eq!(
            cfg.ospf_interfaces,
            vec!["mesh-*".to_string(), "router-lo".to_string()]
        );
        assert!(cfg.bypass.is_some());
    }

    #[test]
    fn render_router_config_direct_interfaces_defaults_to_cni_glob() {
        let mesh: MeshConfig = serde_yaml::from_str(three_node_mesh_yaml()).unwrap();
        let cfg_a = render_router_config(&mesh, "a").unwrap();
        let cfg_b = render_router_config(&mesh, "b").unwrap();
        // Same value on every node with no per-node override - the global default.
        assert_eq!(cfg_a.direct_interfaces, vec!["cni*".to_string()]);
        assert_eq!(cfg_b.direct_interfaces, vec!["cni*".to_string()]);
    }

    #[test]
    fn render_router_config_omits_mesh_glob_from_direct_interfaces_when_tunnel_networks_not_configured()
     {
        let mesh: MeshConfig = serde_yaml::from_str(three_node_mesh_yaml()).unwrap();
        let cfg = render_router_config(&mesh, "a").unwrap();
        assert!(!cfg.direct_interfaces.iter().any(|s| s == "mesh-*"));
    }

    #[test]
    fn render_router_config_uses_explicit_cluster_direct_interfaces() {
        let mut mesh: MeshConfig = serde_yaml::from_str(three_node_mesh_yaml()).unwrap();
        mesh.cluster.direct_interfaces = vec!["cni0".to_string(), "extra0".to_string()];
        let cfg = render_router_config(&mesh, "a").unwrap();
        assert_eq!(
            cfg.direct_interfaces,
            vec!["cni0".to_string(), "extra0".to_string()]
        );
    }

    #[test]
    fn render_router_config_per_node_direct_interfaces_overrides_not_merges_the_global_default() {
        let mut mesh: MeshConfig = serde_yaml::from_str(three_node_mesh_yaml()).unwrap();
        mesh.nodes[0].direct_interfaces = Some(vec!["home".to_string()]);
        let cfg_a = render_router_config(&mesh, "a").unwrap();
        let cfg_b = render_router_config(&mesh, "b").unwrap();
        // Overridden node gets exactly its own list - "cni*" is not also present.
        assert_eq!(cfg_a.direct_interfaces, vec!["home".to_string()]);
        // Untouched node still gets the global default.
        assert_eq!(cfg_b.direct_interfaces, vec!["cni*".to_string()]);
    }

    #[test]
    fn render_router_config_announce_is_empty_by_default() {
        let mesh: MeshConfig = serde_yaml::from_str(three_node_mesh_yaml()).unwrap();
        let cfg = render_router_config(&mesh, "a").unwrap();
        assert!(cfg.announce.is_empty());
    }

    #[test]
    fn render_router_config_announces_the_configured_service_subnet_on_every_node() {
        let mut mesh: MeshConfig = serde_yaml::from_str(three_node_mesh_yaml()).unwrap();
        mesh.cluster.service_subnet = Some("10.60.0.0/16".to_string());
        let cfg_a = render_router_config(&mesh, "a").unwrap();
        let cfg_b = render_router_config(&mesh, "b").unwrap();
        for cfg in [&cfg_a, &cfg_b] {
            assert_eq!(cfg.announce.len(), 1);
            assert_eq!(cfg.announce[0].net, "10.60.0.0/16");
            assert_eq!(cfg.announce[0].label.as_deref(), Some("k8s-services"));
        }
    }

    #[test]
    fn render_router_config_omits_bypass_for_a_node_with_none() {
        let mesh: MeshConfig = serde_yaml::from_str(three_node_mesh_yaml()).unwrap();
        let cfg = render_router_config(&mesh, "b").unwrap();
        assert!(cfg.bypass.is_none());
    }

    fn mesh_and_roadwarriors_yaml() -> &'static str {
        r#"
cluster:
  bgp_as: 64512
  loopback_networks: {ipv4: "10.62.0.0/16", ipv6: "fd00:62::/32"}
nodes:
  - {name: a, node_id: "10.62.0.1"}
  - {name: b, node_id: "10.62.0.2", endpoint: "b.example.com"}
  - {name: c, node_id: "10.62.0.3"}
mesh:
  links:
    - {pair: [a, b], port: 51820}
roadwarriors:
  - name: eu
    node_hostnames: [a]
    iface: rw-eu
    address: "10.99.0.1/24"
    listen_port: 51900
    clients:
      - name: alice
        public_key: "client-pubkey"
        allowed_ips: ["10.99.0.5/32"]
nftables:
  ruleset: "table inet talos_filter {}"
"#
    }

    fn resolved_for(mesh: &MeshConfig) -> ResolvedSecrets {
        let existing = FakeExisting {
            mesh_keys: HashMap::new(),
        };
        resolve_secrets(mesh, &existing)
    }

    #[test]
    fn mesh_interfaces_for_names_the_interface_after_the_peers_node_name() {
        let mesh: MeshConfig = serde_yaml::from_str(mesh_and_roadwarriors_yaml()).unwrap();
        let resolved = resolved_for(&mesh);
        let ifaces = mesh_interfaces_for(&mesh, "a", &resolved).unwrap();
        assert_eq!(ifaces.len(), 1);
        assert_eq!(ifaces[0].name, "mesh-b");
        assert_eq!(ifaces[0].listen_port, 51820);
    }

    #[test]
    fn mesh_interfaces_for_is_full_tunnel_with_no_allowed_ips() {
        let mesh: MeshConfig = serde_yaml::from_str(mesh_and_roadwarriors_yaml()).unwrap();
        let resolved = resolved_for(&mesh);
        let ifaces = mesh_interfaces_for(&mesh, "a", &resolved).unwrap();
        assert_eq!(ifaces[0].peers[0].allowed_ips, None);
    }

    #[test]
    fn mesh_interfaces_for_builds_endpoint_from_node_host_and_link_port() {
        let mesh: MeshConfig = serde_yaml::from_str(mesh_and_roadwarriors_yaml()).unwrap();
        let resolved = resolved_for(&mesh);
        // a's interface peers toward b, which has an endpoint -> host:port using this link's port.
        let a_ifaces = mesh_interfaces_for(&mesh, "a", &resolved).unwrap();
        assert_eq!(
            a_ifaces[0].peers[0].endpoint,
            Some("b.example.com:51820".to_string())
        );
        // b's interface peers toward a, which has no endpoint at all.
        let b_ifaces = mesh_interfaces_for(&mesh, "b", &resolved).unwrap();
        assert_eq!(b_ifaces[0].peers[0].endpoint, None);
    }

    #[test]
    fn mesh_interfaces_for_peer_public_key_matches_the_peers_resolved_private_key() {
        let mesh: MeshConfig = serde_yaml::from_str(mesh_and_roadwarriors_yaml()).unwrap();
        let resolved = resolved_for(&mesh);
        let ifaces = mesh_interfaces_for(&mesh, "a", &resolved).unwrap();
        let expected_public =
            keys::public_key_from_private(&resolved.mesh_private_keys["b"]).unwrap();
        assert_eq!(ifaces[0].peers[0].public_key, expected_public);
    }

    fn mesh_and_roadwarriors_with_tunnel_networks_yaml() -> &'static str {
        r#"
cluster:
  bgp_as: 64512
  loopback_networks: {ipv4: "10.62.0.0/16", ipv6: "fd00:62::/32"}
  tunnel_networks: {ipv4: "10.62.1.0/24", ipv6: "fd00:63::/120"}
nodes:
  - {name: a, node_id: "10.62.0.1"}
  - {name: b, node_id: "10.62.0.2", endpoint: "b.example.com"}
mesh:
  links:
    - {pair: [a, b], port: 51820}
"#
    }

    #[test]
    fn node_tunnel_addresses_is_none_when_not_configured() {
        let mesh: MeshConfig = serde_yaml::from_str(mesh_and_roadwarriors_yaml()).unwrap();
        assert!(node_tunnel_addresses(&mesh, "a").unwrap().is_none());
    }

    #[test]
    fn node_tunnel_addresses_ors_node_id_onto_cluster_networks() {
        let mesh: MeshConfig =
            serde_yaml::from_str(mesh_and_roadwarriors_with_tunnel_networks_yaml()).unwrap();
        let (v4, v6) = node_tunnel_addresses(&mesh, "a").unwrap().unwrap();
        assert_eq!(v4.to_string(), "10.62.1.1");
        assert_eq!(v6.to_string(), "fd00:63::1");
    }

    #[test]
    fn mesh_interfaces_for_uses_tunnel_ipv6_as_the_sole_link_local_when_configured() {
        let mesh: MeshConfig =
            serde_yaml::from_str(mesh_and_roadwarriors_with_tunnel_networks_yaml()).unwrap();
        let resolved = resolved_for(&mesh);
        let ifaces = mesh_interfaces_for(&mesh, "a", &resolved).unwrap();
        // The tunnel IPv6 address (also link-local) replaces the loopback-derived link-local
        // entirely - never both at once on the same interface.
        assert_eq!(
            ifaces[0].addresses,
            vec!["fd00:63::1/64".to_string(), "10.62.1.1/32".to_string()]
        );
    }

    #[test]
    fn mesh_interfaces_for_uses_the_loopback_derived_link_local_when_not_configured() {
        let mesh: MeshConfig = serde_yaml::from_str(mesh_and_roadwarriors_yaml()).unwrap();
        let resolved = resolved_for(&mesh);
        let ifaces = mesh_interfaces_for(&mesh, "a", &resolved).unwrap();
        assert_eq!(ifaces[0].addresses, vec!["fe80::a3e:1/64".to_string()]);
    }

    #[test]
    fn render_router_config_adds_mesh_glob_to_direct_interfaces_when_tunnel_networks_configured() {
        // Without this, the tunnel IPv4 address `mesh_interfaces_for` assigns is never
        // redistributed anywhere - OSPF here is IPv6-only (`ospf v3`) and silently ignores IPv4
        // addresses entirely, so `protocol direct` on `mesh-*` is the only thing that can get it
        // into BGP, same as `direct1` already does for `router-lo`'s own IPv4 loopback.
        let mesh: MeshConfig =
            serde_yaml::from_str(mesh_and_roadwarriors_with_tunnel_networks_yaml()).unwrap();
        let cfg = render_router_config(&mesh, "a").unwrap();
        assert!(cfg.direct_interfaces.iter().any(|s| s == "mesh-*"));
    }

    #[test]
    fn render_router_config_does_not_duplicate_mesh_glob_if_already_present() {
        let mut mesh: MeshConfig =
            serde_yaml::from_str(mesh_and_roadwarriors_with_tunnel_networks_yaml()).unwrap();
        mesh.cluster.direct_interfaces = vec!["mesh-*".to_string()];
        let cfg = render_router_config(&mesh, "a").unwrap();
        assert_eq!(
            cfg.direct_interfaces
                .iter()
                .filter(|s| *s == "mesh-*")
                .count(),
            1
        );
    }

    #[test]
    fn mesh_interfaces_for_a_node_with_no_links_is_empty() {
        let mesh: MeshConfig = serde_yaml::from_str(mesh_and_roadwarriors_yaml()).unwrap();
        let resolved = resolved_for(&mesh);
        assert!(
            mesh_interfaces_for(&mesh, "c", &resolved)
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn roadwarrior_interfaces_for_builds_a_tracked_peer_per_client() {
        let mesh: MeshConfig = serde_yaml::from_str(mesh_and_roadwarriors_yaml()).unwrap();
        let resolved = resolved_for(&mesh);
        let ifaces = roadwarrior_interfaces_for(&mesh, "a", &resolved);
        assert_eq!(ifaces.len(), 1);
        assert_eq!(ifaces[0].name, "rw-eu");
        assert_eq!(ifaces[0].listen_port, 51900);
        assert_eq!(ifaces[0].peers[0].public_key, "client-pubkey");
        assert_eq!(
            ifaces[0].peers[0].allowed_ips,
            Some(vec!["10.99.0.5/32".to_string()])
        );
    }

    #[test]
    fn roadwarrior_interfaces_for_a_node_not_in_node_hostnames_is_empty() {
        let mesh: MeshConfig = serde_yaml::from_str(mesh_and_roadwarriors_yaml()).unwrap();
        let resolved = resolved_for(&mesh);
        assert!(roadwarrior_interfaces_for(&mesh, "c", &resolved).is_empty());
    }

    #[test]
    fn render_awg_config_combines_mesh_and_roadwarrior_interfaces_and_is_valid() {
        let mesh: MeshConfig = serde_yaml::from_str(mesh_and_roadwarriors_yaml()).unwrap();
        let resolved = resolved_for(&mesh);
        let cfg = render_awg_config(&mesh, "a", &resolved).unwrap();
        awg::config::validate(&cfg).unwrap();
        assert_eq!(cfg.interfaces.len(), 2);
    }

    #[test]
    fn render_nftables_config_carries_the_global_ruleset_verbatim() {
        let mesh: MeshConfig = serde_yaml::from_str(mesh_and_roadwarriors_yaml()).unwrap();
        let cfg = render_nftables_config(&mesh).unwrap();
        assert_eq!(cfg.ruleset, "table inet talos_filter {}");
    }

    #[test]
    fn render_nftables_config_is_none_when_mesh_yaml_has_no_nftables_section() {
        let mesh: MeshConfig = serde_yaml::from_str(three_node_mesh_yaml()).unwrap();
        assert!(render_nftables_config(&mesh).is_none());
    }
}
