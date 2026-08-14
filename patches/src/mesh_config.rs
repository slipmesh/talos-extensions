//! Schema for `mesh.yaml` - the single source of truth this whole generator renders per-node
//! `awg`/`router`/`nftables` `ExtensionServiceConfig` content from. Deliberately one file for all
//! four concerns (mesh links, roadwarriors, BGP/OSPF, nftables) rather than one file per daemon -
//! they already share the same node/topology facts (`nodes`, `cluster.loopback_networks`), and
//! keeping them apart would just mean re-stating those facts in multiple places.
//!
//! Ported from (not identical to) the older Kubernetes-CRD system's schema
//! (`slipmesh-core::mesh_types`/`node_config_types`/`router_types`/`cluster_config_types`,
//! `IaC/k8s/main/network/.values.yaml`) - see `render.rs`'s module doc comment for exactly what
//! changed and why.

use common::Obfuscation;
use serde::Deserialize;
use std::collections::HashSet;
use std::net::Ipv4Addr;

#[derive(Deserialize, Debug, Default, PartialEq)]
pub struct MeshConfig {
    pub cluster: ClusterConfig,
    #[serde(default)]
    pub obfuscation: Obfuscation,
    #[serde(default)]
    pub nodes: Vec<NodeEntry>,
    #[serde(default)]
    pub mesh: MeshTopology,
    #[serde(default)]
    pub roadwarriors: Vec<RoadwarriorPool>,
    #[serde(default)]
    pub bypass: Vec<BypassEntry>,
    #[serde(default)]
    pub nftables: Option<NftablesTopology>,
}

#[derive(Deserialize, Debug, Default, PartialEq)]
pub struct ClusterConfig {
    #[serde(default)]
    pub bgp_as: u32,
    #[serde(default)]
    pub loopback_networks: LoopbackNetworks,
    #[serde(default)]
    pub bypass_refresh_interval_secs: Option<u64>,
    /// Extra interfaces every node's `router.yaml` should treat as `protocol direct` sources (see
    /// `router::config::RouterConfig::direct_interfaces`'s own doc comment) - global, not per-node:
    /// the mechanism this exists for (`slipmesh/cni-config`'s pod-bridge) is the same interface
    /// naming on every node by construction, not something that varies node to node. Harmless to
    /// include on a node that never runs `cni-config` - `protocol direct` is inert until a matching
    /// interface actually appears. Defaults to `cni*` (a glob, not the exact `cni0` - matches
    /// whatever the CNI bridge plugin actually names it without needing to hardcode the number)
    /// rather than empty, so this works out of the box without `mesh.yaml` having to know about it.
    #[serde(default = "default_direct_interfaces")]
    pub direct_interfaces: Vec<String>,
    /// Kubernetes' ClusterIP range (Talos's own `cluster.network.serviceSubnets`, stated here too
    /// since `router.yaml` has no live Kubernetes API access to discover it - see this crate's own
    /// `AGENTS.md`/workspace principle). Ported from the old k8s-CRD system's `router`, which read
    /// this live from a `ServiceCIDR` object and re-announced it over iBGP as `AnnounceRoute{label:
    /// "k8s-services"}` (`slipmesh/operators/router/src/main.rs`) - here it's a static value instead
    /// (unlike podCIDR, the service range is fixed at cluster-bootstrap time, not dynamically
    /// allocated per node, so there's no live-discovery requirement to begin with). `None` by
    /// default (unlike `direct_interfaces`'s `cni*`) - there's no universally-sensible default
    /// service CIDR the way there's a de-facto-standard CNI bridge naming convention.
    #[serde(default)]
    pub service_subnet: Option<String>,
    /// A second `node_id`-derived address pair, distinct from `loopback_networks`, hung on every
    /// `mesh-*`/awg tunnel interface (not just `router-lo`). The IPv4 half is the confirmed fix this
    /// exists for: `mesh-*` interfaces otherwise carry no IPv4 address at all, so NAT/MASQUERADE has
    /// nothing valid to pick as a source when service-subnet traffic egresses via one. The IPv6 half
    /// is deliberately ALSO link-local-scoped (`mesh.yaml`'s value lives inside `fe80::/10`, same as
    /// the interface's existing OSPFv3-driving link-local) rather than a globally-scoped address -
    /// there's no live IPv6 masquerade need in this cluster (`service_subnet` is IPv4-only). Being
    /// link-local lets it *replace* rather than duplicate the loopback-derived link-local `render.rs`
    /// would otherwise put on every `mesh-*` interface (see `mesh_interfaces_for`) - one scope-link
    /// address doing double duty (tunnel identity + OSPFv3 Hello/LSA source) instead of two competing
    /// ones on the same interface, which would leave it ambiguous which one BIRD actually uses.
    /// `None` (unlike `loopback_networks`, which is always present) preserves today's link-local-only
    /// behavior for any `mesh.yaml` that hasn't opted in yet.
    #[serde(default)]
    pub tunnel_networks: Option<TunnelNetworks>,
}

fn default_direct_interfaces() -> Vec<String> {
    vec!["cni*".to_string()]
}

#[derive(Deserialize, Debug, Default, PartialEq)]
pub struct LoopbackNetworks {
    #[serde(default)]
    pub ipv4: String,
    #[serde(default)]
    pub ipv6: String,
}

/// Same shape as `LoopbackNetworks` - see `ClusterConfig::tunnel_networks`'s doc comment for what
/// this is for.
#[derive(Deserialize, Debug, Default, PartialEq)]
pub struct TunnelNetworks {
    #[serde(default)]
    pub ipv4: String,
    #[serde(default)]
    pub ipv6: String,
}

#[derive(Deserialize, Debug, PartialEq)]
pub struct NodeEntry {
    pub name: String,
    /// Host-bits identity, same scheme the old CRD system used (`nodeId`) - an IPv4-shaped value
    /// ORed onto `cluster.loopback_networks.{ipv4,ipv6}` to derive this node's own loopback
    /// addresses. Not a real routable IPv4 address on its own.
    pub node_id: String,
    /// Publicly reachable hostname or IP, no port - `render.rs` appends the specific mesh link's
    /// own `port` per interface, since one node can have several mesh links each listening on a
    /// different port (a fixed `host:port` here couldn't represent more than one of them). Omitted
    /// for a NAT'd node (the old schema's "hq" node is the precedent): such a node can still be
    /// the *desired* end of a mesh link, it just never appears as `endpoint` on the peer's side.
    #[serde(default)]
    pub endpoint: Option<String>,
    /// This node's mesh identity private key, shared across all of its `mesh.links` interfaces
    /// (one identity per node, not per link - same as the old schema's per-node `NodeConfig`
    /// public key). See `render.rs`'s idempotency handling for when this is left unset.
    #[serde(default)]
    pub mesh_private_key: Option<String>,
    /// Overrides (replaces, does not merge with) `cluster.direct_interfaces` for this node only -
    /// for a node whose physically-connected interfaces don't follow the fleet-wide CNI-bridge
    /// convention the global default is for (e.g. a non-Talos mesh peer with its own LAN-facing
    /// interface name). `None` means "use the global default", not "announce nothing".
    #[serde(default)]
    pub direct_interfaces: Option<Vec<String>>,
}

#[derive(Deserialize, Debug, Default, PartialEq)]
pub struct MeshTopology {
    #[serde(default)]
    pub links: Vec<MeshLink>,
}

#[derive(Deserialize, Debug, PartialEq)]
pub struct MeshLink {
    /// Exactly two node names, referencing `nodes[].name`. Order doesn't carry addressing
    /// significance (same as the old schema) - only used to derive a deterministic interface name/
    /// link-local address, see `render.rs`.
    pub pair: [String; 2],
    /// Shared UDP port, both ends - always explicit, never generated (see plan's "Идемпотентность"
    /// section: ports are an operator decision, not state this tool invents).
    pub port: u16,
    #[serde(default)]
    pub obfuscation: Obfuscation,
    /// This link is plain WireGuard, no AmneziaWG obfuscation at all - for a peer that can't do
    /// AmneziaWG's extensions (e.g. RouterOS, which only speaks stock WireGuard). Skips obfuscation
    /// generation/resolution entirely rather than resolving to an all-fields-`None` `Obfuscation`
    /// that then gets silently overwritten by a *future* run's random generation the moment nothing
    /// else fills a field in - `render.rs`'s `resolve_secrets` checks this before even calling
    /// `resolve_obfuscation`, so a plain link never round-trips through generation at all.
    #[serde(default)]
    pub plain: bool,
}

#[derive(Deserialize, Debug, PartialEq)]
pub struct RoadwarriorPool {
    pub name: String,
    /// Which nodes terminate connections for this pool - each gets its own `InterfaceEntry` for
    /// it, see `render.rs`.
    pub node_hostnames: Vec<String>,
    /// AWG interface name this pool renders as - <=15 bytes, checked by `awg::config::validate`
    /// on the rendered output, not re-checked here.
    pub iface: String,
    pub address: String,
    #[serde(default)]
    pub address6: Option<String>,
    pub listen_port: u16,
    #[serde(default)]
    pub handshake_stale_secs: Option<u64>,
    /// Shared identity across every node in `node_hostnames` - same precedent as the old schema's
    /// single roadwarriors device key, not per-node.
    #[serde(default)]
    pub private_key: Option<String>,
    #[serde(default)]
    pub obfuscation: Obfuscation,
    #[serde(default)]
    pub clients: Vec<RoadwarriorClient>,
}

#[derive(Deserialize, Debug, PartialEq)]
pub struct RoadwarriorClient {
    pub name: String,
    pub public_key: String,
    #[serde(default)]
    pub allowed_ips: Vec<String>,
    #[serde(default)]
    pub advanced_security: bool,
}

#[derive(Deserialize, Debug, PartialEq)]
pub struct BypassEntry {
    /// References `nodes[].name` - bypass config is per-node, same as the old schema's
    /// `BypassSource.spec.node`.
    pub node: String,
    #[serde(default)]
    pub include: Vec<BypassSourceEntry>,
    #[serde(default)]
    pub exclude: Vec<BypassSourceEntry>,
}

/// Same shape as `router::config::BypassSourceEntry` - re-declared here (not reused directly)
/// because `mesh.yaml`'s `bypass[]` is a flat list keyed by `node`, not yet split per-node the way
/// `router::config::BypassConfig` expects; `render.rs` does that split, constructing the real
/// `router::config` type from these fields.
#[derive(Deserialize, Debug, Clone, PartialEq)]
pub struct BypassSourceEntry {
    pub kind: String,
    #[serde(default)]
    pub label: Option<String>,
    #[serde(default)]
    pub asns: Option<Vec<String>>,
    #[serde(default)]
    pub prefixes: Option<Vec<LabeledPrefix>>,
    #[serde(default)]
    pub country: Option<String>,
    #[serde(default)]
    pub hostnames: Option<Vec<String>>,
}

#[derive(Deserialize, Debug, Clone, PartialEq)]
pub struct LabeledPrefix {
    pub net: String,
    #[serde(default)]
    pub label: Option<String>,
}

#[derive(Deserialize, Debug, PartialEq)]
pub struct NftablesTopology {
    /// Same ruleset, verbatim, for every node in `nodes` - see this struct's doc comment in the
    /// plan for why there's no per-node override in this first version.
    pub ruleset: String,
}

/// Pure validation, no I/O: referential integrity across `mesh.yaml`'s own cross-references
/// (`mesh.links[].pair`, `roadwarriors[].node_hostnames`, `bypass[].node` must all name real
/// `nodes[].name` entries) plus structural invariants this generator's own rendering logic
/// depends on (unique ports per node, non-empty `nodes`). Does **not** validate the
/// awg/router/nftables config this would render into - `render.rs` computes that separately, and
/// `main.rs` runs `awg::config::validate`/`router::config::validate`/`nftables::config::validate`
/// on the *result*, which is the real, authoritative check that the daemons would actually accept
/// it.
pub fn validate(cfg: &MeshConfig) -> anyhow::Result<()> {
    anyhow::ensure!(!cfg.nodes.is_empty(), "nodes must not be empty");

    let mut seen_node_names = HashSet::new();
    let mut seen_node_ids = HashSet::new();
    for node in &cfg.nodes {
        anyhow::ensure!(!node.name.is_empty(), "nodes[].name must not be empty");
        anyhow::ensure!(
            seen_node_names.insert(node.name.as_str()),
            "duplicate node name {:?}",
            node.name
        );
        let node_id: Ipv4Addr = node.node_id.parse().map_err(|e| {
            anyhow::anyhow!(
                "node {:?}: node_id {:?} is not a valid IPv4-shaped identity: {e}",
                node.name,
                node.node_id
            )
        })?;
        anyhow::ensure!(
            seen_node_ids.insert(node_id),
            "node {:?}: node_id {:?} is already used by another node - each node needs a distinct \
             node_id, or they'll collide onto the same loopback address",
            node.name,
            node.node_id
        );
    }
    let known_node = |name: &str| seen_node_names.contains(name);

    // port -> set of node names already using it, so a port collision names both offending nodes,
    // not just the second one seen.
    let mut ports_by_node: std::collections::HashMap<&str, HashSet<u16>> =
        std::collections::HashMap::new();

    for link in &cfg.mesh.links {
        for name in &link.pair {
            anyhow::ensure!(
                known_node(name),
                "mesh.links: pair references unknown node {name:?}"
            );
        }
        anyhow::ensure!(
            link.pair[0] != link.pair[1],
            "mesh.links: pair {:?} links a node to itself",
            link.pair
        );
        for name in &link.pair {
            anyhow::ensure!(
                ports_by_node
                    .entry(name.as_str())
                    .or_default()
                    .insert(link.port),
                "node {name:?}: port {} used by more than one mesh link/roadwarriors pool",
                link.port
            );
        }
    }

    let mut seen_pool_names = HashSet::new();
    for pool in &cfg.roadwarriors {
        anyhow::ensure!(
            seen_pool_names.insert(pool.name.as_str()),
            "duplicate roadwarriors pool name {:?}",
            pool.name
        );
        anyhow::ensure!(
            !pool.node_hostnames.is_empty(),
            "roadwarriors pool {:?}: node_hostnames must not be empty",
            pool.name
        );
        for name in &pool.node_hostnames {
            anyhow::ensure!(
                known_node(name),
                "roadwarriors pool {:?}: node_hostnames references unknown node {name:?}",
                pool.name
            );
            anyhow::ensure!(
                ports_by_node
                    .entry(name.as_str())
                    .or_default()
                    .insert(pool.listen_port),
                "node {name:?}: port {} used by more than one mesh link/roadwarriors pool",
                pool.listen_port
            );
        }
        let mut seen_client_keys = HashSet::new();
        for client in &pool.clients {
            anyhow::ensure!(
                seen_client_keys.insert(client.public_key.as_str()),
                "roadwarriors pool {:?}: duplicate client public_key {:?}",
                pool.name,
                client.public_key
            );
        }
    }

    for entry in &cfg.bypass {
        anyhow::ensure!(
            known_node(&entry.node),
            "bypass: entry references unknown node {:?}",
            entry.node
        );
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn minimal_yaml() -> &'static str {
        r#"
cluster:
  bgp_as: 64512
  loopback_networks: {ipv4: "10.62.0.0/16", ipv6: "fd00:62::/32"}
nodes:
  - name: a
    node_id: "10.62.0.1"
  - name: b
    node_id: "10.62.0.2"
"#
    }

    #[test]
    fn parses_a_minimal_config() {
        let cfg: MeshConfig = serde_yaml::from_str(minimal_yaml()).unwrap();
        assert_eq!(cfg.nodes.len(), 2);
        assert_eq!(cfg.cluster.bgp_as, 64512);
        validate(&cfg).unwrap();
    }

    #[test]
    fn tunnel_networks_is_none_when_not_configured() {
        let cfg: MeshConfig = serde_yaml::from_str(minimal_yaml()).unwrap();
        assert!(cfg.cluster.tunnel_networks.is_none());
    }

    #[test]
    fn parses_an_explicit_tunnel_networks_block() {
        let yaml = r#"
cluster:
  bgp_as: 64512
  loopback_networks: {ipv4: "10.62.0.0/16", ipv6: "fd00:62::/32"}
  tunnel_networks: {ipv4: "10.62.1.0/24", ipv6: "fd00:63::/120"}
nodes:
  - name: a
    node_id: "10.62.0.1"
  - name: b
    node_id: "10.62.0.2"
"#;
        let cfg: MeshConfig = serde_yaml::from_str(yaml).unwrap();
        let tunnel = cfg.cluster.tunnel_networks.unwrap();
        assert_eq!(tunnel.ipv4, "10.62.1.0/24");
        assert_eq!(tunnel.ipv6, "fd00:63::/120");
    }

    #[test]
    fn rejects_empty_nodes() {
        let cfg = MeshConfig::default();
        assert!(validate(&cfg).is_err());
    }

    #[test]
    fn rejects_duplicate_node_names() {
        let mut cfg: MeshConfig = serde_yaml::from_str(minimal_yaml()).unwrap();
        cfg.nodes[1].name = "a".to_string();
        assert!(validate(&cfg).is_err());
    }

    #[test]
    fn rejects_duplicate_node_id() {
        // Two distinct nodes sharing a node_id would silently collide onto the same loopback
        // address and the same mesh interface name on any node linked to both - must fail here,
        // not surface downstream as a confusing "duplicate interface name" from awg::config.
        let mut cfg: MeshConfig = serde_yaml::from_str(minimal_yaml()).unwrap();
        cfg.nodes[1].node_id = cfg.nodes[0].node_id.clone();
        let err = validate(&cfg).unwrap_err();
        assert!(err.to_string().contains("node_id"), "error was: {err}");
    }

    #[test]
    fn rejects_a_node_id_that_is_not_a_valid_ipv4_address() {
        let mut cfg: MeshConfig = serde_yaml::from_str(minimal_yaml()).unwrap();
        cfg.nodes[0].node_id = "not-an-ip".to_string();
        assert!(validate(&cfg).is_err());
    }

    #[test]
    fn rejects_mesh_link_referencing_unknown_node() {
        let mut cfg: MeshConfig = serde_yaml::from_str(minimal_yaml()).unwrap();
        cfg.mesh.links.push(MeshLink {
            pair: ["a".to_string(), "ghost".to_string()],
            port: 51820,
            obfuscation: Obfuscation::default(),
            plain: false,
        });
        assert!(validate(&cfg).is_err());
    }

    #[test]
    fn rejects_mesh_link_to_self() {
        let mut cfg: MeshConfig = serde_yaml::from_str(minimal_yaml()).unwrap();
        cfg.mesh.links.push(MeshLink {
            pair: ["a".to_string(), "a".to_string()],
            port: 51820,
            obfuscation: Obfuscation::default(),
            plain: false,
        });
        assert!(validate(&cfg).is_err());
    }

    #[test]
    fn accepts_two_links_on_the_same_node_with_different_ports() {
        let mut cfg: MeshConfig = serde_yaml::from_str(minimal_yaml()).unwrap();
        cfg.nodes.push(NodeEntry {
            name: "c".to_string(),
            node_id: "10.62.0.3".to_string(),
            endpoint: None,
            mesh_private_key: None,
            direct_interfaces: None,
        });
        cfg.mesh.links.push(MeshLink {
            pair: ["a".to_string(), "b".to_string()],
            port: 51820,
            obfuscation: Obfuscation::default(),
            plain: false,
        });
        cfg.mesh.links.push(MeshLink {
            pair: ["a".to_string(), "c".to_string()],
            port: 51821,
            obfuscation: Obfuscation::default(),
            plain: false,
        });
        validate(&cfg).unwrap();
    }

    #[test]
    fn rejects_duplicate_port_on_the_same_node() {
        let mut cfg: MeshConfig = serde_yaml::from_str(minimal_yaml()).unwrap();
        cfg.nodes.push(NodeEntry {
            name: "c".to_string(),
            node_id: "10.62.0.3".to_string(),
            endpoint: None,
            mesh_private_key: None,
            direct_interfaces: None,
        });
        cfg.mesh.links.push(MeshLink {
            pair: ["a".to_string(), "b".to_string()],
            port: 51820,
            obfuscation: Obfuscation::default(),
            plain: false,
        });
        cfg.mesh.links.push(MeshLink {
            pair: ["a".to_string(), "c".to_string()],
            port: 51820,
            obfuscation: Obfuscation::default(),
            plain: false,
        });
        assert!(validate(&cfg).is_err());
    }

    #[test]
    fn rejects_roadwarriors_pool_referencing_unknown_node() {
        let mut cfg: MeshConfig = serde_yaml::from_str(minimal_yaml()).unwrap();
        cfg.roadwarriors.push(RoadwarriorPool {
            name: "eu".to_string(),
            node_hostnames: vec!["ghost".to_string()],
            iface: "rw-eu".to_string(),
            address: "10.62.253.1/24".to_string(),
            address6: None,
            listen_port: 51820,
            handshake_stale_secs: None,
            private_key: None,
            obfuscation: Obfuscation::default(),
            clients: vec![],
        });
        assert!(validate(&cfg).is_err());
    }

    #[test]
    fn rejects_roadwarriors_pool_with_empty_node_hostnames() {
        let mut cfg: MeshConfig = serde_yaml::from_str(minimal_yaml()).unwrap();
        cfg.roadwarriors.push(RoadwarriorPool {
            name: "eu".to_string(),
            node_hostnames: vec![],
            iface: "rw-eu".to_string(),
            address: "10.62.253.1/24".to_string(),
            address6: None,
            listen_port: 51820,
            handshake_stale_secs: None,
            private_key: None,
            obfuscation: Obfuscation::default(),
            clients: vec![],
        });
        assert!(validate(&cfg).is_err());
    }

    #[test]
    fn rejects_duplicate_roadwarrior_client_public_key_in_one_pool() {
        let mut cfg: MeshConfig = serde_yaml::from_str(minimal_yaml()).unwrap();
        cfg.roadwarriors.push(RoadwarriorPool {
            name: "eu".to_string(),
            node_hostnames: vec!["a".to_string()],
            iface: "rw-eu".to_string(),
            address: "10.62.253.1/24".to_string(),
            address6: None,
            listen_port: 51820,
            handshake_stale_secs: None,
            private_key: None,
            obfuscation: Obfuscation::default(),
            clients: vec![
                RoadwarriorClient {
                    name: "alice".to_string(),
                    public_key: "k".to_string(),
                    allowed_ips: vec!["10.62.253.5/32".to_string()],
                    advanced_security: false,
                },
                RoadwarriorClient {
                    name: "bob".to_string(),
                    public_key: "k".to_string(),
                    allowed_ips: vec!["10.62.253.6/32".to_string()],
                    advanced_security: false,
                },
            ],
        });
        assert!(validate(&cfg).is_err());
    }

    #[test]
    fn rejects_bypass_entry_referencing_unknown_node() {
        let mut cfg: MeshConfig = serde_yaml::from_str(minimal_yaml()).unwrap();
        cfg.bypass.push(BypassEntry {
            node: "ghost".to_string(),
            include: vec![],
            exclude: vec![],
        });
        assert!(validate(&cfg).is_err());
    }

    #[test]
    fn accepts_roadwarriors_and_mesh_sharing_a_node_with_distinct_ports() {
        let mut cfg: MeshConfig = serde_yaml::from_str(minimal_yaml()).unwrap();
        cfg.mesh.links.push(MeshLink {
            pair: ["a".to_string(), "b".to_string()],
            port: 51820,
            obfuscation: Obfuscation::default(),
            plain: false,
        });
        cfg.roadwarriors.push(RoadwarriorPool {
            name: "eu".to_string(),
            node_hostnames: vec!["a".to_string()],
            iface: "rw-eu".to_string(),
            address: "10.62.253.1/24".to_string(),
            address6: None,
            listen_port: 51821,
            handshake_stale_secs: None,
            private_key: None,
            obfuscation: Obfuscation::default(),
            clients: vec![],
        });
        validate(&cfg).unwrap();
    }
}
