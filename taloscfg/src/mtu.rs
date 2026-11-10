//! The one MTU every mesh interface gets: the largest at which a full-size packet, with its
//! WireGuard and junk overhead, still crosses every link's underlay unfragmented.
//!
//! A link's limit is `U - 32 - 8 - IP - S4`. `U` is the smaller uplink MTU of its two nodes, 32 is
//! WireGuard's own header and tag, 8 the UDP header, `IP` 20 or 40 for the underlay family, and S4
//! the junk AmneziaWG adds to every data packet. WireGuard pads a packet to a multiple of 16, but
//! never past the MTU, so a full-size packet carries no padding. A fragmented outer packet takes
//! TCP in the tunnel down to a few Mbit/s, which is what this guards against.

use crate::mesh_config::{AddressFamily, MeshConfig, MeshLink, NodeEntry};
use crate::secrets::{ResolvedSecrets, link_key};
use anyhow::{Context, Result, bail, ensure};
use std::net::IpAddr;

/// An uplink's MTU when `nodes[].uplink_mtu` does not say.
pub const DEFAULT_UPLINK_MTU: u32 = 1500;

/// The least MTU IPv6 allows a link (RFC 8200); the mesh carries OSPFv3 over IPv6 link-locals.
pub const MIN_MESH_MTU: u32 = 1280;

/// The MTU of every mesh interface: `cluster.mesh_mtu` when it fits every link, else the least
/// link limit. None for a mesh without links, which has no mesh interface to give it to.
pub fn mesh_mtu(mesh: &MeshConfig, resolved: &ResolvedSecrets) -> Result<Option<u32>> {
    let mut least: Option<(u32, &MeshLink)> = None;
    for link in &mesh.mesh.links {
        let limit = link_limit(mesh, link, resolved)
            .with_context(|| format!("mesh link {}", name(link)))?;
        if least.is_none_or(|(least, _)| limit < least) {
            least = Some((limit, link));
        }
    }
    let Some((limit, link)) = least else {
        ensure!(
            mesh.cluster.mesh_mtu.is_none(),
            "cluster.mesh_mtu is set, but the mesh has no link to give it to"
        );
        return Ok(None);
    };
    let mtu = match mesh.cluster.mesh_mtu {
        Some(mtu) => {
            ensure!(
                mtu <= limit,
                "cluster.mesh_mtu {mtu} is above {limit}, the limit of mesh link {}",
                name(link)
            );
            ensure!(
                mtu >= MIN_MESH_MTU,
                "cluster.mesh_mtu {mtu} is below {MIN_MESH_MTU}, the least IPv6 allows a link"
            );
            mtu
        }
        None => {
            ensure!(
                limit >= MIN_MESH_MTU,
                "mesh link {} limits the mesh MTU to {limit}, below {MIN_MESH_MTU}, the least \
                 IPv6 allows a link",
                name(link)
            );
            limit
        }
    };
    Ok(Some(mtu))
}

/// The largest MTU at which a full-size packet crosses `link` unfragmented.
fn link_limit(mesh: &MeshConfig, link: &MeshLink, resolved: &ResolvedSecrets) -> Result<u32> {
    let [a, b] = &link.pair;
    let (a, b) = (mesh.node(a)?, mesh.node(b)?);
    let ip_header = match link_family(a, b)? {
        AddressFamily::Ipv4 => 20,
        AddressFamily::Ipv6 => 40,
    };
    let uplink = uplink(a).min(uplink(b));
    let junk = resolved
        .mesh_link_obfuscation
        .get(&link_key(&link.pair))
        .and_then(|o| o.s4)
        .map_or(0, u32::from);
    Ok(uplink.saturating_sub(32 + 8 + ip_header + junk))
}

fn uplink(node: &NodeEntry) -> u32 {
    node.uplink_mtu.unwrap_or(DEFAULT_UPLINK_MTU)
}

/// The family of the endpoint a link is dialed at: either side's, and the same when both have one.
fn link_family(a: &NodeEntry, b: &NodeEntry) -> Result<AddressFamily> {
    match (endpoint_family(a)?, endpoint_family(b)?) {
        (Some(x), Some(y)) if x != y => bail!(
            "the endpoints of {:?} and {:?} differ in address family, so which one carries the \
             link depends on who starts the handshake",
            a.name,
            b.name
        ),
        (Some(family), _) | (None, Some(family)) => Ok(family),
        (None, None) => bail!(
            "neither {:?} nor {:?} has an endpoint, so neither can dial the other",
            a.name,
            b.name
        ),
    }
}

fn endpoint_family(node: &NodeEntry) -> Result<Option<AddressFamily>> {
    let Some(endpoint) = &node.endpoint else {
        return Ok(None);
    };
    let Ok(literal) = endpoint.parse::<IpAddr>() else {
        return Ok(Some(node.address_family.unwrap_or(AddressFamily::Ipv6)));
    };
    let family = if literal.is_ipv4() {
        AddressFamily::Ipv4
    } else {
        AddressFamily::Ipv6
    };
    ensure!(
        node.address_family.is_none_or(|said| said == family),
        "node {:?}: address_family {:?} contradicts its endpoint {endpoint}",
        node.name,
        node.address_family.expect("checked just above")
    );
    Ok(Some(family))
}

fn name(link: &MeshLink) -> String {
    format!("{}-{}", link.pair[0], link.pair[1])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secrets;

    /// Two nodes `a` and `b` and one link between them, plain unless `obfuscation` gives it some.
    fn mesh(a: &str, b: &str, link: &str, cluster: &str) -> MeshConfig {
        let yaml = format!(
            "cluster:\n  bgp_as: 64512\n  loopback_networks: {{ipv4: \"198.51.100.0/25\", \
             ipv6: \"3fff::/32\"}}\n{cluster}nodes:\n  - {{name: a, node_id: \
             \"198.51.100.1\"{a}}}\n  - {{name: b, node_id: \"198.51.100.2\"{b}}}\nmesh:\n  \
             links:\n    - {{pair: [a, b], port: 51820{link}}}\n"
        );
        sliplib_yaml::from_str(&yaml).unwrap()
    }

    fn computed(mesh: &MeshConfig) -> Result<Option<u32>> {
        mesh_mtu(mesh, &secrets::resolve(mesh).0)
    }

    fn mtu(a: &str, b: &str, link: &str, cluster: &str) -> u32 {
        computed(&mesh(a, b, link, cluster)).unwrap().unwrap()
    }

    fn error(a: &str, b: &str, link: &str, cluster: &str) -> String {
        format!("{:#}", computed(&mesh(a, b, link, cluster)).unwrap_err())
    }

    const PLAIN: &str = ", plain: true";
    const V4: &str = ", endpoint: \"192.0.2.10\"";
    const V4_OTHER: &str = ", endpoint: \"192.0.2.11\"";
    const V6: &str = ", endpoint: \"2001:db8::10\"";
    const NAME: &str = ", endpoint: node-a.example.com";

    #[test]
    fn an_ipv4_link_with_no_junk_on_a_1500_underlay_takes_1440() {
        assert_eq!(mtu(V4, V4_OTHER, PLAIN, ""), 1440);
    }

    #[test]
    fn an_ipv6_link_takes_20_less() {
        assert_eq!(mtu(V6, "", PLAIN, ""), 1420);
    }

    #[test]
    fn the_family_is_that_of_the_endpoint_dialed_whichever_side_has_it() {
        assert_eq!(mtu(V4, "", PLAIN, ""), 1440);
        assert_eq!(mtu("", V4, PLAIN, ""), 1440);
        assert_eq!(mtu("", V6, PLAIN, ""), 1420);
    }

    #[test]
    fn endpoints_of_two_families_on_one_link_are_an_error_naming_it() {
        let err = error(V4, V6, PLAIN, "");
        assert!(
            err.contains("a") && err.contains("b") && err.contains("family"),
            "{err}"
        );
    }

    #[test]
    fn a_link_with_no_endpoint_on_either_side_is_an_error_naming_it() {
        let err = error("", "", PLAIN, "");
        assert!(err.contains("endpoint"), "{err}");
    }

    #[test]
    fn a_hostname_endpoint_is_ipv6_unless_its_node_says_otherwise() {
        assert_eq!(mtu(NAME, "", PLAIN, ""), 1420);
        let named_v4 = format!("{NAME}, address_family: ipv4");
        assert_eq!(mtu(&named_v4, "", PLAIN, ""), 1440);
    }

    #[test]
    fn an_address_family_that_contradicts_a_literal_endpoint_is_an_error() {
        let err = error(&format!("{V4}, address_family: ipv6"), "", PLAIN, "");
        assert!(err.contains("address_family"), "{err}");
        assert_eq!(
            mtu(&format!("{V4}, address_family: ipv4"), "", PLAIN, ""),
            1440
        );
    }

    #[test]
    fn the_smaller_uplink_of_the_two_nodes_bounds_the_link() {
        assert_eq!(mtu(&format!("{V4}, uplink_mtu: 1460"), "", PLAIN, ""), 1400);
        assert_eq!(mtu(V4, ", uplink_mtu: 1460", PLAIN, ""), 1400);
        assert_eq!(
            mtu(
                &format!("{V4}, uplink_mtu: 1460"),
                ", uplink_mtu: 1450",
                PLAIN,
                ""
            ),
            1390
        );
    }

    #[test]
    fn junk_on_data_packets_lowers_the_link_by_its_size() {
        assert_eq!(mtu(V6, "", ", obfuscation: {s4: 12}", ""), 1408);
        let global = "obfuscation: {s4: 12}\n";
        assert_eq!(mtu(V4, "", "", global), 1428);
        assert_eq!(mtu(V4, "", ", obfuscation: {s4: 20}", global), 1420);
    }

    #[test]
    fn the_mesh_takes_the_least_of_its_links() {
        // a-b dials a over IPv4 at 1500: 1440. b-c dials c over IPv6 at 1490: 1410.
        let yaml = "cluster:\n  bgp_as: 64512\n  loopback_networks: {ipv4: \"198.51.100.0/25\", \
                    ipv6: \"3fff::/32\"}\nnodes:\n  - {name: a, node_id: \"198.51.100.1\", \
                    endpoint: \"192.0.2.10\"}\n  - {name: b, node_id: \"198.51.100.2\"}\n  - \
                    {name: c, node_id: \"198.51.100.3\", endpoint: \"2001:db8::12\", uplink_mtu: \
                    1490}\nmesh:\n  links:\n    - {pair: [a, b], port: 51820, plain: true}\n    - \
                    {pair: [b, c], port: 51821, plain: true}\n";
        let topology: MeshConfig = sliplib_yaml::from_str(yaml).unwrap();
        assert_eq!(computed(&topology).unwrap(), Some(1410));
    }

    #[test]
    fn a_mesh_mtu_at_or_below_the_least_link_is_taken() {
        assert_eq!(mtu(V4, "", PLAIN, "  mesh_mtu: 1420\n"), 1420);
        assert_eq!(mtu(V4, "", PLAIN, "  mesh_mtu: 1440\n"), 1440);
    }

    #[test]
    fn a_mesh_mtu_above_the_least_link_is_an_error_naming_the_link_and_its_limit() {
        let err = error(V4, "", PLAIN, "  mesh_mtu: 1441\n");
        assert!(err.contains("1441") && err.contains("1440"), "{err}");
        assert!(err.contains("a") && err.contains("b"), "{err}");
    }

    #[test]
    fn an_mtu_below_1280_is_an_error_and_1280_is_not() {
        assert_eq!(mtu(V4, ", uplink_mtu: 1340", PLAIN, ""), 1280);
        let err = error(V4, ", uplink_mtu: 1339", PLAIN, "");
        assert!(err.contains("1279") && err.contains("1280"), "{err}");
        let err = error(V4, "", PLAIN, "  mesh_mtu: 1279\n");
        assert!(err.contains("1279") && err.contains("1280"), "{err}");
    }

    #[test]
    fn a_mesh_without_links_takes_no_mtu_and_refuses_one() {
        let mut topology = mesh(V4, V6, PLAIN, "");
        topology.mesh.links.clear();
        assert_eq!(computed(&topology).unwrap(), None);
        let mut topology = mesh(V4, V6, PLAIN, "  mesh_mtu: 1400\n");
        topology.mesh.links.clear();
        let err = format!("{:#}", computed(&topology).unwrap_err());
        assert!(err.contains("mesh_mtu"), "{err}");
    }

    /// The outer packet as it leaves the node: the inner packet padded to 16 but never past the
    /// MTU, then the WireGuard header and tag, the junk, UDP and the underlay's IP header.
    fn outer(inner: u32, mtu: u32, s4: u32, ip: u32) -> u32 {
        inner.div_ceil(16).saturating_mul(16).min(mtu) + 32 + s4 + 8 + ip
    }

    #[test]
    fn across_the_grid_a_full_size_packet_fits_and_one_byte_more_does_not() {
        for s4 in [0, 12, 20, 89, 150] {
            for uplink in [1400, 1460, 1500, 9000] {
                for (endpoint, ip) in [(V4, 20), (V6, 40)] {
                    let a = format!("{endpoint}, uplink_mtu: {uplink}");
                    let b = format!(", uplink_mtu: {uplink}");
                    let link = format!(", obfuscation: {{s4: {s4}}}");
                    let Ok(Some(mtu)) = computed(&mesh(&a, &b, &link, "")) else {
                        assert!(uplink - 32 - 8 - ip - s4 < MIN_MESH_MTU);
                        continue;
                    };
                    assert!(outer(mtu, mtu, s4, ip) <= uplink, "{s4} {uplink} {ip}");
                    assert!(
                        outer(mtu + 1, mtu + 1, s4, ip) > uplink,
                        "{s4} {uplink} {ip}"
                    );
                }
            }
        }
    }
}
