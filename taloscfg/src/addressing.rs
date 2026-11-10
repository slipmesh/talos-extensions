//! Deterministic address/name derivation from a node's `node_id` (an IPv4-address-shaped identity,
//! see `mesh_config::NodeEntry`) - ported from the old k8s-CRD system's `slipmesh-core::ipv6`
//! (`network | node_id`), not reused as a dependency: `taloscfg` deliberately has no dependency on
//! the legacy Kubernetes-based crate, since the whole point of this tool is the migration away
//! from it. Same formulas, same test vectors, reimplemented standalone.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

fn node_id_bits(node_id: Ipv4Addr) -> u32 {
    u32::from(node_id)
}

/// `network/prefix_len`'s network bits with `node_id`'s low bits filling in the host portion.
pub fn ipv4_loopback(network: Ipv4Addr, prefix_len: u8, node_id: Ipv4Addr) -> Ipv4Addr {
    let mask: u32 = if prefix_len == 0 {
        0
    } else {
        u32::MAX << (32 - prefix_len)
    };
    Ipv4Addr::from((u32::from(network) & mask) | (node_id_bits(node_id) & !mask))
}

/// Same `network | node_id` idea as `ipv4_loopback`, embedding `node_id`'s 32 bits into the low 32
/// bits of `network/prefix_len`'s host portion.
pub fn ipv6_loopback(network: Ipv6Addr, prefix_len: u8, node_id: Ipv4Addr) -> Ipv6Addr {
    let mask: u128 = if prefix_len == 0 {
        0
    } else {
        u128::MAX << (128 - prefix_len)
    };
    let host = u128::from(node_id_bits(node_id));
    Ipv6Addr::from((u128::from(network) & mask) | (host & !mask))
}

/// `host`, `host:port`, an IP address, or a bracketed IPv6 with or without a port, as an
/// endpoint to dial - `port` filling in a missing one.
pub fn endpoint(endpoint: &str, port: u16) -> String {
    if let Ok(IpAddr::V6(v6)) = endpoint.parse() {
        return format!("[{v6}]:{port}");
    }
    match endpoint.rsplit_once(':') {
        Some((_, given)) if given.parse::<u16>().is_ok() => endpoint.to_owned(),
        _ => format!("{endpoint}:{port}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ipv4_loopback_ors_node_id_into_the_host_bits() {
        let network = Ipv4Addr::new(198, 51, 100, 0);
        let node_id = Ipv4Addr::new(0, 0, 0, 5);
        assert_eq!(
            ipv4_loopback(network, 25, node_id),
            Ipv4Addr::new(198, 51, 100, 5)
        );
    }

    #[test]
    fn different_node_ids_never_collide_for_the_same_network() {
        let network = Ipv4Addr::new(198, 51, 100, 0);
        let a = ipv4_loopback(network, 25, Ipv4Addr::new(0, 0, 0, 1));
        let b = ipv4_loopback(network, 25, Ipv4Addr::new(0, 0, 0, 2));
        assert_ne!(a, b);
    }

    #[test]
    fn ipv6_loopback_ors_node_id_into_the_low_32_host_bits() {
        let network: Ipv6Addr = "3fff::".parse().unwrap();
        let node_id = Ipv4Addr::new(0, 0, 0, 5);
        assert_eq!(ipv6_loopback(network, 32, node_id).to_string(), "3fff::5");
    }

    #[test]
    fn ipv6_loopback_leaves_middle_bits_zero() {
        let network: Ipv6Addr = "3fff::".parse().unwrap();
        let node_id = Ipv4Addr::new(198, 51, 100, 1);
        assert_eq!(
            ipv6_loopback(network, 32, node_id).to_string(),
            "3fff::c633:6401"
        );
    }
}
