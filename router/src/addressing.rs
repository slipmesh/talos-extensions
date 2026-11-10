//! Addresses derived from this node's own loopbacks.

use std::net::Ipv6Addr;

/// This node's deterministic IPv6 link-local address for `router-lo`, derived from the low 32
/// bits of its own configured `ipv6_loopback` (`fe80::<hex>`, e.g. `3fff::a1b2c3d4` ->
/// `fe80::a1b2:c3d4`) - not a separately-configured `node_id` the way the k8s original derived it
/// (that concept doesn't exist here; `router.yaml` gives each node's loopbacks directly, see
/// `RouterIdentity`'s doc comment), just reusing the same digits already unique to this node by
/// construction (they're a real, config-supplied loopback address).
///
/// `pub`, not just used internally by `ensure_loopback`: the `taloscfg` crate (a separate crate
/// from this lib target, generating the `ipv6_loopback` this daemon reads rather than reading it)
/// calls this too, for its mesh-interface link-locals - it computes an `ipv6_loopback`-shaped
/// value from a node's `node_id` first (see `taloscfg::addressing::ipv6_loopback`), whose low 32
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn link_local_from_loopback_derives_fe80_from_low_32_bits() {
        assert_eq!(
            link_local_from_loopback("3fff::a1b2:c3d4".parse().unwrap()).to_string(),
            "fe80::a1b2:c3d4"
        );
    }
}
