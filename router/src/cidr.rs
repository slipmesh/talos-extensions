//! Pure IPv4 CIDR parsing and set arithmetic - no I/O, no netlink, fully portable. Ported from
//! `slipmesh/core`'s `cidr.rs`, dropped down to just the pieces `resolver.rs`'s bypass-route set
//! arithmetic and `config.rs`'s validation actually use - the
//! `Cidr`/`contains`/`address_exclude`/`collapse` trio matches Python's `ipaddress` module's
//! `subnet_of`/`address_exclude`/`collapse_addresses` shape. IPv4 only throughout: BYPASS/ANNOUNCE
//! stay IPv4-only even after the OSPFv3/RFC 8950 underlay migration (only the transport under iBGP
//! changed, not the payload prefixes it carries) - see `bird.rs`'s module doc comment.

use anyhow::{Context, Result};
use std::net::{Ipv4Addr, Ipv6Addr};

/// Shared IPv4 CIDR parse+validate.
pub fn parse_cidr(cidr: &str) -> Result<(Ipv4Addr, u8)> {
    let (addr, prefix) = cidr
        .split_once('/')
        .with_context(|| format!("{cidr:?} is not a CIDR (missing '/')"))?;
    let addr: Ipv4Addr = addr
        .parse()
        .with_context(|| format!("invalid address in {cidr:?}"))?;
    let prefix: u8 = prefix
        .parse()
        .with_context(|| format!("invalid prefix length in {cidr:?}"))?;
    anyhow::ensure!(
        prefix <= 32,
        "invalid prefix length in {cidr:?}: {prefix} > 32"
    );
    Ok((addr, prefix))
}

/// IPv4-only CIDR set operations equivalent to Python's `ipaddress` module functions
/// `subnet_of`, `address_exclude`, `collapse_addresses`.
pub type Cidr = (u32, u8); // (network address, prefix length)

fn mask(prefix_len: u8) -> u32 {
    if prefix_len == 0 {
        0
    } else {
        u32::MAX << (32 - prefix_len)
    }
}

pub fn network_addr(addr: u32, prefix_len: u8) -> u32 {
    addr & mask(prefix_len)
}

pub fn contains(outer: Cidr, inner: Cidr) -> bool {
    inner.1 >= outer.1 && network_addr(inner.0, outer.1) == outer.0
}

/// Splits `net` into the minimal set of subnets that cover `net` but exclude `exclude`.
/// Caller's responsibility: `exclude` must be `contains`ed by `net`.
pub fn address_exclude(net: Cidr, exclude: Cidr) -> Vec<Cidr> {
    if net.1 >= exclude.1 {
        return Vec::new();
    }
    let mut out = Vec::new();
    let mut current = net;
    while current.1 < exclude.1 {
        let child_len = current.1 + 1;
        let half_size = 1u32 << (32 - child_len);
        let lower = (current.0, child_len);
        let upper = (current.0.wrapping_add(half_size), child_len);
        if contains(lower, exclude) {
            out.push(upper);
            current = lower;
        } else {
            out.push(lower);
            current = upper;
        }
    }
    out
}

/// Merges overlapping/subsumed/sibling-adjacent networks into their minimal covering set -
/// mirrors `ipaddress.collapse_addresses()`: first drops anything already contained in a larger
/// entry, then repeatedly merges same-length sibling pairs (differ only in their last bit, so
/// together they exactly fill their shared parent prefix) until no more merges apply.
pub fn collapse(nets: &[Cidr]) -> Vec<Cidr> {
    let mut nets: Vec<Cidr> = nets.to_vec();
    nets.sort();
    nets.dedup();

    // Drop anything fully contained in a different, larger entry.
    let mut deduped: Vec<Cidr> = Vec::new();
    for &n in &nets {
        if !nets
            .iter()
            .any(|&other| other != n && other.1 < n.1 && contains(other, n))
        {
            deduped.push(n);
        }
    }
    deduped.sort();
    deduped.dedup();

    loop {
        let mut merged: Vec<Cidr> = Vec::new();
        let mut used = vec![false; deduped.len()];
        let mut changed = false;
        for i in 0..deduped.len() {
            if used[i] {
                continue;
            }
            let (addr, len) = deduped[i];
            if len == 0 {
                merged.push(deduped[i]);
                continue;
            }
            let parent = network_addr(addr, len - 1);
            let sibling_addr = parent | (1u32 << (32 - len));
            let is_lower = addr == parent;
            let sibling = if is_lower {
                (sibling_addr, len)
            } else {
                (parent, len)
            };
            if let Some(j) = deduped
                .iter()
                .enumerate()
                .position(|(idx, &c)| idx != i && !used[idx] && c == sibling)
            {
                used[i] = true;
                used[j] = true;
                merged.push((parent, len - 1));
                changed = true;
            } else {
                used[i] = true;
                merged.push(deduped[i]);
            }
        }
        merged.sort();
        merged.dedup();
        deduped = merged;
        if !changed {
            break;
        }
    }
    deduped
}

/// This node's deterministic IPv6 link-local address for `router-lo`, derived from the low 32
/// bits of its own configured `ipv6_loopback` (`fe80::<hex>`, e.g. `fd00::a1b2c3d4` ->
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

    fn c(a: u8, b: u8, c_: u8, d: u8, len: u8) -> Cidr {
        (u32::from_be_bytes([a, b, c_, d]), len)
    }

    #[test]
    fn parse_cidr_accepts_well_formed() {
        assert_eq!(
            parse_cidr("10.0.0.0/24").unwrap(),
            (Ipv4Addr::new(10, 0, 0, 0), 24)
        );
    }

    #[test]
    fn parse_cidr_rejects_missing_slash() {
        assert!(parse_cidr("10.0.0.0").is_err());
    }

    #[test]
    fn parse_cidr_rejects_prefix_over_32() {
        assert!(parse_cidr("10.0.0.0/33").is_err());
    }

    #[test]
    fn exclude_splits_correctly() {
        // 10.0.0.0/24 minus 10.0.0.128/25 -> 10.0.0.0/25
        let out = address_exclude(c(10, 0, 0, 0, 24), c(10, 0, 0, 128, 25));
        assert_eq!(out, vec![c(10, 0, 0, 0, 25)]);
    }

    #[test]
    fn exclude_splits_nested() {
        // 10.0.0.0/24 minus 10.0.0.64/26 -> 10.0.0.128/25, 10.0.0.0/26
        let mut out = address_exclude(c(10, 0, 0, 0, 24), c(10, 0, 0, 64, 26));
        out.sort();
        let mut expected = vec![c(10, 0, 0, 128, 25), c(10, 0, 0, 0, 26)];
        expected.sort();
        assert_eq!(out, expected);
    }

    #[test]
    fn collapse_merges_siblings() {
        let out = collapse(&[c(10, 0, 0, 0, 25), c(10, 0, 0, 128, 25)]);
        assert_eq!(out, vec![c(10, 0, 0, 0, 24)]);
    }

    #[test]
    fn collapse_drops_subsumed() {
        let out = collapse(&[c(10, 0, 0, 0, 24), c(10, 0, 0, 0, 25)]);
        assert_eq!(out, vec![c(10, 0, 0, 0, 24)]);
    }

    #[test]
    fn collapse_leaves_unrelated_alone() {
        let mut out = collapse(&[c(10, 0, 0, 0, 24), c(192, 168, 1, 0, 24)]);
        out.sort();
        let mut expected = vec![c(10, 0, 0, 0, 24), c(192, 168, 1, 0, 24)];
        expected.sort();
        assert_eq!(out, expected);
    }

    #[test]
    fn contains_checks_prefix_and_alignment() {
        assert!(contains(c(10, 0, 0, 0, 8), c(10, 1, 2, 0, 24)));
        assert!(!contains(c(10, 0, 0, 0, 24), c(10, 0, 1, 0, 24)));
    }
    #[test]
    fn link_local_from_loopback_derives_fe80_from_low_32_bits() {
        assert_eq!(
            link_local_from_loopback("fd00::a1b2:c3d4".parse().unwrap()).to_string(),
            "fe80::a1b2:c3d4"
        );
    }
}
