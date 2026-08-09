//! Applies one `InterfaceEntry` to the kernel: link/addresses/identity, then a point-wise peer
//! diff against whatever's actually configured (read back from the kernel, not assumed empty -
//! this process gets fully restarted on every config change, so there is no in-memory "previous"
//! to carry over between runs; see AGENTS.md).
//!
//! Ported and merged from slipmesh-operators' `mesh::awg`/`roadwarriors::awg` (same repo,
//! github.com/slipmesh/operators) - the two were nearly-identical device/peer-attribute-building
//! code with different reconciliation shapes (mesh: exactly one peer, unconditional resend;
//! roadwarriors: many peers, point-wise diff). One shape (point-wise diff) now covers both, since
//! a diff against a single peer degenerates to exactly the same SetDevice call an unconditional
//! resend would have made.

use crate::config::{InterfaceEntry, PeerEntry};
use anyhow::{Context, Result};
use common::keys::decode_key;
use common::netlink::awg::{AwgClient, push_obfuscation_attrs};
use common::netlink::rt::{RtClient, parse_cidr};
use netlink_packet_amnezia_wireguard::{
    AmneziaWireguardAddressFamily, AmneziaWireguardAllowedIp, AmneziaWireguardAllowedIpAttr,
    AmneziaWireguardAttribute, AmneziaWireguardPeer, AmneziaWireguardPeerAttribute,
};
use std::net::{IpAddr, SocketAddr};

/// See amneziawg-linux-kernel-module's uapi/wireguard.h `enum wg_peer_flag`.
const WGPEER_F_REMOVE_ME: u32 = 1 << 0;
const WGPEER_F_REPLACE_ALLOWEDIPS: u32 = 1 << 1;
const PERSISTENT_KEEPALIVE_SECS: u32 = 25;

fn full_tunnel_allowed_ips() -> Vec<String> {
    vec!["0.0.0.0/0".to_string(), "::/0".to_string()]
}

/// One peer, resolved to exactly what the kernel needs - `allowed_ips` is always concrete (the
/// full-tunnel default if the config entry left it unset) and `endpoint` is already DNS-resolved.
/// Whether this peer is handshake-tracked (see `handshake.rs`) is a separate question, answered by
/// the *config* entry's `allowed_ips: Option<_>` being `Some` - not encoded here.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub struct Peer {
    pub public_key: String,
    pub allowed_ips: Vec<String>,
    pub endpoint: Option<String>,
}

async fn resolve_peer(entry: &PeerEntry) -> Result<Peer> {
    let allowed_ips = entry
        .allowed_ips
        .clone()
        .unwrap_or_else(full_tunnel_allowed_ips);
    let endpoint = match &entry.endpoint {
        Some(host_port) => Some(resolve_endpoint(host_port).await?),
        None => None,
    };
    Ok(Peer {
        public_key: entry.public_key.clone(),
        allowed_ips,
        endpoint,
    })
}

async fn resolve_endpoint(host_port: &str) -> Result<String> {
    let addr: SocketAddr = tokio::net::lookup_host(host_port)
        .await
        .with_context(|| format!("failed to resolve endpoint {host_port:?}"))?
        .next()
        .with_context(|| format!("no addresses found for endpoint {host_port:?}"))?;
    Ok(addr.to_string())
}

fn cidr_to_allowed_ip(cidr: &str) -> Result<AmneziaWireguardAllowedIp> {
    let (addr, prefix) = parse_cidr(cidr)?;
    let family = match addr {
        IpAddr::V4(_) => AmneziaWireguardAddressFamily::Ipv4,
        IpAddr::V6(_) => AmneziaWireguardAddressFamily::Ipv6,
    };
    Ok(AmneziaWireguardAllowedIp(vec![
        AmneziaWireguardAllowedIpAttr::Family(family),
        AmneziaWireguardAllowedIpAttr::IpAddr(addr),
        AmneziaWireguardAllowedIpAttr::Cidr(prefix),
    ]))
}

fn allowed_ip_to_cidr(attrs: &[AmneziaWireguardAllowedIpAttr]) -> Option<String> {
    let ip = attrs.iter().find_map(|a| match a {
        AmneziaWireguardAllowedIpAttr::IpAddr(ip) => Some(*ip),
        _ => None,
    })?;
    let cidr = attrs.iter().find_map(|a| match a {
        AmneziaWireguardAllowedIpAttr::Cidr(c) => Some(*c),
        _ => None,
    })?;
    Some(format!("{ip}/{cidr}"))
}

/// Reads back the peer set actually configured on the kernel interface. Always called, never
/// assumed empty - see this module's doc comment for why (no in-memory state survives a restart).
pub async fn current_peers(awg: &mut AwgClient, iface: &str) -> Result<Vec<Peer>> {
    use base64::Engine;

    let attrs = awg.get_device(iface).await?;
    let mut peers = Vec::new();
    for attr in attrs {
        let AmneziaWireguardAttribute::Peers(device_peers) = attr else {
            continue;
        };
        for peer in device_peers {
            let mut public_key = None;
            let mut allowed_ips = Vec::new();
            let mut endpoint = None;
            for pattr in peer.0 {
                match pattr {
                    AmneziaWireguardPeerAttribute::PublicKey(k) => {
                        public_key = Some(base64::engine::general_purpose::STANDARD.encode(k));
                    }
                    AmneziaWireguardPeerAttribute::AllowedIps(ips) => {
                        allowed_ips = ips
                            .iter()
                            .filter_map(|ip| allowed_ip_to_cidr(&ip.0))
                            .collect();
                    }
                    AmneziaWireguardPeerAttribute::Endpoint(addr) => {
                        endpoint = Some(addr.to_string());
                    }
                    _ => {}
                }
            }
            if let Some(public_key) = public_key {
                peers.push(Peer {
                    public_key,
                    allowed_ips,
                    endpoint,
                });
            }
        }
    }
    peers.sort();
    Ok(peers)
}

/// One entry per peer that needs to change: `Some(peer)` to add/replace, `None` to remove.
/// `previous`/`desired` need not be pre-sorted - keyed by `public_key` internally.
///
/// A peer counts as unchanged only if *both* `allowed_ips` (compared as a set - CIDR order is not
/// semantically meaningful to WireGuard) and `endpoint` match; either changing means the peer gets
/// re-sent with `WGPEER_F_REPLACE_ALLOWEDIPS`.
fn diff_peers(previous: &[Peer], desired: &[Peer]) -> Vec<(String, Option<Peer>)> {
    use std::collections::{BTreeMap, BTreeSet};

    fn as_set(ips: &[String]) -> BTreeSet<&str> {
        ips.iter().map(String::as_str).collect()
    }

    let prev_map: BTreeMap<&str, &Peer> = previous
        .iter()
        .map(|p| (p.public_key.as_str(), p))
        .collect();
    let desired_map: BTreeMap<&str, &Peer> =
        desired.iter().map(|p| (p.public_key.as_str(), p)).collect();

    let mut ops = Vec::new();
    for (key, peer) in &desired_map {
        let unchanged = prev_map.get(key).is_some_and(|prev| {
            as_set(&prev.allowed_ips) == as_set(&peer.allowed_ips) && prev.endpoint == peer.endpoint
        });
        if !unchanged {
            ops.push((key.to_string(), Some((*peer).clone())));
        }
    }
    for key in prev_map.keys() {
        if !desired_map.contains_key(key) {
            ops.push((key.to_string(), None));
        }
    }
    ops
}

/// Applies exactly the peers that changed - unrelated peers keep their live session untouched.
/// No-op if `previous == desired`.
async fn sync_peers(
    awg: &mut AwgClient,
    iface: &str,
    previous: &[Peer],
    desired: &[Peer],
) -> Result<()> {
    let ops = diff_peers(previous, desired);
    if ops.is_empty() {
        return Ok(());
    }

    // Applied independently - one peer with an undecodable public_key or unresolvable endpoint
    // must not block every other peer in the same batch.
    let mut wg_peers = Vec::new();
    for (public_key, peer) in ops {
        let decoded = match decode_key(&public_key) {
            Ok(k) => k,
            Err(e) => {
                tracing::warn!(public_key, error = %e, "skipping peer with undecodable public_key");
                continue;
            }
        };
        match peer {
            Some(peer) => {
                let mut allowed_ips = Vec::new();
                let mut skip = false;
                for cidr in &peer.allowed_ips {
                    match cidr_to_allowed_ip(cidr) {
                        Ok(a) => allowed_ips.push(a),
                        Err(e) => {
                            tracing::warn!(public_key, cidr, error = %e, "skipping peer with malformed allowed_ips entry");
                            skip = true;
                            break;
                        }
                    }
                }
                if skip {
                    continue;
                }
                let mut attrs = vec![
                    AmneziaWireguardPeerAttribute::PublicKey(decoded),
                    AmneziaWireguardPeerAttribute::Flags(WGPEER_F_REPLACE_ALLOWEDIPS),
                    AmneziaWireguardPeerAttribute::AllowedIps(allowed_ips),
                ];
                if let Some(endpoint) = &peer.endpoint {
                    match endpoint.parse::<SocketAddr>() {
                        Ok(addr) => {
                            attrs.push(AmneziaWireguardPeerAttribute::Endpoint(addr));
                            // *Range, not the plain u16 variant: this kernel module's
                            // WGPEER_A_PERSISTENT_KEEPALIVE_INTERVAL policy is NLA_U32 (4 bytes),
                            // not the u16 vanilla WireGuard uses - confirmed against
                            // amneziawg-linux-kernel-module's netlink.c on a real node ("attribute
                            // type 5 has an invalid length" with the plain variant).
                            attrs.push(AmneziaWireguardPeerAttribute::PersistentKeepaliveRange(
                                PERSISTENT_KEEPALIVE_SECS,
                            ));
                        }
                        Err(e) => {
                            tracing::warn!(public_key, endpoint, error = %e, "skipping unparsable resolved endpoint");
                        }
                    }
                }
                wg_peers.push(AmneziaWireguardPeer(attrs));
            }
            None => {
                wg_peers.push(AmneziaWireguardPeer(vec![
                    AmneziaWireguardPeerAttribute::PublicKey(decoded),
                    AmneziaWireguardPeerAttribute::Flags(WGPEER_F_REMOVE_ME),
                ]));
            }
        }
    }

    if wg_peers.is_empty() {
        return Ok(());
    }

    awg.set_device(vec![
        AmneziaWireguardAttribute::IfName(iface.to_string()),
        AmneziaWireguardAttribute::Peers(wg_peers),
    ])
    .await
    .context("SetDevice (peer diff) failed")
}

/// Sets the device's private key, listen port, and obfuscation params. Idempotent and cheap to
/// call unconditionally every run - nothing about identity changes at runtime within one process.
async fn set_identity(awg: &mut AwgClient, iface: &InterfaceEntry) -> Result<()> {
    let mut device_attrs = vec![
        AmneziaWireguardAttribute::IfName(iface.name.clone()),
        AmneziaWireguardAttribute::PrivateKey(decode_key(&iface.private_key)?),
        AmneziaWireguardAttribute::ListenPort(iface.listen_port),
    ];
    push_obfuscation_attrs(&mut device_attrs, &iface.obfuscation);
    awg.set_device(device_attrs)
        .await
        .context("SetDevice (identity) failed")
}

/// Brings one interface fully up to date: link, addresses, identity, and peer set. Safe to call
/// unconditionally on every process start - every step is idempotent.
pub async fn ensure_interface(
    rt: &RtClient,
    awg: &mut AwgClient,
    iface: &InterfaceEntry,
) -> Result<()> {
    let (index, _created) = rt.ensure_link(&iface.name, "amneziawg").await?;
    rt.ensure_addresses(index, &iface.addresses).await?;

    // Without this, a statically assigned address (in particular an IPv6 link-local used for an
    // OSPFv3-style underlay) is dropped every time the interface cycles down/up (e.g. a brief
    // reconnect) - neighbor adjacencies over it would silently stop reforming until the next full
    // reconcile reassigns it. Cheap and harmless to set even for an interface with no IPv6 address
    // at all.
    if !iface.addresses.is_empty()
        && let Err(e) = common::sysctl::write(
            &format!("/proc/sys/net/ipv6/conf/{}/keep_addr_on_down", iface.name),
            "1",
        )
        .await
    {
        tracing::warn!(iface = iface.name, error = %e, "failed to set keep_addr_on_down - an address may be lost on interface flap");
    }

    rt.set_up(index).await?;
    set_identity(awg, iface).await?;

    let previous = current_peers(awg, &iface.name).await?;
    let mut desired = Vec::with_capacity(iface.peers.len());
    for peer in &iface.peers {
        desired.push(resolve_peer(peer).await?);
    }
    desired.sort();

    sync_peers(awg, &iface.name, &previous, &desired).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn peer(public_key: &str, allowed_ips: &[&str], endpoint: Option<&str>) -> Peer {
        Peer {
            public_key: public_key.to_string(),
            allowed_ips: allowed_ips.iter().map(|s| s.to_string()).collect(),
            endpoint: endpoint.map(str::to_string),
        }
    }

    #[test]
    fn identical_sets_produce_no_ops() {
        let a = vec![
            peer("k1", &["10.0.0.1/32"], None),
            peer("k2", &["10.0.0.2/32"], None),
        ];
        assert!(diff_peers(&a, &a).is_empty());
    }

    #[test]
    fn added_peer_yields_replace_op() {
        let previous = vec![peer("k1", &["10.0.0.1/32"], None)];
        let desired = vec![
            peer("k1", &["10.0.0.1/32"], None),
            peer("k2", &["10.0.0.2/32"], None),
        ];
        let ops = diff_peers(&previous, &desired);
        assert_eq!(
            ops,
            vec![("k2".to_string(), Some(peer("k2", &["10.0.0.2/32"], None)))]
        );
    }

    #[test]
    fn removed_peer_yields_remove_op() {
        let previous = vec![
            peer("k1", &["10.0.0.1/32"], None),
            peer("k2", &["10.0.0.2/32"], None),
        ];
        let desired = vec![peer("k1", &["10.0.0.1/32"], None)];
        let ops = diff_peers(&previous, &desired);
        assert_eq!(ops, vec![("k2".to_string(), None)]);
    }

    #[test]
    fn reordered_allowed_ips_produce_no_ops() {
        let previous = vec![peer("k1", &["10.0.0.1/32", "10.0.0.2/32"], None)];
        let desired = vec![peer("k1", &["10.0.0.2/32", "10.0.0.1/32"], None)];
        assert!(diff_peers(&previous, &desired).is_empty());
    }

    #[test]
    fn changed_allowed_ips_yields_replace_op_not_remove_and_add() {
        let previous = vec![peer("k1", &["10.0.0.1/32"], None)];
        let desired = vec![peer("k1", &["10.0.0.99/32"], None)];
        let ops = diff_peers(&previous, &desired);
        assert_eq!(
            ops,
            vec![("k1".to_string(), Some(peer("k1", &["10.0.0.99/32"], None)))]
        );
    }

    #[test]
    fn changed_endpoint_yields_replace_op_even_with_same_allowed_ips() {
        // Real fork from the k8s-daemon original (roadwarriors' diff_peers never had endpoints to
        // compare): a peer whose reachable address changed must get its Endpoint attribute
        // re-applied, not be treated as unchanged because allowed_ips alone didn't move.
        let previous = vec![peer(
            "k1",
            &["0.0.0.0/0", "::/0"],
            Some("203.0.113.1:51820"),
        )];
        let desired = vec![peer(
            "k1",
            &["0.0.0.0/0", "::/0"],
            Some("203.0.113.2:51820"),
        )];
        let ops = diff_peers(&previous, &desired);
        assert_eq!(
            ops,
            vec![(
                "k1".to_string(),
                Some(peer(
                    "k1",
                    &["0.0.0.0/0", "::/0"],
                    Some("203.0.113.2:51820")
                ))
            )]
        );
    }

    #[test]
    fn unrelated_peers_are_never_mentioned() {
        let previous = vec![
            peer("k1", &["10.0.0.1/32"], None),
            peer("k2", &["10.0.0.2/32"], None),
        ];
        let desired = vec![
            peer("k1", &["10.0.0.1/32"], None),
            peer("k2", &["10.0.0.2/32"], None),
            peer("k3", &["10.0.0.3/32"], None),
        ];
        let ops = diff_peers(&previous, &desired);
        assert!(!ops.iter().any(|(k, _)| k == "k1"));
        assert!(!ops.iter().any(|(k, _)| k == "k2"));
        assert_eq!(
            ops,
            vec![("k3".to_string(), Some(peer("k3", &["10.0.0.3/32"], None)))]
        );
    }

    #[test]
    fn full_tunnel_default_is_the_expected_pair() {
        assert_eq!(full_tunnel_allowed_ips(), vec!["0.0.0.0/0", "::/0"]);
    }
}
