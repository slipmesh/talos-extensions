//! Applies one `InterfaceEntry` to the kernel: link/addresses/identity, then a point-wise peer
//! diff against whatever's actually configured (read back from the kernel, not assumed empty -
//! this process gets fully restarted on every config change, so there is no in-memory "previous"
//! to carry over between runs).
//!
//! Ported and merged from slipmesh-operators' `mesh::awg`/`roadwarriors::awg` (same repo,
//! ) - the two were nearly-identical device/peer-attribute-building
//! code with different reconciliation shapes (mesh: exactly one peer, unconditional resend;
//! roadwarriors: many peers, point-wise diff). One shape (point-wise diff) now covers both, since
//! a diff against a single peer degenerates to exactly the same SetDevice call an unconditional
//! resend would have made.

use anyhow::{Context, Result};
use common::netlink::awg::{AwgClient, push_obfuscation_attrs};
use common::netlink::rt::RtClient;
use netlink_packet_amneziawg::AmneziaWireguardRange;
use netlink_packet_amneziawg::{
    AmneziaWireguardAddressFamily, AmneziaWireguardAllowedIp, AmneziaWireguardAllowedIpAttr,
    AmneziaWireguardAttribute, AmneziaWireguardPeer, AmneziaWireguardPeerAttribute,
    AmneziaWireguardPeerFlags,
};
use sliplib_config::awg::{InterfaceEntry, PeerEntry};
use sliplib_secrets::wireguard::{decode_key, encode_key};
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

/// Matches `router/src/resolver.rs`'s own `NETWORK_TIMEOUT` for DNS lookups - same "unreachable
/// resolver, not NXDOMAIN" failure mode, same order-of-magnitude answer for how long to wait
/// before giving up. Without this, a hung `tokio::net::lookup_host` used to block
/// `converge_interface` for that interface forever - and since `main.rs::run()` converges
/// interfaces one at a time, every interface *after* it in the config never converges either, and
/// the process never exits for `restart: always` to get a chance to retry it.
const ENDPOINT_RESOLVE_TIMEOUT: Duration = Duration::from_secs(15);

const PERSISTENT_KEEPALIVE_SECS: u16 = 25;

fn full_tunnel_allowed_ips() -> Vec<String> {
    vec!["0.0.0.0/0".to_string(), "::/0".to_string()]
}

/// One peer, resolved to exactly what the kernel needs - `allowed_ips` is always concrete (the
/// full-tunnel default if the config entry left it unset) and `endpoint` is already DNS-resolved.
/// Whether this peer is handshake-tracked (see `handshake.rs`) is a separate question, answered by
/// the *config* entry's `allowed_ips: Option<_>` being `Some` - not encoded here.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Peer {
    pub public_key: String,
    pub allowed_ips: Vec<String>,
    pub endpoint: Option<String>,
    /// As the module holds it: it draws the interval out of the range at every re-arm. The zero
    /// range is no keepalive.
    pub persistent_keepalive: AmneziaWireguardRange<u16>,
}

/// A peer this node dials gets a keepalive, so that a NAT on the way keeps its mapping.
fn persistent_keepalive(endpoint: Option<&str>) -> AmneziaWireguardRange<u16> {
    match endpoint {
        Some(_) => AmneziaWireguardRange::from(PERSISTENT_KEEPALIVE_SECS),
        None => AmneziaWireguardRange::default(),
    }
}

/// `existing` as the kernel holds it, for a peer whose endpoint could not be resolved this pass.
/// Its keepalive is the one `entry` calls for, whatever the kernel holds: the kernel may have no
/// endpoint for the peer yet.
fn last_known_good(existing: &Peer, entry: &PeerEntry) -> Peer {
    Peer {
        persistent_keepalive: persistent_keepalive(entry.endpoint.as_deref()),
        ..existing.clone()
    }
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
        persistent_keepalive: persistent_keepalive(endpoint.as_deref()),
        endpoint,
    })
}

async fn resolve_endpoint(host_port: &str) -> Result<String> {
    let mut addrs = tokio::time::timeout(
        ENDPOINT_RESOLVE_TIMEOUT,
        tokio::net::lookup_host(host_port),
    )
    .await
    .with_context(|| {
        format!("resolving endpoint {host_port:?} exceeded its {ENDPOINT_RESOLVE_TIMEOUT:?} budget")
    })?
    .with_context(|| format!("failed to resolve endpoint {host_port:?}"))?;
    let addr: SocketAddr = addrs
        .next()
        .with_context(|| format!("no addresses found for endpoint {host_port:?}"))?;
    Ok(addr.to_string())
}

fn cidr_to_allowed_ip(cidr: &str) -> Result<AmneziaWireguardAllowedIp> {
    let net = sliplib_net::parse(cidr)?;
    let (addr, prefix) = (net.addr(), net.prefix_len());
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

fn peer_from_attrs(attrs: Vec<AmneziaWireguardPeerAttribute>) -> Option<Peer> {
    let mut public_key = None;
    let mut allowed_ips = Vec::new();
    let mut endpoint = None;
    let mut persistent_keepalive = AmneziaWireguardRange::default();
    for attr in attrs {
        match attr {
            AmneziaWireguardPeerAttribute::PersistentKeepalive(range) => {
                persistent_keepalive = range;
            }
            AmneziaWireguardPeerAttribute::PublicKey(k) => {
                public_key = Some(encode_key(&k));
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
    Some(Peer {
        public_key: public_key?,
        allowed_ips,
        endpoint,
        persistent_keepalive,
    })
}

/// Reads back the peer set actually configured on the kernel interface. Always called, never
/// assumed empty - see this module's doc comment for why (no in-memory state survives a restart).
pub async fn current_peers(awg: &mut AwgClient, iface: &str) -> Result<Vec<Peer>> {
    let attrs = awg.get_device(iface).await?;
    let mut peers = Vec::new();
    for attr in attrs {
        let AmneziaWireguardAttribute::Peers(device_peers) = attr else {
            continue;
        };
        peers.extend(
            device_peers
                .into_iter()
                .filter_map(|peer| peer_from_attrs(peer.0)),
        );
    }
    peers.sort_by(|a, b| a.public_key.cmp(&b.public_key));
    Ok(peers)
}

/// One entry per peer that needs to change: `Some(peer)` to add/replace, `None` to remove.
/// `previous`/`desired` need not be pre-sorted - keyed by `public_key` internally.
///
/// A peer counts as unchanged only if `allowed_ips` (compared as a set - CIDR order is not
/// semantically meaningful to WireGuard), `endpoint` and the keepalive all match; any of
/// them changing means the peer gets re-sent with `WGPEER_F_REPLACE_ALLOWEDIPS`.
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
            as_set(&prev.allowed_ips) == as_set(&peer.allowed_ips)
                && prev.endpoint == peer.endpoint
                && prev.persistent_keepalive == peer.persistent_keepalive
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

/// The attributes that add `peer` or replace what the kernel holds for it.
fn replace_peer_attrs(
    public_key: [u8; 32],
    peer: &Peer,
) -> Result<Vec<AmneziaWireguardPeerAttribute>> {
    let allowed_ips = peer
        .allowed_ips
        .iter()
        .map(|cidr| {
            cidr_to_allowed_ip(cidr)
                .with_context(|| format!("malformed allowed_ips entry {cidr:?}"))
        })
        .collect::<Result<Vec<_>>>()?;
    let mut attrs = vec![
        AmneziaWireguardPeerAttribute::PublicKey(public_key),
        AmneziaWireguardPeerAttribute::Flags(AmneziaWireguardPeerFlags::ReplaceAllowedIps),
        AmneziaWireguardPeerAttribute::AllowedIps(allowed_ips),
    ];
    if let Some(endpoint) = &peer.endpoint {
        let addr: SocketAddr = endpoint
            .parse()
            .with_context(|| format!("unparsable resolved endpoint {endpoint:?}"))?;
        attrs.push(AmneziaWireguardPeerAttribute::Endpoint(addr));
    }
    // Sent even when zero: an omitted attribute keeps what the kernel holds.
    attrs.push(AmneziaWireguardPeerAttribute::PersistentKeepalive(
        peer.persistent_keepalive,
    ));
    Ok(attrs)
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
            Some(peer) => match replace_peer_attrs(decoded, &peer) {
                Ok(attrs) => wg_peers.push(AmneziaWireguardPeer(attrs)),
                Err(e) => {
                    tracing::warn!(public_key, error = %format_args!("{e:#}"), "skipping peer")
                }
            },
            None => {
                wg_peers.push(AmneziaWireguardPeer(vec![
                    AmneziaWireguardPeerAttribute::PublicKey(decoded),
                    AmneziaWireguardPeerAttribute::Flags(AmneziaWireguardPeerFlags::RemoveMe),
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

/// The device's private key, listen port and obfuscation params as the kernel is sent them.
fn identity_attrs(iface: &InterfaceEntry) -> Result<Vec<AmneziaWireguardAttribute>> {
    let mut device_attrs = vec![
        AmneziaWireguardAttribute::IfName(iface.name.clone()),
        AmneziaWireguardAttribute::PrivateKey(
            decode_key(iface.private_key.expose())
                .map_err(|e| anyhow::anyhow!("invalid private_key: {e}"))?,
        ),
        AmneziaWireguardAttribute::ListenPort(iface.listen_port),
    ];
    push_obfuscation_attrs(&mut device_attrs, &iface.obfuscation)?;
    Ok(device_attrs)
}

/// What `iface`'s identity is set with, or why the module would refuse or mishandle it, the
/// interface named. It needs no kernel, so that such an interface is refused before it is
/// touched.
fn check(iface: &InterfaceEntry) -> Result<Vec<AmneziaWireguardAttribute>> {
    iface
        .obfuscation
        .validate()
        .map_err(anyhow::Error::new)
        .and_then(|()| identity_attrs(iface))
        .with_context(|| format!("interface {}", iface.name))
}

/// Sets the device's private key, listen port, and obfuscation params. Idempotent and cheap to
/// call unconditionally every run - nothing about identity changes at runtime within one process.
async fn set_identity(awg: &mut AwgClient, identity: Vec<AmneziaWireguardAttribute>) -> Result<()> {
    awg.set_device(identity)
        .await
        .context("SetDevice (identity) failed")
}

/// Brings one interface fully up to date: link, addresses, identity, and peer set. An interface
/// `check` refuses is refused first, with nothing of it touched. Safe to call unconditionally on
/// every process start - every step is idempotent.
pub async fn ensure_interface(
    rt: &RtClient,
    awg: &mut AwgClient,
    iface: &InterfaceEntry,
) -> Result<()> {
    let identity = check(iface)?;
    let (index, _created) = rt.ensure_link(&iface.name, "amneziawg").await?;
    rt.ensure_addresses(index, &iface.addresses).await?;
    if let Some(mtu) = iface.mtu {
        rt.set_mtu(index, mtu).await?;
    }

    // A statically assigned address (in particular an IPv6 link-local used for an OSPFv3-style
    // underlay) would otherwise be dropped every time the interface cycles down/up (e.g. a brief
    // reconnect). Not handled here: writing `net.ipv6.conf.<iface>.keep_addr_on_down` from inside
    // this process failed on a real node (container lacked permission to write /proc/sys, and the
    // interface doesn't exist yet at boot for Talos's own `machine.sysctls` to apply it directly
    // either). Instead, set `net.ipv6.conf.default.keep_addr_on_down: "1"` once in the node's
    // `machine.sysctls` - the kernel copies `ipv6_devconf_dflt` into every interface's devconf at
    // creation time (confirmed against net/ipv6/addrconf.c), so it applies to `mesh-*`/etc.
    // interfaces this daemon creates later, with no code here needed at all.

    rt.set_up(index).await?;
    set_identity(awg, identity).await?;

    let previous = current_peers(awg, &iface.name).await?;
    let mut desired = Vec::with_capacity(iface.peers.len());
    for peer in &iface.peers {
        // One peer's transient DNS failure must not block every other peer on this interface -
        // the same guarantee `sync_peers` itself documents for its own per-peer apply loop, which
        // a bare `?` here used to defeat before `sync_peers` was ever reached. Falling back to
        // this peer's already-live state (if any) rather than dropping it from `desired` matters:
        // dropping it would make `diff_peers` see a "removed" peer and tear down its live session
        // over what might be a one-off resolver hiccup, not an actual config change.
        match resolve_peer(peer).await {
            Ok(resolved) => desired.push(resolved),
            Err(e) => match previous.iter().find(|p| p.public_key == peer.public_key) {
                Some(existing) => {
                    tracing::warn!(
                        interface = %iface.name, peer = %peer.public_key, error = %e,
                        "failed to resolve peer, keeping its last-known-good state this pass"
                    );
                    desired.push(last_known_good(existing, peer));
                }
                None => tracing::warn!(
                    interface = %iface.name, peer = %peer.public_key, error = %e,
                    "failed to resolve new peer with no previous state, skipping it this pass"
                ),
            },
        }
    }
    desired.sort_by(|a, b| a.public_key.cmp(&b.public_key));

    sync_peers(awg, &iface.name, &previous, &desired).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use sliplib_config::Obfuscation;

    fn peer(public_key: &str, allowed_ips: &[&str], endpoint: Option<&str>) -> Peer {
        Peer {
            public_key: public_key.to_string(),
            allowed_ips: allowed_ips.iter().map(|s| s.to_string()).collect(),
            endpoint: endpoint.map(str::to_string),
            persistent_keepalive: persistent_keepalive(endpoint),
        }
    }

    #[test]
    fn identical_sets_produce_no_ops() {
        let a = vec![
            peer("k1", &["203.0.113.1/32"], None),
            peer("k2", &["203.0.113.2/32"], None),
        ];
        assert!(diff_peers(&a, &a).is_empty());
    }

    #[test]
    fn added_peer_yields_replace_op() {
        let previous = vec![peer("k1", &["203.0.113.1/32"], None)];
        let desired = vec![
            peer("k1", &["203.0.113.1/32"], None),
            peer("k2", &["203.0.113.2/32"], None),
        ];
        let ops = diff_peers(&previous, &desired);
        assert_eq!(
            ops,
            vec![(
                "k2".to_string(),
                Some(peer("k2", &["203.0.113.2/32"], None))
            )]
        );
    }

    #[test]
    fn removed_peer_yields_remove_op() {
        let previous = vec![
            peer("k1", &["203.0.113.1/32"], None),
            peer("k2", &["203.0.113.2/32"], None),
        ];
        let desired = vec![peer("k1", &["203.0.113.1/32"], None)];
        let ops = diff_peers(&previous, &desired);
        assert_eq!(ops, vec![("k2".to_string(), None)]);
    }

    #[test]
    fn reordered_allowed_ips_produce_no_ops() {
        let previous = vec![peer("k1", &["203.0.113.1/32", "203.0.113.2/32"], None)];
        let desired = vec![peer("k1", &["203.0.113.2/32", "203.0.113.1/32"], None)];
        assert!(diff_peers(&previous, &desired).is_empty());
    }

    #[test]
    fn changed_allowed_ips_yields_replace_op_not_remove_and_add() {
        let previous = vec![peer("k1", &["203.0.113.1/32"], None)];
        let desired = vec![peer("k1", &["203.0.113.29/32"], None)];
        let ops = diff_peers(&previous, &desired);
        assert_eq!(
            ops,
            vec![(
                "k1".to_string(),
                Some(peer("k1", &["203.0.113.29/32"], None))
            )]
        );
    }

    #[test]
    fn changed_endpoint_yields_replace_op_even_with_same_allowed_ips() {
        // Real fork from the k8s-daemon original (roadwarriors' diff_peers never had endpoints to
        // compare): a peer whose reachable address changed must get its Endpoint attribute
        // re-applied, not be treated as unchanged because allowed_ips alone didn't move.
        let previous = vec![peer("k1", &["0.0.0.0/0", "::/0"], Some("192.0.2.1:51820"))];
        let desired = vec![peer("k1", &["0.0.0.0/0", "::/0"], Some("192.0.2.2:51820"))];
        let ops = diff_peers(&previous, &desired);
        assert_eq!(
            ops,
            vec![(
                "k1".to_string(),
                Some(peer("k1", &["0.0.0.0/0", "::/0"], Some("192.0.2.2:51820")))
            )]
        );
    }

    #[test]
    fn unrelated_peers_are_never_mentioned() {
        let previous = vec![
            peer("k1", &["203.0.113.1/32"], None),
            peer("k2", &["203.0.113.2/32"], None),
        ];
        let desired = vec![
            peer("k1", &["203.0.113.1/32"], None),
            peer("k2", &["203.0.113.2/32"], None),
            peer("k3", &["203.0.113.3/32"], None),
        ];
        let ops = diff_peers(&previous, &desired);
        assert!(!ops.iter().any(|(k, _)| k == "k1"));
        assert!(!ops.iter().any(|(k, _)| k == "k2"));
        assert_eq!(
            ops,
            vec![(
                "k3".to_string(),
                Some(peer("k3", &["203.0.113.3/32"], None))
            )]
        );
    }

    const KEY: [u8; 32] = [7; 32];
    const KEEPALIVE: AmneziaWireguardRange<u16> = AmneziaWireguardRange { lo: 25, hi: 25 };
    /// What a number of seconds sent in place of a range left in the module.
    const BARE_25: AmneziaWireguardRange<u16> = AmneziaWireguardRange { lo: 25, hi: 0 };

    fn keepalive_sent(peer: &Peer) -> Option<AmneziaWireguardRange<u16>> {
        replace_peer_attrs(KEY, peer)
            .unwrap()
            .into_iter()
            .find_map(|attr| match attr {
                AmneziaWireguardPeerAttribute::PersistentKeepalive(v) => Some(v),
                _ => None,
            })
    }

    #[test]
    fn a_peer_with_an_endpoint_is_sent_its_keepalive_as_a_range_of_one_value() {
        let peer = peer("k1", &["0.0.0.0/0"], Some("192.0.2.1:51820"));
        assert_eq!(keepalive_sent(&peer), Some(KEEPALIVE));
    }

    // Sent rather than left out: an omitted attribute keeps what the kernel holds.
    #[test]
    fn a_peer_without_an_endpoint_is_sent_a_zero_keepalive() {
        let peer = peer("k1", &["203.0.113.1/32"], None);
        assert_eq!(
            keepalive_sent(&peer),
            Some(AmneziaWireguardRange::default())
        );
    }

    #[test]
    fn a_replaced_peer_carries_its_key_its_allowed_ips_and_its_endpoint() {
        let attrs = replace_peer_attrs(
            KEY,
            &peer("k1", &["203.0.113.1/32"], Some("192.0.2.1:51820")),
        )
        .unwrap();
        assert!(attrs.contains(&AmneziaWireguardPeerAttribute::PublicKey(KEY)));
        assert!(attrs.contains(&AmneziaWireguardPeerAttribute::Flags(
            AmneziaWireguardPeerFlags::ReplaceAllowedIps
        )));
        assert!(
            attrs.contains(&AmneziaWireguardPeerAttribute::AllowedIps(vec![
                cidr_to_allowed_ip("203.0.113.1/32").unwrap()
            ]))
        );
        assert!(attrs.contains(&AmneziaWireguardPeerAttribute::Endpoint(
            "192.0.2.1:51820".parse().unwrap()
        )));
    }

    #[test]
    fn a_malformed_allowed_ip_refuses_the_peer_and_names_the_entry() {
        let err = replace_peer_attrs(KEY, &peer("k1", &["203.0.113.1/32", "not-a-cidr"], None))
            .unwrap_err()
            .to_string();
        assert!(err.contains("not-a-cidr"), "{err}");
    }

    #[test]
    fn an_unparsable_endpoint_refuses_the_peer_and_names_it() {
        let err = replace_peer_attrs(KEY, &peer("k1", &["203.0.113.1/32"], Some("node-b:51820")))
            .unwrap_err()
            .to_string();
        assert!(err.contains("node-b:51820"), "{err}");
    }

    #[test]
    fn a_peer_is_read_back_with_its_key_allowed_ips_endpoint_and_keepalive() {
        let read = peer_from_attrs(vec![
            AmneziaWireguardPeerAttribute::PublicKey(KEY),
            AmneziaWireguardPeerAttribute::AllowedIps(vec![
                cidr_to_allowed_ip("203.0.113.1/32").unwrap(),
            ]),
            AmneziaWireguardPeerAttribute::Endpoint("192.0.2.1:51820".parse().unwrap()),
            AmneziaWireguardPeerAttribute::PersistentKeepalive(BARE_25),
        ])
        .unwrap();
        assert_eq!(
            read,
            Peer {
                persistent_keepalive: BARE_25,
                ..peer(
                    &encode_key(&KEY),
                    &["203.0.113.1/32"],
                    Some("192.0.2.1:51820")
                )
            }
        );
    }

    #[test]
    fn attributes_without_a_public_key_are_not_a_peer() {
        assert_eq!(
            peer_from_attrs(vec![AmneziaWireguardPeerAttribute::PersistentKeepalive(
                KEEPALIVE
            )]),
            None
        );
    }

    #[test]
    fn a_keepalive_held_as_a_bare_number_yields_replace_op() {
        let desired = peer("k1", &["0.0.0.0/0"], Some("192.0.2.1:51820"));
        let held = Peer {
            persistent_keepalive: BARE_25,
            ..desired.clone()
        };
        assert_eq!(
            diff_peers(&[held], std::slice::from_ref(&desired)),
            vec![("k1".to_string(), Some(desired))]
        );
    }

    fn entry(endpoint: Option<&str>) -> PeerEntry {
        PeerEntry {
            public_key: "k1".to_string(),
            name: None,
            endpoint: endpoint.map(str::to_string),
            allowed_ips: None,
        }
    }

    #[test]
    fn a_peer_kept_through_a_failed_lookup_gets_the_keepalive_its_entry_calls_for() {
        let held = Peer {
            persistent_keepalive: BARE_25,
            ..peer("k1", &["0.0.0.0/0"], Some("192.0.2.1:51820"))
        };
        assert_eq!(
            last_known_good(&held, &entry(Some("node-b.example.net:51820"))),
            peer("k1", &["0.0.0.0/0"], Some("192.0.2.1:51820"))
        );
    }

    // A lookup fails only for an entry that has an endpoint, and the kernel may hold none for
    // that peer yet.
    #[test]
    fn a_peer_the_kernel_holds_without_an_endpoint_is_kept_with_its_entrys_keepalive() {
        let held = peer("k1", &["0.0.0.0/0"], None);
        assert_eq!(
            last_known_good(&held, &entry(Some("node-b.example.net:51820"))),
            Peer {
                persistent_keepalive: KEEPALIVE,
                ..held.clone()
            }
        );
    }

    fn interface(name: &str, obfuscation: Obfuscation) -> InterfaceEntry {
        InterfaceEntry {
            name: name.to_string(),
            listen_port: 51820,
            addresses: vec![],
            private_key: encode_key(&KEY).as_str().into(),
            obfuscation,
            handshake_stale_secs: None,
            mtu: None,
            peers: vec![],
        }
    }

    #[test]
    fn an_interface_the_kernel_cannot_be_sent_is_refused_by_name() {
        assert!(check(&interface("awg-a", Obfuscation::default())).is_ok());
        let undecodable = Obfuscation {
            header_protection_key: Some("not a key".into()),
            s1: Some(12),
            s2: Some(12),
            s3: Some(12),
            s4: Some(12),
            ..Obfuscation::default()
        };
        let shown = format!("{:#}", check(&interface("awg-b", undecodable)).unwrap_err());
        assert!(
            shown.starts_with("interface awg-b: invalid header_protection_key"),
            "{shown}"
        );
    }

    // The module refuses this only at `SetDevice`, once the link exists.
    #[test]
    fn an_interface_whose_obfuscation_the_module_refuses_is_refused_by_name() {
        let overlapping = Obfuscation {
            h1: Some(5.into()),
            h2: Some(5.into()),
            ..Obfuscation::default()
        };
        let shown = format!("{:#}", check(&interface("awg-b", overlapping)).unwrap_err());
        assert!(
            shown.starts_with("interface awg-b: obfuscation.h1 (5) and obfuscation.h2 (5)"),
            "{shown}"
        );
    }

    #[test]
    fn an_interface_with_a_timing_value_the_module_misuses_is_refused_by_name() {
        let too_late = Obfuscation {
            rekey_after_time: Some(180.into()),
            ..Obfuscation::default()
        };
        let shown = format!("{:#}", check(&interface("awg-b", too_late)).unwrap_err());
        assert!(
            shown.starts_with("interface awg-b: obfuscation.rekey_after_time (180)"),
            "{shown}"
        );
    }

    #[test]
    fn an_interface_with_an_undecodable_private_key_is_refused_by_its_name() {
        let mut iface = interface("awg-b", Obfuscation::default());
        iface.private_key = "not a key".into();
        let shown = format!("{:#}", check(&iface).unwrap_err());
        assert!(
            shown.starts_with("interface awg-b: invalid private_key"),
            "{shown}"
        );
        // The logged chain would otherwise show a character of the configured text and where.
        assert!(!shown.contains("offset"), "{shown}");
    }

    #[test]
    fn what_the_identity_of_an_interface_is_set_with_is_its_name_key_port_and_obfuscation() {
        let obfuscation = Obfuscation {
            jc: Some(4),
            ..Obfuscation::default()
        };
        let mut expected = vec![
            AmneziaWireguardAttribute::IfName("awg-a".to_string()),
            AmneziaWireguardAttribute::PrivateKey(KEY),
            AmneziaWireguardAttribute::ListenPort(51820),
        ];
        push_obfuscation_attrs(&mut expected, &obfuscation).unwrap();
        assert!(expected.contains(&AmneziaWireguardAttribute::Jc(4)));
        assert_eq!(check(&interface("awg-a", obfuscation)).unwrap(), expected);
    }

    #[test]
    fn full_tunnel_default_is_the_expected_pair() {
        assert_eq!(full_tunnel_allowed_ips(), vec!["0.0.0.0/0", "::/0"]);
    }
}
