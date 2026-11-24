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
use common::netlink::awg::{AwgClient, push_obfuscation_attrs, wire};
use common::netlink::rt::RtClient;
use netlink_packet_amneziawg::AmneziaWireguardRange;
use netlink_packet_amneziawg::{
    AmneziaWireguardAddressFamily, AmneziaWireguardAllowedIp, AmneziaWireguardAllowedIpAttr,
    AmneziaWireguardAttribute, AmneziaWireguardPeer, AmneziaWireguardPeerAttribute,
    AmneziaWireguardPeerFlags,
};
use sliplib_config::awg::{InterfaceEntry, PeerEntry};
use sliplib_net::IpNet;
use sliplib_secrets::wireguard::decode_key;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

/// Matches `router/src/resolver.rs`'s own `NETWORK_TIMEOUT` for DNS lookups - same "unreachable
/// resolver, not NXDOMAIN" failure mode, same order-of-magnitude answer for how long to wait
/// before giving up. Without this, a hung `tokio::net::lookup_host` used to block
/// `converge_interface` for that interface forever - and since `main.rs::run()` converges
/// interfaces one at a time, every interface *after* it in the config never converges either, and
/// the process never exits for `restart: always` to get a chance to retry it.
const ENDPOINT_RESOLVE_TIMEOUT: Duration = Duration::from_secs(15);

/// One peer, resolved to exactly what the kernel needs - `allowed_ips` is always concrete (the
/// full-tunnel default if the config entry left it unset) and `endpoint` is already DNS-resolved.
/// Whether this peer is handshake-tracked (see `handshake.rs`) is a separate question, answered by
/// the *config* entry's `allowed_ips: Option<_>` being `Some` - not encoded here.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Peer {
    pub public_key: String,
    pub allowed_ips: Vec<IpNet>,
    pub endpoint: Option<String>,
    /// As the module holds it: it draws the interval out of the range at every re-arm. The zero
    /// range is no keepalive.
    pub persistent_keepalive: AmneziaWireguardRange<u16>,
}

/// What `peer`, one of `iface`'s, is sent as its keepalive: what the interface's entry gives
/// for it, as the module takes it. After that long a silence the peer is sent a packet, so that
/// a NAT on the way keeps its mapping; `0` sends none.
fn keepalive_to_send(iface: &InterfaceEntry, peer: &PeerEntry) -> AmneziaWireguardRange<u16> {
    wire(iface.keepalive_of(peer))
}

/// `existing` as the kernel holds it, for a peer whose endpoint could not be resolved this pass.
/// Its keepalive is `keepalive`, the one called for, whatever the kernel holds: the kernel may
/// have no endpoint for the peer yet.
fn last_known_good(existing: &Peer, keepalive: AmneziaWireguardRange<u16>) -> Peer {
    Peer {
        persistent_keepalive: keepalive,
        ..existing.clone()
    }
}

async fn resolve_peer(entry: &PeerEntry, keepalive: AmneziaWireguardRange<u16>) -> Result<Peer> {
    let allowed_ips = entry
        .allowed_ips_or_all()
        .into_iter()
        .map(|prefix| prefix.0)
        .collect();
    let endpoint = match &entry.endpoint {
        Some(host_port) => Some(resolve_endpoint(host_port).await?),
        None => None,
    };
    Ok(Peer {
        public_key: entry.public_key.clone(),
        allowed_ips,
        persistent_keepalive: keepalive,
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

fn allowed_ip(net: IpNet) -> AmneziaWireguardAllowedIp {
    let (addr, prefix) = (net.addr(), net.prefix_len());
    let family = match addr {
        IpAddr::V4(_) => AmneziaWireguardAddressFamily::Ipv4,
        IpAddr::V6(_) => AmneziaWireguardAddressFamily::Ipv6,
    };
    AmneziaWireguardAllowedIp(vec![
        AmneziaWireguardAllowedIpAttr::Family(family),
        AmneziaWireguardAllowedIpAttr::IpAddr(addr),
        AmneziaWireguardAllowedIpAttr::Cidr(prefix),
    ])
}

/// Reads back the peer set actually configured on the kernel interface. Always called, never
/// assumed empty - see this module's doc comment for why (no in-memory state survives a restart).
pub async fn current_peers(awg: &mut AwgClient, iface: &str) -> Result<Vec<Peer>> {
    Ok(dumped_peers(&awg.get_device(iface).await?))
}

fn dumped_peers(attrs: &[AmneziaWireguardAttribute]) -> Vec<Peer> {
    crate::dump::peers(attrs)
        .into_values()
        .map(|dumped| dumped.peer)
        .collect()
}

/// One entry per peer that needs to change: `Some(peer)` to add/replace, `None` to remove.
/// `previous`/`desired` need not be pre-sorted - keyed by `public_key` internally.
///
/// A peer counts as unchanged only if `allowed_ips` (compared as a set - CIDR order is not
/// semantically meaningful to WireGuard), `endpoint` and the keepalive all match; any of
/// them changing means the peer gets re-sent with `WGPEER_F_REPLACE_ALLOWEDIPS`.
fn diff_peers(previous: &[Peer], desired: &[Peer]) -> Vec<(String, Option<Peer>)> {
    use std::collections::{BTreeMap, BTreeSet};

    fn as_set(ips: &[IpNet]) -> BTreeSet<&IpNet> {
        ips.iter().collect()
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
    let allowed_ips = peer.allowed_ips.iter().copied().map(allowed_ip).collect();
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
    let addresses: Vec<IpNet> = iface.addresses.iter().map(|prefix| prefix.0).collect();
    rt.ensure_addresses(index, &addresses).await?;
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
        let keepalive = keepalive_to_send(iface, peer);
        match resolve_peer(peer, keepalive).await {
            Ok(resolved) => desired.push(resolved),
            Err(e) => match previous.iter().find(|p| p.public_key == peer.public_key) {
                Some(existing) => {
                    tracing::warn!(
                        interface = %iface.name, peer = %peer.public_key, error = %e,
                        "failed to resolve peer, keeping its last-known-good state this pass"
                    );
                    desired.push(last_known_good(existing, keepalive));
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
    use sliplib_config::awg::{NO_KEEPALIVE, OBFUSCATED_KEEPALIVE, PLAIN_KEEPALIVE};
    use sliplib_config::{Obfuscation, Range};
    use sliplib_secrets::wireguard::encode_key;

    /// A peer as the kernel holds it on an interface that sets nothing of the obfuscation: 25 if
    /// it is dialed, none if it is only waited for.
    fn peer(public_key: &str, allowed_ips: &[&str], endpoint: Option<&str>) -> Peer {
        Peer {
            public_key: public_key.to_string(),
            allowed_ips: allowed_ips.iter().map(|s| s.parse().unwrap()).collect(),
            endpoint: endpoint.map(str::to_string),
            persistent_keepalive: wire(match endpoint {
                Some(_) => PLAIN_KEEPALIVE,
                None => NO_KEEPALIVE,
            }),
        }
    }

    #[test]
    fn a_peer_is_replaced_where_it_differs_removed_where_undesired_and_otherwise_left() {
        let held = Peer {
            persistent_keepalive: wire(OBFUSCATED_KEEPALIVE),
            ..peer("k1", &["0.0.0.0/0"], Some("192.0.2.1:51820"))
        };
        let k1 = peer("k1", &["203.0.113.1/32"], None);
        let k2 = peer("k2", &["203.0.113.2/32"], None);
        let k3 = peer("k3", &["203.0.113.3/32"], None);
        let at_29 = peer("k1", &["203.0.113.29/32"], None);
        let at_2 = peer("k1", &["0.0.0.0/0", "::/0"], Some("192.0.2.2:51820"));
        let replace = |p: &Peer| (p.public_key.clone(), Some(p.clone()));
        let cases = [
            (vec![held.clone()], vec![held.clone()], vec![]),
            // What a node upgraded from a release that sent 25 sees once, on an obfuscated link.
            (
                vec![peer("k1", &["0.0.0.0/0"], Some("192.0.2.1:51820"))],
                vec![held.clone()],
                vec![replace(&held)],
            ),
            (
                vec![k1.clone(), k2.clone()],
                vec![k1.clone()],
                vec![("k2".to_string(), None)],
            ),
            (
                vec![peer("k1", &["203.0.113.1/32", "203.0.113.2/32"], None)],
                vec![peer("k1", &["203.0.113.2/32", "203.0.113.1/32"], None)],
                vec![],
            ),
            (vec![k1.clone()], vec![at_29.clone()], vec![replace(&at_29)]),
            // Its endpoint changed and its allowed IPs did not: the endpoint is sent again.
            (
                vec![peer("k1", &["0.0.0.0/0", "::/0"], Some("192.0.2.1:51820"))],
                vec![at_2.clone()],
                vec![replace(&at_2)],
            ),
            (
                vec![k1.clone(), k2.clone()],
                vec![k1, k2, k3.clone()],
                vec![replace(&k3)],
            ),
        ];
        for (previous, desired, ops) in cases {
            assert_eq!(diff_peers(&previous, &desired), ops, "{desired:?}");
        }
    }

    const KEY: [u8; 32] = [7; 32];
    const KEEPALIVE: AmneziaWireguardRange<u16> = AmneziaWireguardRange { lo: 25, hi: 25 };
    /// What a number of seconds sent in place of a range left in the module.
    const BARE_25: AmneziaWireguardRange<u16> = AmneziaWireguardRange { lo: 25, hi: 0 };

    #[test]
    fn a_replaced_peer_carries_its_key_its_allowed_ips_its_endpoint_and_its_keepalive() {
        let head = |ip: &str| {
            vec![
                AmneziaWireguardPeerAttribute::PublicKey(KEY),
                AmneziaWireguardPeerAttribute::Flags(AmneziaWireguardPeerFlags::ReplaceAllowedIps),
                AmneziaWireguardPeerAttribute::AllowedIps(vec![allowed_ip(ip.parse().unwrap())]),
            ]
        };
        let dialed = [
            head("203.0.113.1/32"),
            vec![
                AmneziaWireguardPeerAttribute::Endpoint("192.0.2.1:51820".parse().unwrap()),
                AmneziaWireguardPeerAttribute::PersistentKeepalive(KEEPALIVE),
            ],
        ]
        .concat();
        let waited_for = [
            head("203.0.113.1/32"),
            vec![AmneziaWireguardPeerAttribute::PersistentKeepalive(
                AmneziaWireguardRange::default(),
            )],
        ]
        .concat();
        for (peer, attrs) in [
            (
                peer("k1", &["203.0.113.1/32"], Some("192.0.2.1:51820")),
                dialed,
            ),
            (peer("k1", &["203.0.113.1/32"], None), waited_for),
        ] {
            assert_eq!(replace_peer_attrs(KEY, &peer).unwrap(), attrs);
        }
    }

    #[test]
    fn a_peer_is_sent_what_its_interface_entry_gives_for_it() {
        const DIALED: Option<&str> = Some("node-b.example.net:51820");
        let plain = interface("mesh-a", Obfuscation::default());
        let obfuscated = interface(
            "mesh-a",
            Obfuscation {
                jc: Some(4),
                ..Obfuscation::default()
            },
        );
        let with = |endpoint, own: Option<Range<u16>>| PeerEntry {
            persistent_keepalive: own,
            ..entry(endpoint)
        };
        let none = AmneziaWireguardRange::default();
        for (iface, peer, sent) in [
            (
                &plain,
                with(DIALED, None),
                AmneziaWireguardRange { lo: 25, hi: 25 },
            ),
            (
                &obfuscated,
                with(DIALED, None),
                AmneziaWireguardRange { lo: 20, hi: 30 },
            ),
            (
                &obfuscated,
                with(DIALED, Some(Range::from(7))),
                AmneziaWireguardRange { lo: 7, hi: 7 },
            ),
            (&plain, with(DIALED, Some(Range::from(0))), none),
            (&obfuscated, with(None, None), none),
            (&plain, with(None, Some(Range::from(7))), none),
        ] {
            assert_eq!(keepalive_to_send(iface, &peer), sent, "{peer:?}");
        }
    }

    #[test]
    fn an_unparsable_endpoint_refuses_the_peer_and_names_it() {
        let err = replace_peer_attrs(KEY, &peer("k1", &["203.0.113.1/32"], Some("node-b:51820")))
            .unwrap_err()
            .to_string();
        assert!(err.contains("node-b:51820"), "{err}");
    }

    #[test]
    fn a_peer_the_dump_splits_over_two_pieces_reads_whole_and_compares_unchanged() {
        let desired = Peer {
            persistent_keepalive: BARE_25,
            ..peer(
                &encode_key(&KEY),
                &["203.0.113.1/32", "203.0.113.2/32"],
                Some("192.0.2.1:51820"),
            )
        };
        let dump = vec![
            AmneziaWireguardAttribute::Peers(vec![AmneziaWireguardPeer(vec![
                AmneziaWireguardPeerAttribute::PublicKey(KEY),
                AmneziaWireguardPeerAttribute::Endpoint("192.0.2.1:51820".parse().unwrap()),
                AmneziaWireguardPeerAttribute::PersistentKeepalive(BARE_25),
                AmneziaWireguardPeerAttribute::AllowedIps(vec![allowed_ip(
                    "203.0.113.1/32".parse().unwrap(),
                )]),
            ])]),
            AmneziaWireguardAttribute::Peers(vec![AmneziaWireguardPeer(vec![
                AmneziaWireguardPeerAttribute::PublicKey(KEY),
                AmneziaWireguardPeerAttribute::AllowedIps(vec![allowed_ip(
                    "203.0.113.2/32".parse().unwrap(),
                )]),
            ])]),
        ];
        let held = dumped_peers(&dump);
        assert_eq!(held, std::slice::from_ref(&desired));
        assert_eq!(diff_peers(&held, &[desired]), vec![]);
    }

    fn entry(endpoint: Option<&str>) -> PeerEntry {
        PeerEntry {
            public_key: "k1".to_string(),
            name: None,
            endpoint: endpoint.map(str::to_string),
            allowed_ips: None,
            persistent_keepalive: None,
        }
    }

    #[test]
    fn a_peer_kept_through_a_failed_lookup_gets_the_keepalive_called_for() {
        let held = Peer {
            persistent_keepalive: BARE_25,
            ..peer("k1", &["0.0.0.0/0"], Some("192.0.2.1:51820"))
        };
        assert_eq!(
            last_known_good(&held, wire(PLAIN_KEEPALIVE)),
            peer("k1", &["0.0.0.0/0"], Some("192.0.2.1:51820"))
        );
    }

    fn interface(name: &str, obfuscation: Obfuscation) -> InterfaceEntry {
        InterfaceEntry {
            name: name.to_string(),
            listen_port: 51820,
            addresses: vec![],
            private_key: encode_key(&KEY).as_str().into(),
            obfuscation,
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
        let overlapping = Obfuscation {
            h1: Some(5.into()),
            h2: Some(5.into()),
            ..Obfuscation::default()
        };
        let mut unkeyed = interface("awg-b", Obfuscation::default());
        unkeyed.private_key = "not a key".into();
        for (iface, refused) in [
            (
                interface("awg-b", undecodable),
                "interface awg-b: invalid header_protection_key",
            ),
            (
                interface("awg-b", overlapping),
                "interface awg-b: obfuscation.h1 (5) and obfuscation.h2 (5)",
            ),
            (unkeyed, "interface awg-b: invalid private_key"),
        ] {
            let shown = format!("{:#}", check(&iface).unwrap_err());
            assert!(shown.starts_with(refused), "{shown}");
            // The logged chain would otherwise show a character of the configured text and where.
            assert!(!shown.contains("offset"), "{shown}");
        }
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
}
