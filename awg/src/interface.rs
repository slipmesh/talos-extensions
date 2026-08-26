//! Applies one `InterfaceEntry` to the kernel: link/addresses/identity, then a point-wise peer
//! diff against whatever's actually configured (read back from the kernel, not assumed empty -
//! this process gets fully restarted on every config change, so there is no in-memory "previous"
//! to carry over between runs).
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
use netlink_packet_core::DefaultNla;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

/// Matches `router/src/resolver.rs`'s own `NETWORK_TIMEOUT` for DNS lookups - same "unreachable
/// resolver, not NXDOMAIN" failure mode, same order-of-magnitude answer for how long to wait
/// before giving up. Without this, a hung `tokio::net::lookup_host` used to block
/// `converge_interface` for that interface forever - and since `main.rs::run()` converges
/// interfaces one at a time, every interface *after* it in the config never converges either, and
/// the process never exits for `restart: always` to get a chance to retry it.
const ENDPOINT_RESOLVE_TIMEOUT: Duration = Duration::from_secs(15);

/// See amneziawg-linux-kernel-module's uapi/wireguard.h `enum wg_peer_flag`.
const WGPEER_F_REMOVE_ME: u32 = 1 << 0;
const WGPEER_F_REPLACE_ALLOWEDIPS: u32 = 1 << 1;
/// Signals "this update explicitly sets AdvancedSecurity" (as opposed to leaving it untouched) -
/// distinct from the `WGPEER_A_ADVANCED_SECURITY` attribute below, which signals the *value*.
/// amneziawg-tools' own `ipc-linux.h` always sets this bit whenever its config file mentions
/// `AdvancedSecurity` at all, true or false - our config always has a definite value (`#[serde
/// (default)]`), so we always set this bit too, every peer sync.
const WGPEER_F_HAS_ADVANCED_SECURITY: u32 = 1 << 3;
/// `wgpeer_attribute` has no crate support (as of the pinned rev) for this one - confirmed absent
/// from `netlink-packet-amnezia-wireguard`'s `peer.rs`, unlike everything else in this file, which
/// does have a typed variant. Built manually via `Other(DefaultNla::new(...))`. `NLA_FLAG`: an
/// empty payload means "present" (true); the attribute is simply omitted for "false".
const WGPEER_A_ADVANCED_SECURITY: u16 = 11;
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
    /// See `PeerEntry::advanced_security`'s doc comment - the kernel never reports this back in a
    /// `GetDevice` dump (confirmed against `netlink.c`'s `get_peer`), so `current_peers()` can
    /// never populate this truthfully; it always reads back `false` there regardless of the real
    /// state. That's fine for the diff this feeds: it just means a peer configured `true` gets
    /// re-sent on every single process start, not only when it actually changed - harmless, since
    /// re-sending is idempotent.
    pub advanced_security: bool,
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
        advanced_security: entry.advanced_security,
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
                    // Always false - see the `advanced_security` field's own doc comment.
                    advanced_security: false,
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
            as_set(&prev.allowed_ips) == as_set(&peer.allowed_ips)
                && prev.endpoint == peer.endpoint
                && prev.advanced_security == peer.advanced_security
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
                let flags = WGPEER_F_REPLACE_ALLOWEDIPS | WGPEER_F_HAS_ADVANCED_SECURITY;
                let mut attrs = vec![
                    AmneziaWireguardPeerAttribute::PublicKey(decoded),
                    AmneziaWireguardPeerAttribute::Flags(flags),
                    AmneziaWireguardPeerAttribute::AllowedIps(allowed_ips),
                ];
                if peer.advanced_security {
                    attrs.push(AmneziaWireguardPeerAttribute::Other(DefaultNla::new(
                        WGPEER_A_ADVANCED_SECURITY,
                        Vec::new(),
                    )));
                }
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
    push_obfuscation_attrs(&mut device_attrs, &iface.obfuscation)?;
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

    // A statically assigned address (in particular an IPv6 link-local used for an OSPFv3-style
    // underlay) would otherwise be dropped every time the interface cycles down/up (e.g. a brief
    // reconnect). Not handled here: writing `net.ipv6.conf.<iface>.keep_addr_on_down` from inside
    // this process failed on a real node (container lacked permission to write /proc/sys, and the
    // interface doesn't exist yet at boot for Talos's own `machine.sysctls` to apply it directly
    // either). Instead, set `net.ipv6.conf.default.keep_addr_on_down: "1"` once in the node's
    // `machine.sysctls` - the kernel copies `ipv6_devconf_dflt` into every interface's devconf at
    // creation time (confirmed against net/ipv6/addrconf.c), so it applies to `mesh-*`/etc.
    // interfaces this daemon creates later, with no code here needed at all. See
    // talos-awg-extension/docs/extension-services.md.

    rt.set_up(index).await?;
    set_identity(awg, iface).await?;

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
                    desired.push(existing.clone());
                }
                None => tracing::warn!(
                    interface = %iface.name, peer = %peer.public_key, error = %e,
                    "failed to resolve new peer with no previous state, skipping it this pass"
                ),
            },
        }
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
            advanced_security: false,
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
    fn advanced_security_alone_yields_replace_op() {
        // The kernel never reports this back (see `Peer::advanced_security`'s doc comment), so
        // `previous` always carries `false` here regardless of the real state - a peer configured
        // `true` must still show up as changed, every single time, not just once.
        let previous = vec![peer("k1", &["10.0.0.1/32"], None)];
        let mut desired = peer("k1", &["10.0.0.1/32"], None);
        desired.advanced_security = true;
        let ops = diff_peers(&previous, &[desired.clone()]);
        assert_eq!(ops, vec![("k1".to_string(), Some(desired))]);
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
