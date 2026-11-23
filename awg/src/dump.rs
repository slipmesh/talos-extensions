//! A device dump folded into its peers.

use crate::handshake::PeerStats;
use crate::interface::Peer;
use netlink_packet_amneziawg::{
    AmneziaWireguardAllowedIpAttr, AmneziaWireguardAttribute, AmneziaWireguardPeerAttribute,
};
use sliplib_secrets::wireguard::encode_key;
use std::collections::BTreeMap;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Dumped {
    pub peer: Peer,
    pub stats: PeerStats,
}

/// By public key. The kernel resumes a peer whose `allowed_ips` do not fit one message in the
/// next, under its `PublicKey` alone: each piece is folded into the peer.
pub fn peers(attrs: &[AmneziaWireguardAttribute]) -> BTreeMap<String, Dumped> {
    let mut peers = BTreeMap::new();
    let pieces = attrs
        .iter()
        .filter_map(|attr| match attr {
            AmneziaWireguardAttribute::Peers(pieces) => Some(pieces),
            _ => None,
        })
        .flatten();
    for piece in pieces {
        let Some(public_key) = piece.0.iter().find_map(|attr| match attr {
            AmneziaWireguardPeerAttribute::PublicKey(key) => Some(encode_key(key)),
            _ => None,
        }) else {
            continue;
        };
        let dumped = peers.entry(public_key.clone()).or_insert_with(|| Dumped {
            peer: Peer {
                public_key,
                allowed_ips: Vec::new(),
                endpoint: None,
                persistent_keepalive: Default::default(),
            },
            stats: PeerStats::default(),
        });
        for attr in &piece.0 {
            match attr {
                AmneziaWireguardPeerAttribute::AllowedIps(ips) => dumped
                    .peer
                    .allowed_ips
                    .extend(ips.iter().filter_map(|ip| allowed_ip_to_cidr(&ip.0))),
                AmneziaWireguardPeerAttribute::Endpoint(address) => {
                    dumped.peer.endpoint = Some(address.to_string());
                }
                AmneziaWireguardPeerAttribute::PersistentKeepalive(range) => {
                    dumped.peer.persistent_keepalive = *range;
                }
                AmneziaWireguardPeerAttribute::LastHandshake(at) => {
                    dumped.stats.last_handshake = at.seconds.max(0) as u64;
                }
                AmneziaWireguardPeerAttribute::RxBytes(bytes) => dumped.stats.rx_bytes = *bytes,
                AmneziaWireguardPeerAttribute::TxBytes(bytes) => dumped.stats.tx_bytes = *bytes,
                _ => {}
            }
        }
    }
    peers
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
