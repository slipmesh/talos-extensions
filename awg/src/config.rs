//! Config shape: a flat list of interfaces, each with any number of peers. There is no
//! discriminator between "mesh-style" and "roadwarriors-style" interfaces - the difference is
//! purely behavioral, driven by whether a given peer's `allowed_ips` is set (see `PeerEntry`'s own
//! doc comment). Always read from a fixed path (`crate::CONFIG_PATH`) mounted by Talos via
//! `ExtensionServiceConfig.configFiles` - never an env var or CLI flag.

use common::Obfuscation;
use common::netlink::rt::parse_cidr;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

#[derive(Deserialize, Serialize, Debug, Default, PartialEq)]
pub struct AwgConfig {
    #[serde(default)]
    pub interfaces: Vec<InterfaceEntry>,
}

#[derive(Deserialize, Serialize, Debug, PartialEq)]
pub struct InterfaceEntry {
    /// Valid Linux interface name (`IFNAMSIZ` is 16 bytes including the NUL terminator, so 15
    /// usable bytes) - no other naming convention required. GC doesn't rely on a name prefix; see
    /// `gc.rs`.
    pub name: String,
    pub listen_port: u16,
    /// CIDR strings, IPv4 and IPv6 freely mixed, any count of either.
    #[serde(default)]
    pub addresses: Vec<String>,
    /// Base64 X25519 private key. Always supplied here - this daemon never generates or persists
    /// a key itself (see the README); whoever renders the machine config is responsible for
    /// giving a node its own per-interface key, or the same key across every node's config when a
    /// single shared identity is needed (e.g. so roaming clients see one consistent server
    /// identity regardless of which node they connect to).
    pub private_key: String,
    #[serde(default)]
    pub obfuscation: Obfuscation,
    /// Only meaningful for peers that have an explicit `allowed_ips` (see `PeerEntry`) - ignored
    /// entirely for full-tunnel peers, which are never handshake-tracked. Defaults to 180s if unset.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub handshake_stale_secs: Option<u64>,
    #[serde(default)]
    pub peers: Vec<PeerEntry>,
}

#[derive(Deserialize, Serialize, Debug, PartialEq)]
pub struct PeerEntry {
    pub public_key: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<String>,
    /// `None` => this peer gets the full-tunnel default (`0.0.0.0/0` + `::/0`) as its AllowedIPs,
    /// its handshake is never polled, and no kernel route is ever installed for it - this is what
    /// used to be a dedicated "mesh" interface (connectivity comes from the underlay routing
    /// protocol reaching over the tunnel once it's up, not from a per-peer route).
    ///
    /// `Some(cidrs)` => exactly these CIDRs become the peer's AllowedIPs, its handshake is polled
    /// at 1Hz, and a kernel route is installed per CIDR while the handshake stays fresh - this is
    /// what used to be a dedicated "roadwarriors" interface. An interface can freely mix peers of
    /// both kinds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allowed_ips: Option<Vec<String>>,
    /// Enables AmneziaWG's "header protection" for this peer - encrypts the WireGuard packet
    /// header's own type/reserved fields with the interface's `obfuscation.header_protection_key`.
    /// Both ends must agree: the peer's own config needs the matching key and
    /// `AdvancedSecurity: true` too. Setting `header_protection_key` alone, without this, does
    /// nothing (confirmed against amneziawg-tools' `src/config.c`).
    #[serde(default)]
    pub advanced_security: bool,
}

pub const DEFAULT_HANDSHAKE_STALE_SECS: u64 = 180;

/// Pure validation, no I/O: interface names are non-empty, fit `IFNAMSIZ`, and are unique;
/// every `addresses`/`allowed_ips` entry is a parseable CIDR (either family).
pub fn validate(cfg: &AwgConfig) -> anyhow::Result<()> {
    let mut seen_names = HashSet::new();
    for iface in &cfg.interfaces {
        anyhow::ensure!(!iface.name.is_empty(), "interface name must not be empty");
        anyhow::ensure!(
            iface.name.len() <= 15,
            "interface name {:?} is longer than 15 bytes (IFNAMSIZ)",
            iface.name
        );
        anyhow::ensure!(
            seen_names.insert(iface.name.as_str()),
            "duplicate interface name {:?}",
            iface.name
        );
        for cidr in &iface.addresses {
            parse_cidr(cidr).map_err(|e| {
                anyhow::anyhow!("interface {:?}: invalid address {cidr:?}: {e}", iface.name)
            })?;
        }
        let mut seen_peer_keys = HashSet::new();
        for peer in &iface.peers {
            anyhow::ensure!(
                seen_peer_keys.insert(peer.public_key.as_str()),
                "interface {:?}: duplicate peer public_key {:?}",
                iface.name,
                peer.public_key
            );
            // `advanced_security` alone does nothing without the interface's own
            // `header_protection_key` (see `PeerEntry::advanced_security`'s own doc comment,
            // confirmed against amneziawg-tools' src/config.c) - catching this here means a
            // typo'd/missing key fails the config outright instead of silently negotiating
            // without header protection, discoverable only by traffic analysis.
            anyhow::ensure!(
                !peer.advanced_security || iface.obfuscation.header_protection_key.is_some(),
                "interface {:?}, peer {:?}: advanced_security is set but obfuscation.header_protection_key is not",
                iface.name,
                peer.public_key
            );
            if let Some(allowed_ips) = &peer.allowed_ips {
                for cidr in allowed_ips {
                    parse_cidr(cidr).map_err(|e| {
                        anyhow::anyhow!(
                            "interface {:?}, peer {:?}: invalid allowed_ips entry {cidr:?}: {e}",
                            iface.name,
                            peer.public_key
                        )
                    })?;
                }
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn iface(name: &str) -> InterfaceEntry {
        InterfaceEntry {
            name: name.to_string(),
            listen_port: 51820,
            addresses: vec![],
            private_key: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".to_string(),
            obfuscation: Obfuscation::default(),
            handshake_stale_secs: None,
            peers: vec![],
        }
    }

    #[test]
    fn parses_a_full_config_from_yaml() {
        let yaml = r#"
interfaces:
  - name: mesh-a1b2c3d4
    listen_port: 51820
    addresses: ["fe80::a1b2:c3d4/64"]
    private_key: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
    obfuscation: {jc: 4, jmin: 40, jmax: 70}
    peers:
      - public_key: "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB="
        endpoint: "203.0.113.7:51820"
  - name: rw-eu
    listen_port: 51900
    addresses: ["10.99.0.1/24", "fd00:99::1/64"]
    private_key: "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC="
    obfuscation:
      s3: 60
      s4: 90
      i1: "5-10"
      header_protection_key: "EEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEE="
      content_padding_addition: 128
      rekey_after_time: 120
      max_handshake_attempts: 90
    peers:
      - public_key: "DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD="
        allowed_ips: ["10.99.0.5/32"]
        advanced_security: true
"#;
        let cfg: AwgConfig = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(cfg.interfaces.len(), 2);
        assert_eq!(cfg.interfaces[0].peers[0].allowed_ips, None);
        assert_eq!(
            cfg.interfaces[1].peers[0].allowed_ips,
            Some(vec!["10.99.0.5/32".to_string()])
        );
        assert!(cfg.interfaces[1].peers[0].advanced_security);
        assert_eq!(cfg.interfaces[1].obfuscation.s3, Some(60));
        assert_eq!(cfg.interfaces[1].obfuscation.i1, Some("5-10".to_string()));
        assert_eq!(
            cfg.interfaces[1].obfuscation.header_protection_key,
            Some("EEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEE=".to_string())
        );
        assert_eq!(
            cfg.interfaces[1].obfuscation.content_padding_addition,
            Some(128)
        );
        assert_eq!(
            cfg.interfaces[1].obfuscation.max_handshake_attempts,
            Some(90)
        );
        validate(&cfg).unwrap();
    }

    #[test]
    fn rejects_duplicate_interface_names() {
        let cfg = AwgConfig {
            interfaces: vec![iface("dup"), iface("dup")],
        };
        assert!(validate(&cfg).is_err());
    }

    #[test]
    fn rejects_a_name_longer_than_ifnamsiz() {
        let cfg = AwgConfig {
            interfaces: vec![iface("this-name-is-way-too-long")],
        };
        assert!(validate(&cfg).is_err());
    }

    #[test]
    fn rejects_a_malformed_address_cidr() {
        let mut a = iface("a");
        a.addresses.push("not-a-cidr".to_string());
        let cfg = AwgConfig {
            interfaces: vec![a],
        };
        assert!(validate(&cfg).is_err());
    }

    #[test]
    fn rejects_a_malformed_allowed_ips_entry() {
        let mut a = iface("a");
        a.peers.push(PeerEntry {
            public_key: "k".to_string(),
            endpoint: None,
            allowed_ips: Some(vec!["not-a-cidr".to_string()]),
            advanced_security: false,
        });
        let cfg = AwgConfig {
            interfaces: vec![a],
        };
        assert!(validate(&cfg).is_err());
    }

    #[test]
    fn rejects_duplicate_peer_public_key_within_one_interface() {
        let mut a = iface("a");
        a.peers.push(PeerEntry {
            public_key: "k".to_string(),
            endpoint: None,
            allowed_ips: Some(vec!["10.0.0.1/32".to_string()]),
            advanced_security: false,
        });
        a.peers.push(PeerEntry {
            public_key: "k".to_string(),
            endpoint: None,
            allowed_ips: Some(vec!["10.0.0.2/32".to_string()]),
            advanced_security: false,
        });
        let cfg = AwgConfig {
            interfaces: vec![a],
        };
        assert!(validate(&cfg).is_err());
    }

    #[test]
    fn rejects_advanced_security_peer_without_header_protection_key() {
        let mut a = iface("a");
        a.peers.push(PeerEntry {
            public_key: "k".to_string(),
            endpoint: None,
            allowed_ips: None,
            advanced_security: true,
        });
        // a.obfuscation.header_protection_key is left at its default: None.
        let cfg = AwgConfig {
            interfaces: vec![a],
        };
        assert!(validate(&cfg).is_err());
    }

    #[test]
    fn accepts_advanced_security_peer_with_header_protection_key() {
        let mut a = iface("a");
        a.obfuscation.header_protection_key =
            Some("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".to_string());
        a.peers.push(PeerEntry {
            public_key: "k".to_string(),
            endpoint: None,
            allowed_ips: None,
            advanced_security: true,
        });
        let cfg = AwgConfig {
            interfaces: vec![a],
        };
        assert!(validate(&cfg).is_ok());
    }

    #[test]
    fn accepts_an_empty_config() {
        assert!(validate(&AwgConfig::default()).is_ok());
    }
}
