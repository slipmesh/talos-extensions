//! Config shape: everything `router` needs is declared statically, matching `awg`'s own
//! philosophy - no CRD watching, no netlink introspection of `ext-awg`'s interfaces (see
//! `talos-extensions/README.md`'s design notes for this crate). Always read from a fixed path
//! (`crate::CONFIG_PATH`) mounted by Talos via `ExtensionServiceConfig.configFiles` - never an
//! env var or CLI flag, same invariant `awg/src/config.rs` documents.

use crate::resolver::BypassSourceEntry;
use anyhow::Result;
use common::MetricsConfig;
use common::cidr::parse_cidr as parse_dual_family_cidr;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::net::{IpAddr, Ipv6Addr};

/// BIRD's own defaults (`min tx 100 ms`, multiplier 5) declare a session dead after ~500 ms.
/// These links cannot honour that: every mesh interface is an obfuscated WireGuard tunnel,
/// several of them intercontinental, where a brief stall is normal and a flap costs more than
/// slow convergence. 300 ms with the default multiplier detects in ~1.5s, against OSPF's 40s.
pub const BFD_DEFAULT_MIN_RX_MS: u32 = 300;
pub const BFD_DEFAULT_MIN_TX_MS: u32 = 300;
pub const BFD_DEFAULT_MULTIPLIER: u8 = 5;

fn default_bfd_min_rx_ms() -> u32 {
    BFD_DEFAULT_MIN_RX_MS
}
fn default_bfd_min_tx_ms() -> u32 {
    BFD_DEFAULT_MIN_TX_MS
}
fn default_bfd_multiplier() -> u8 {
    BFD_DEFAULT_MULTIPLIER
}

/// Only what both BIRD and RouterOS accept. BIRD alone also offers `idle tx interval`, `passive`
/// and packet authentication, and MikroTik has none of the three - stating one here would leave
/// the two ends of a link configured differently, which is the opposite of what a shared
/// document is for. Authentication is moot regardless: these packets travel inside WireGuard.
#[derive(Deserialize, Serialize, Debug, PartialEq, Clone)]
pub struct BfdSettings {
    #[serde(default = "default_bfd_min_rx_ms")]
    pub min_rx_ms: u32,
    #[serde(default = "default_bfd_min_tx_ms")]
    pub min_tx_ms: u32,
    #[serde(default = "default_bfd_multiplier")]
    pub multiplier: u8,
}

impl Default for BfdSettings {
    fn default() -> Self {
        Self {
            min_rx_ms: BFD_DEFAULT_MIN_RX_MS,
            min_tx_ms: BFD_DEFAULT_MIN_TX_MS,
            multiplier: BFD_DEFAULT_MULTIPLIER,
        }
    }
}

#[derive(Deserialize, Serialize, Debug, PartialEq)]
pub struct RouterConfig {
    pub node: NodeIdentity,
    pub bgp_as: u32,
    #[serde(default)]
    pub bgp_peers: Vec<BgpPeerEntry>,
    /// Present when the mesh asked for BFD on its OSPF links, absent otherwise. `routeros` reads
    /// this same field to configure the MikroTik side, which is why it lives here rather than in
    /// either consumer - and why it carries only the three settings both ends can honour.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bfd: Option<BfdSettings>,
    /// Interface-matching entries fed straight into BIRD's own `interface` clause: an exact name,
    /// a shell-glob pattern (`"mesh-*"`), or a CIDR matching by the interface's address - BIRD
    /// accepts all three forms in the same list. See `bird.rs::render_iface_pattern` for how each
    /// entry gets rendered (quoted name/pattern vs. bare CIDR literal).
    #[serde(default)]
    pub ospf_interfaces: Vec<String>,
    /// Extra interfaces (same grammar as `ospf_interfaces`: exact name, glob, or CIDR) to treat as
    /// `protocol direct` sources - each one's connected route gets exported over iBGP by the
    /// existing `RTS_DEVICE` clause, same as `router-lo`'s own loopback already is. Not tied to any
    /// one purpose (a pod-network bridge is the motivating case - see `bird.rs`'s `RenderInputs`
    /// doc comment) - whoever authors `router.yaml` decides what belongs here.
    #[serde(default)]
    pub direct_interfaces: Vec<String>,
    /// IPv4 CIDR ranges (not exact per-peer `/32`s) - any kernel-learned route inside one of these
    /// ranges is re-announced over iBGP. See `bird.rs`'s module doc comment for why this stays
    /// IPv4-only.
    #[serde(default)]
    pub learn: Vec<String>,
    #[serde(default)]
    pub announce: Vec<AnnounceEntry>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bypass: Option<BypassConfig>,
    /// Present when this node serves BIRD's protocol state to Prometheus, absent otherwise.
    /// Served by `bird_exporter`, which this daemon runs beside BIRD - an implementation detail
    /// of the daemon, not of this document.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metrics: Option<MetricsConfig>,
}

#[derive(Deserialize, Serialize, Debug, PartialEq)]
pub struct NodeIdentity {
    /// CIDR strings, exactly one IPv4 and exactly one IPv6 entry (see `validate`) - both are used
    /// simultaneously for different roles (v4: BIRD router id / `krt_prefsrc` / OSPFv3 stub
    /// network; v6: this node's iBGP session source address), not "any one of these". The prefix
    /// length can be omitted (defaults to `/32` for v4, `/128` for v6, since these are always
    /// loopback identities, never networks) - see `parse_loopback_address`.
    pub loopback_addresses: Vec<String>,
}

#[derive(Deserialize, Serialize, Debug, PartialEq)]
pub struct BgpPeerEntry {
    pub name: String,
    /// A single bare IPv6 address (no prefix length - this isn't a network). Not a list: a
    /// `protocol bgp` instance in BIRD takes exactly one `local`/`neighbor` address each, so a
    /// list here would imply failover/multi-address support BIRD's config syntax doesn't have.
    /// Always IPv6: the iBGP session itself runs over
    /// IPv6 loopbacks (RFC 8950 extended next hop carries the IPv4 payload prefixes on top of
    /// that IPv6-only session), same as `node.loopback_addresses`'s v6 entry.
    pub address: String,
}

#[derive(Deserialize, Serialize, Debug, PartialEq)]
pub struct AnnounceEntry {
    pub net: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
}

#[derive(Deserialize, Serialize, Debug, PartialEq)]
pub struct BypassConfig {
    #[serde(default = "default_bypass_refresh_interval_secs")]
    pub refresh_interval_secs: u64,
    pub include: Vec<BypassSourceEntry>,
    #[serde(default)]
    pub exclude: Vec<BypassSourceEntry>,
}

fn default_bypass_refresh_interval_secs() -> u64 {
    24 * 60 * 60
}

/// Parses a loopback-identity address: `"<addr>/<prefix>"`, or a bare address (defaults to `/32`
/// for IPv4, `/128` for IPv6 - the whole point of a loopback identity is that it has no host
/// bits). Delegates to `common::cidr::parse_cidr` (already used by `awg` for the same
/// dual-family CIDR shape) whenever a prefix is present, so both parsers agree on what's valid.
pub fn parse_loopback_address(s: &str) -> Result<(IpAddr, u8)> {
    if s.contains('/') {
        return parse_dual_family_cidr(s);
    }
    let addr: IpAddr = s
        .parse()
        .map_err(|e| anyhow::anyhow!("{s:?} is not a valid IP address: {e}"))?;
    let prefix = if addr.is_ipv4() { 32 } else { 128 };
    Ok((addr, prefix))
}

/// Pure validation, no I/O: `node.loopback_addresses` has exactly one IPv4 and one IPv6 entry,
/// every `bgp_peers` name is non-empty/unique and its address is a valid IPv6 address, every
/// `ospf_interfaces`/ entry is non-empty, every `learn`/`announce[].net` entry is a valid IPv4
/// CIDR, and every `bypass` entry's `kind` is recognized (with `literal` prefixes validated
/// eagerly, since that's a local check - `asn`/`geoip`/`dns` still only get validated at resolve
/// time in `resolver.rs`, since that's genuinely network-dependent).
pub fn validate(cfg: &RouterConfig) -> Result<()> {
    // AS 0 is reserved and explicitly invalid per RFC 7607 ("Codification of AS 0 Processing") -
    // BIRD would only surface this once it tries to actually start an iBGP session, well past
    // where this config's own fail-fast validation should have caught it. Not checking against
    // the private-use ranges (64512-65534/4200000000-4294967294): this project's own test nodes
    // use 64512, a legitimate and common choice for an internal-only network like this one.
    anyhow::ensure!(cfg.bgp_as != 0, "bgp_as must not be 0 (reserved, RFC 7607)");
    let mut v4_count = 0;
    let mut v6_count = 0;
    for addr in &cfg.node.loopback_addresses {
        let (addr, _prefix) = parse_loopback_address(addr)
            .map_err(|e| anyhow::anyhow!("node.loopback_addresses: {e}"))?;
        match addr {
            IpAddr::V4(_) => v4_count += 1,
            IpAddr::V6(_) => v6_count += 1,
        }
    }
    anyhow::ensure!(
        v4_count == 1,
        "node.loopback_addresses must contain exactly one IPv4 address, found {v4_count}"
    );
    anyhow::ensure!(
        v6_count == 1,
        "node.loopback_addresses must contain exactly one IPv6 address, found {v6_count}"
    );

    if let Some(metrics) = &cfg.metrics {
        metrics.validate("metrics.listen")?;
    }

    if let Some(bfd) = &cfg.bfd {
        // A zero here renders a bird.conf BIRD refuses, which this daemon would only discover
        // when `birdc configure` fails on the node - long past where a typo in mesh.yaml should
        // have been caught. BIRD's own documentation puts the practical floor at tens of
        // milliseconds, so this checks for the meaningless value rather than for a good one.
        anyhow::ensure!(
            bfd.min_rx_ms > 0 && bfd.min_tx_ms > 0,
            "bfd: min_rx_ms and min_tx_ms must be greater than 0"
        );
        anyhow::ensure!(bfd.multiplier > 0, "bfd: multiplier must be greater than 0");
    }

    let mut seen_names = HashSet::new();
    for peer in &cfg.bgp_peers {
        anyhow::ensure!(!peer.name.is_empty(), "bgp_peers: name must not be empty");
        anyhow::ensure!(
            seen_names.insert(peer.name.as_str()),
            "bgp_peers: duplicate name {:?}",
            peer.name
        );
        peer.address.parse::<Ipv6Addr>().map_err(|e| {
            anyhow::anyhow!(
                "bgp_peers {:?}: address {:?} is not a valid IPv6 address: {e}",
                peer.name,
                peer.address
            )
        })?;
    }

    for iface in &cfg.ospf_interfaces {
        anyhow::ensure!(
            !iface.is_empty(),
            "ospf_interfaces: entry must not be empty"
        );
    }

    for cidr in &cfg.learn {
        crate::cidr::parse_cidr(cidr)
            .map_err(|e| anyhow::anyhow!("learn: invalid IPv4 CIDR {cidr:?}: {e}"))?;
    }

    for entry in &cfg.announce {
        crate::cidr::parse_cidr(&entry.net)
            .map_err(|e| anyhow::anyhow!("announce: invalid IPv4 CIDR {:?}: {e}", entry.net))?;
    }

    if let Some(bypass) = &cfg.bypass {
        // `bypass_refresh_loop` builds `tokio::time::interval(Duration::from_secs(refresh_interval_secs))`
        // - a zero period panics there per tokio's own documented contract, taking the whole
        // process down instead of failing here with a clear message.
        anyhow::ensure!(
            bypass.refresh_interval_secs > 0,
            "bypass.refresh_interval_secs must be greater than 0"
        );
        for entry in bypass.include.iter().chain(bypass.exclude.iter()) {
            validate_bypass_entry(entry)?;
        }
    }

    Ok(())
}

fn validate_bypass_entry(entry: &BypassSourceEntry) -> Result<()> {
    match entry.kind.as_str() {
        "literal" => {
            let prefixes = entry
                .prefixes
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("literal bypass source requires `prefixes`"))?;
            for p in prefixes {
                crate::cidr::parse_cidr(&p.net).map_err(|e| {
                    anyhow::anyhow!("bypass: invalid literal prefix {:?}: {e}", p.net)
                })?;
            }
        }
        "asn" => {
            anyhow::ensure!(entry.label.is_some(), "asn bypass source requires `label`");
            anyhow::ensure!(entry.asns.is_some(), "asn bypass source requires `asns`");
        }
        "dns" => {
            anyhow::ensure!(entry.label.is_some(), "dns bypass source requires `label`");
            anyhow::ensure!(
                entry.hostnames.is_some(),
                "dns bypass source requires `hostnames`"
            );
        }
        "geoip" => {
            anyhow::ensure!(
                entry.country.is_some(),
                "geoip bypass source requires `country`"
            );
        }
        other => anyhow::bail!("unknown bypass source kind: {other:?}"),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn minimal_yaml() -> &'static str {
        r#"
node:
  loopback_addresses: ["10.62.0.1/32", "fd00::1/128"]
bgp_as: 64512
"#
    }

    /// The rule itself lives on `MetricsConfig` and `awg`'s own tests cover it; what this
    /// guards is that `router` still asks for it. A wildcard listener would put BIRD's protocol
    /// state on every interface the node has, public ones included.
    #[test]
    fn validate_rejects_a_wildcard_metrics_listener() {
        let yaml = format!(
            "{}metrics:
  listen: 0.0.0.0:9324
",
            minimal_yaml()
        );
        let cfg: RouterConfig = serde_yaml::from_str(&yaml).unwrap();
        let err = validate(&cfg).unwrap_err().to_string();
        assert!(err.contains("wildcard"), "unexpected error: {err}");
    }

    /// A zero interval renders a bird.conf BIRD refuses, and this daemon would only find out
    /// when `birdc configure` fails on the node.
    #[test]
    fn validate_rejects_a_bfd_interval_of_zero() {
        let yaml = format!(
            "{}bfd:
  min_rx_ms: 0
  min_tx_ms: 300
",
            minimal_yaml()
        );
        let cfg: RouterConfig = serde_yaml::from_str(&yaml).unwrap();
        assert_eq!(cfg.bfd.as_ref().unwrap().multiplier, BFD_DEFAULT_MULTIPLIER);
        let err = validate(&cfg).unwrap_err().to_string();
        assert!(err.contains("min_rx_ms"), "unexpected error: {err}");
    }

    #[test]
    fn parses_a_minimal_config() {
        let cfg: RouterConfig = serde_yaml::from_str(minimal_yaml()).unwrap();
        assert_eq!(cfg.bgp_as, 64512);
        assert!(cfg.bgp_peers.is_empty());
        assert!(cfg.bypass.is_none());
        validate(&cfg).unwrap();
    }

    #[test]
    fn parses_a_full_config() {
        let yaml = r#"
node:
  loopback_addresses: ["10.62.0.1/32", "fd00::1/128"]
bgp_as: 64512
bgp_peers:
  - name: fra
    address: fd00::2
  - name: lon
    address: fd00::3
ospf_interfaces: ["mesh-*", "router-lo"]
learn: ["10.99.0.0/24"]
announce:
  - net: "10.96.0.0/12"
    label: "k8s-services"
bypass:
  refresh_interval_secs: 3600
  include:
    - kind: asn
      label: "some vendor"
      asns: ["AS15169"]
  exclude:
    - kind: literal
      prefixes: [{net: "10.0.0.0/8"}]
"#;
        let cfg: RouterConfig = serde_yaml::from_str(yaml).unwrap();
        validate(&cfg).unwrap();
        assert_eq!(cfg.bgp_peers.len(), 2);
        assert_eq!(cfg.bypass.as_ref().unwrap().refresh_interval_secs, 3600);
    }

    #[test]
    fn parse_loopback_address_defaults_prefix_by_family() {
        assert_eq!(
            parse_loopback_address("10.62.0.1").unwrap(),
            ("10.62.0.1".parse().unwrap(), 32)
        );
        assert_eq!(
            parse_loopback_address("fd00::1").unwrap(),
            ("fd00::1".parse().unwrap(), 128)
        );
    }

    #[test]
    fn parse_loopback_address_accepts_explicit_prefix() {
        assert_eq!(
            parse_loopback_address("10.62.0.1/24").unwrap(),
            ("10.62.0.1".parse().unwrap(), 24)
        );
    }

    #[test]
    fn rejects_missing_ipv4_loopback() {
        let mut cfg: RouterConfig = serde_yaml::from_str(minimal_yaml()).unwrap();
        cfg.node.loopback_addresses = vec!["fd00::1/128".to_string()];
        assert!(validate(&cfg).is_err());
    }

    #[test]
    fn rejects_missing_ipv6_loopback() {
        let mut cfg: RouterConfig = serde_yaml::from_str(minimal_yaml()).unwrap();
        cfg.node.loopback_addresses = vec!["10.62.0.1/32".to_string()];
        assert!(validate(&cfg).is_err());
    }

    #[test]
    fn rejects_duplicate_peer_names() {
        let mut cfg: RouterConfig = serde_yaml::from_str(minimal_yaml()).unwrap();
        cfg.bgp_peers = vec![
            BgpPeerEntry {
                name: "fra".to_string(),
                address: "fd00::2".to_string(),
            },
            BgpPeerEntry {
                name: "fra".to_string(),
                address: "fd00::3".to_string(),
            },
        ];
        assert!(validate(&cfg).is_err());
    }

    #[test]
    fn rejects_ipv4_peer_address() {
        let mut cfg: RouterConfig = serde_yaml::from_str(minimal_yaml()).unwrap();
        cfg.bgp_peers = vec![BgpPeerEntry {
            name: "fra".to_string(),
            address: "10.0.0.2".to_string(),
        }];
        assert!(validate(&cfg).is_err());
    }

    #[test]
    fn rejects_malformed_learn_cidr() {
        let mut cfg: RouterConfig = serde_yaml::from_str(minimal_yaml()).unwrap();
        cfg.learn = vec!["not-a-cidr".to_string()];
        assert!(validate(&cfg).is_err());
    }

    #[test]
    fn rejects_malformed_announce_cidr() {
        let mut cfg: RouterConfig = serde_yaml::from_str(minimal_yaml()).unwrap();
        cfg.announce = vec![AnnounceEntry {
            net: "not-a-cidr".to_string(),
            label: None,
        }];
        assert!(validate(&cfg).is_err());
    }

    #[test]
    fn rejects_unknown_bypass_kind() {
        let mut cfg: RouterConfig = serde_yaml::from_str(minimal_yaml()).unwrap();
        cfg.bypass = Some(BypassConfig {
            refresh_interval_secs: default_bypass_refresh_interval_secs(),
            include: vec![BypassSourceEntry {
                kind: "bogus".to_string(),
                label: None,
                asns: None,
                prefixes: None,
                country: None,
                hostnames: None,
            }],
            exclude: vec![],
        });
        assert!(validate(&cfg).is_err());
    }

    #[test]
    fn rejects_as0() {
        let mut cfg: RouterConfig = serde_yaml::from_str(minimal_yaml()).unwrap();
        cfg.bgp_as = 0;
        assert!(validate(&cfg).is_err());
    }

    #[test]
    fn rejects_zero_bypass_refresh_interval() {
        let mut cfg: RouterConfig = serde_yaml::from_str(minimal_yaml()).unwrap();
        cfg.bypass = Some(BypassConfig {
            refresh_interval_secs: 0,
            include: vec![],
            exclude: vec![],
        });
        assert!(validate(&cfg).is_err());
    }

    #[test]
    fn rejects_literal_bypass_without_prefixes() {
        let mut cfg: RouterConfig = serde_yaml::from_str(minimal_yaml()).unwrap();
        cfg.bypass = Some(BypassConfig {
            refresh_interval_secs: default_bypass_refresh_interval_secs(),
            include: vec![BypassSourceEntry {
                kind: "literal".to_string(),
                label: None,
                asns: None,
                prefixes: None,
                country: None,
                hostnames: None,
            }],
            exclude: vec![],
        });
        assert!(validate(&cfg).is_err());
    }

    #[test]
    fn accepts_empty_ospf_interfaces_and_learn() {
        let cfg: RouterConfig = serde_yaml::from_str(minimal_yaml()).unwrap();
        assert!(cfg.ospf_interfaces.is_empty());
        assert!(cfg.learn.is_empty());
        validate(&cfg).unwrap();
    }
}
