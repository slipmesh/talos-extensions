//! `rw-add`/`rw-del`/`rw-inspect` - a roadwarriors pool's clients: the entry a new client gets,
//! the client found by name, and the client-side config rendered as text or a QR code. Editing
//! `slipmesh.yaml` is `edit`'s.

use crate::addressing;
use crate::keys;
use crate::mesh_config::{MeshConfig, RoadwarriorClient, RoadwarriorPool};
use crate::secrets::ResolvedSecrets;
use anyhow::{Context, Result, bail};
use common::Obfuscation;
use std::net::{IpAddr, Ipv4Addr};

/// A private key we know (was just generated, or given via `--public-key`'s absence) vs. one we
/// never had (given via `--public-key`, or looking up an existing client with `rw-inspect`).
#[derive(Debug)]
pub enum ClientPrivateKey {
    Known(String),
    Unknown,
}

/// Finds a roadwarriors pool by `name`, erring with the names there are.
pub fn find_pool<'a>(mesh: &'a MeshConfig, if_: &str) -> Result<&'a RoadwarriorPool> {
    mesh.roadwarriors
        .iter()
        .find(|p| p.name == if_)
        .with_context(|| {
            let known: Vec<&str> = mesh.roadwarriors.iter().map(|p| p.name.as_str()).collect();
            format!("unknown roadwarriors pool {if_:?} - known pools: {known:?}")
        })
}

/// Finds a client by `name` within an already-located pool, same reasoning as `find_pool`.
fn find_client_index(pool: &RoadwarriorPool, name: &str) -> Result<usize> {
    pool.clients
        .iter()
        .position(|c| c.name == name)
        .with_context(|| {
            let known: Vec<&str> = pool.clients.iter().map(|c| c.name.as_str()).collect();
            format!(
                "unknown client {name:?} in pool {:?} - known clients: {known:?}",
                pool.name
            )
        })
}

/// Normalizes one `--allowed-ips` entry: an explicit `/prefix` is validated and passed through
/// unchanged (for the "route a whole subnet through this client" case - a client whose
/// `allowed_ips` includes its own home LAN, not just its own tunnel address); a bare address
/// gets `/32` (v4) or `/128` (v6) appended, the single-host convention every other client entry
/// already uses.
pub(crate) fn parse_allowed_ip(input: &str) -> Result<String> {
    let input = input.trim();
    if input.contains('/') {
        let (addr, prefix) = common::cidr::parse_cidr(input)
            .with_context(|| format!("invalid --allowed-ips entry {input:?}"))?;
        Ok(format!("{addr}/{prefix}"))
    } else {
        let addr: IpAddr = input
            .parse()
            .with_context(|| format!("invalid --allowed-ips entry {input:?}"))?;
        let prefix = if addr.is_ipv4() { 32 } else { 128 };
        Ok(format!("{addr}/{prefix}"))
    }
}

/// Rejects a client `name` or `public_key` that already exists in the pool - today's
/// `mesh_config::validate` only catches a duplicate `public_key` *within one pool*, not `name`;
/// `rw-add` is what mints names now, so it enforces uniqueness of both up front.
fn check_not_duplicate(pool: &RoadwarriorPool, name: &str, public_key: &str) -> Result<()> {
    if pool.clients.iter().any(|c| c.name == name) {
        bail!("client {name:?} already exists in pool {:?}", pool.name);
    }
    if pool.clients.iter().any(|c| c.public_key == public_key) {
        bail!(
            "public_key {public_key:?} already exists in pool {:?}",
            pool.name
        );
    }
    Ok(())
}

/// The pool's server identity, taken from the secrets `generate` resolves - never a second,
/// independently generated set of values that could drift from what `generate` actually puts on
/// the wire.
fn pool_identity(
    pool: &RoadwarriorPool,
    secrets: &ResolvedSecrets,
) -> Result<(String, Obfuscation)> {
    let private_key = secrets
        .roadwarrior_private_keys
        .get(&pool.name)
        .with_context(|| format!("no private key resolved for pool {:?}", pool.name))?
        .clone();
    let obfuscation = secrets
        .roadwarrior_obfuscation
        .get(&pool.name)
        .cloned()
        .unwrap_or_default();
    Ok((private_key, obfuscation))
}

/// The pool's endpoint(s): every `node_hostnames` entry's `nodes[].endpoint` + `pool.listen_port`.
/// First one is the config's primary `Endpoint`, the rest are noted as alternates - `primary`
/// (`--endpoint`) picks which `node_hostnames` entry that is, instead of always the first one in
/// slipmesh.yaml's own order; the rest keep their relative order behind it.
fn pool_endpoints(
    mesh: &MeshConfig,
    pool: &RoadwarriorPool,
    primary: Option<&str>,
) -> Result<Vec<String>> {
    let mut endpoints: Vec<String> = pool
        .node_hostnames
        .iter()
        .map(|host| {
            let node = mesh
                .nodes
                .iter()
                .find(|n| &n.name == host)
                .with_context(|| {
                    format!(
                        "roadwarriors pool {:?}: node_hostnames references unknown node {host:?}",
                        pool.name
                    )
                })?;
            let endpoint = node.endpoint.as_deref().with_context(|| {
                format!("node {host:?} has no endpoint - can't terminate a roadwarrior pool")
            })?;
            Ok(format!("{endpoint}:{}", pool.listen_port))
        })
        .collect::<Result<_>>()?;

    if let Some(primary_host) = primary {
        let idx = pool
            .node_hostnames
            .iter()
            .position(|h| h == primary_host)
            .with_context(|| {
                format!(
                    "--endpoint {primary_host:?} is not one of pool {:?}'s node_hostnames: {:?}",
                    pool.name, pool.node_hostnames
                )
            })?;
        let promoted = endpoints.remove(idx);
        endpoints.insert(0, promoted);
    }

    Ok(endpoints)
}

/// The client-side `DNS =` value for this pool: `pool.dns` if set, else the cluster's own CoreDNS
/// ClusterIP derived from `cluster.service_subnet` (the `.10` convention kubeadm/most distros
/// use - same `network | host_id` formula `addressing::ipv4_loopback` already does for loopback
/// derivation, reused here with a fixed host id of `.10` instead of a node's `node_id`). `None`
/// when neither is available - no DNS line at all, not a guess.
pub(crate) fn resolve_dns(mesh: &MeshConfig, pool: &RoadwarriorPool) -> Option<String> {
    if let Some(dns) = &pool.dns {
        return Some(dns.clone());
    }
    let subnet = mesh.cluster.service_subnet.as_deref()?;
    let (IpAddr::V4(network), prefix) = common::cidr::parse_cidr(subnet).ok()? else {
        return None;
    };
    Some(addressing::ipv4_loopback(network, prefix, Ipv4Addr::new(0, 0, 0, 10)).to_string())
}

/// Renders a client-side config: stock WireGuard `.conf` shape for both cases (AmneziaWG apps
/// accept the same `[Interface]`/`[Peer]` INI with extra keys, not a different format) - the
/// AmneziaWG `Jc..H4` lines are only emitted when `obfuscation` is non-default (a `plain` pool
/// always resolves to `Obfuscation::default()`, see `resolve_pool_identity`).
///
/// `endpoints`' first entry is the live `Endpoint`; any rest are commented-out `#Endpoint =`
/// lines (not a single summary comment) so they're each individually ready to uncomment. No
/// `# Name`/similar leading comment - neither the official WireGuard app nor AmneziaWG's
/// recognizes one on QR import (confirmed: no documented convention, generic "Server 1"-style
/// naming instead), and the only place that idea exists is an open, third-party feature request
/// for a different app entirely - not worth a line that no importer actually reads.
pub(crate) fn render_client_config(
    private_key: &ClientPrivateKey,
    address: &[String],
    dns: Option<&str>,
    server_public_key: &str,
    endpoints: &[String],
    obfuscation: &Obfuscation,
) -> String {
    let mut out = String::new();
    out.push_str("[Interface]\n");
    let key_line = match private_key {
        ClientPrivateKey::Known(k) => k.as_str(),
        ClientPrivateKey::Unknown => "<enter your private key here>",
    };
    out.push_str(&format!("PrivateKey = {key_line}\n"));
    out.push_str(&format!("Address = {}\n", address.join(", ")));
    if let Some(dns) = dns {
        out.push_str(&format!("DNS = {dns}\n"));
    }

    if obfuscation != &Obfuscation::default() {
        macro_rules! field {
            ($label:literal, $f:ident) => {
                if let Some(v) = obfuscation.$f {
                    out.push_str(&format!(concat!($label, " = {}\n"), v));
                }
            };
        }
        field!("Jc", jc);
        field!("Jmin", jmin);
        field!("Jmax", jmax);
        field!("S1", s1);
        field!("S2", s2);
        field!("H1", h1);
        field!("H2", h2);
        field!("H3", h3);
        field!("H4", h4);
    }

    out.push('\n');
    out.push_str("[Peer]\n");
    out.push_str(&format!("PublicKey = {server_public_key}\n"));
    let (primary, alternates) = endpoints
        .split_first()
        .expect("pool has >=1 node_hostnames");
    out.push_str(&format!("Endpoint = {primary}\n"));
    for alt in alternates {
        out.push_str(&format!("#Endpoint = {alt}\n"));
    }
    out.push_str("AllowedIPs = 0.0.0.0/0, ::/0\n");
    // Road-warrior clients are behind NAT by definition (phone/laptop, never a fixed public
    // peer) - without a keepalive the NAT mapping times out and the server can't reach the
    // client until it sends something first. 25s matches WireGuard's own suggested default for
    // "most" NATs.
    out.push_str("PersistentKeepalive = 25\n");
    out
}

/// Renders a client config as an in-terminal QR code (unicode block art) - scan straight off the
/// screen instead of needing a file to hand off. `invert` swaps dark/light modules - a dark-
/// themed terminal renders "dark" modules as the foreground color and "light" ones as the
/// background, the visual opposite of standard (dark-on-light) QR polarity. The official
/// WireGuard app's own scanner rejects the un-inverted default there; AmneziaWG's and a plain
/// camera read either polarity fine.
pub fn render_qr(config_text: &str, invert: bool) -> Result<String> {
    let code = qrcode::QrCode::new(config_text).context("encoding client config as a QR code")?;
    let mut renderer = code.render::<qrcode::render::unicode::Dense1x2>();
    if invert {
        // Some phone camera/scanner UIs are pickier about polarity than others when reading a
        // QR straight off a terminal (vs. a printed/rendered image) - swap dark/light modules to
        // try the other way round.
        renderer
            .dark_color(qrcode::render::unicode::Dense1x2::Light)
            .light_color(qrcode::render::unicode::Dense1x2::Dark);
    }
    Ok(renderer.build())
}

/// What `rw-add` makes: the entry to add to the pool, and the client config if one was asked for.
pub struct Added {
    pub client: RoadwarriorClient,
    pub config: Option<(ClientPrivateKey, String)>,
}

/// `rw-add`: validates, resolves/generates the client's keypair, and (if `export`/`qr`) renders
/// the client config. With `keep_private` the entry holds the generated private key instead of the
/// public one. Writing the entry into `slipmesh.yaml` is `edit::add_client`'s.
#[allow(clippy::too_many_arguments)]
pub fn add(
    mesh: &MeshConfig,
    secrets: &ResolvedSecrets,
    if_: &str,
    name: &str,
    allowed_ips_raw: &str,
    public_key: Option<&str>,
    endpoint: Option<&str>,
    export: bool,
    qr: bool,
    keep_private: bool,
) -> Result<Added> {
    if keep_private && public_key.is_some() {
        bail!("--keep-private has no private key to keep when --public-key is given");
    }
    if public_key.is_none() && !keep_private && !export && !qr {
        bail!(
            "a private key would be generated and then lost - pass --export, --qr or --keep-private, \
             or give --public-key"
        );
    }

    let pool = find_pool(mesh, if_)?;

    let allowed_ips: Vec<String> = allowed_ips_raw
        .split(',')
        .map(parse_allowed_ip)
        .collect::<Result<_>>()?;
    anyhow::ensure!(!allowed_ips.is_empty(), "--allowed-ips must not be empty");

    let (client_private_key, resolved_public_key) = match public_key {
        Some(pk) => (ClientPrivateKey::Unknown, pk.to_string()),
        None => {
            let sk = keys::generate_private_key();
            let pk = keys::public_key_from_private(&sk)?;
            (ClientPrivateKey::Known(sk), pk)
        }
    };

    check_not_duplicate(pool, name, &resolved_public_key)?;

    let client = RoadwarriorClient {
        name: name.to_owned(),
        public_key: resolved_public_key,
        private_key: match &client_private_key {
            ClientPrivateKey::Known(sk) if keep_private => Some(sk.clone()),
            _ => None,
        },
        allowed_ips,
        advanced_security: false,
    };

    if !(export || qr) {
        return Ok(Added {
            client,
            config: None,
        });
    }
    let (server_private_key, obfuscation) = pool_identity(pool, secrets)?;
    let server_public_key = keys::public_key_from_private(&server_private_key)?;
    let endpoints = pool_endpoints(mesh, pool, endpoint)?;
    let text = render_client_config(
        &client_private_key,
        &client.allowed_ips,
        resolve_dns(mesh, pool).as_deref(),
        &server_public_key,
        &endpoints,
        &obfuscation,
    );
    Ok(Added {
        client,
        config: Some((client_private_key, text)),
    })
}

/// Client `name` of pool `if_`, with its position in the pool's `clients` - what `rw-del` removes.
pub fn find_client<'a>(
    mesh: &'a MeshConfig,
    if_: &str,
    name: &str,
) -> Result<(usize, &'a RoadwarriorClient)> {
    let pool = find_pool(mesh, if_)?;
    let index = find_client_index(pool, name)?;
    Ok((index, &pool.clients[index]))
}

/// `rw-inspect`: re-renders an existing client's config/QR - never writes anything. The private
/// key is the one passed in, else the one `rw-add --keep-private` kept with the client; with
/// neither, the config carries a placeholder.
pub fn inspect(
    mesh: &MeshConfig,
    secrets: &ResolvedSecrets,
    if_: &str,
    name: &str,
    private_key: Option<&str>,
    endpoint: Option<&str>,
) -> Result<String> {
    let pool = find_pool(mesh, if_)?;
    let (_, client) = find_client(mesh, if_, name)?;

    let (server_private_key, obfuscation) = pool_identity(pool, secrets)?;
    let server_public_key = keys::public_key_from_private(&server_private_key)?;
    let endpoints = pool_endpoints(mesh, pool, endpoint)?;
    let client_private_key = match private_key {
        Some(pk) => {
            let derived = keys::public_key_from_private(pk).context("--private-key")?;
            anyhow::ensure!(
                derived == client.public_key,
                "--private-key doesn't match {name:?}'s stored public_key in slipmesh.yaml \
                 (derived {derived:?}, expected {:?}) - wrong key, or wrong client",
                client.public_key
            );
            ClientPrivateKey::Known(pk.to_string())
        }
        None => match &client.private_key {
            Some(kept) => ClientPrivateKey::Known(kept.clone()),
            None => ClientPrivateKey::Unknown,
        },
    };
    Ok(render_client_config(
        &client_private_key,
        &client.allowed_ips,
        resolve_dns(mesh, pool).as_deref(),
        &server_public_key,
        &endpoints,
        &obfuscation,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> &'static str {
        r#"cluster:
  bgp_as: 64512
  loopback_networks: {ipv4: "192.0.2.0/24", ipv6: "2001:db8::/32"}
  service_subnet: "100.64.0.0/16"
nodes:
  - {name: a, node_id: "0.0.0.1", endpoint: "192.0.2.10"}
  - {name: b, node_id: "0.0.0.2", endpoint: "192.0.2.11"}
roadwarriors:
  - name: plain
    node_hostnames: ["a", "b"]
    address: "198.51.100.1/24"
    listen_port: 51820
    plain: true
    clients:
      - {name: alice, public_key: "AAA=", allowed_ips: ["198.51.100.41/32"]}
      - {name: bob, public_key: "BBB=", allowed_ips: ["198.51.100.32/32"]}
  - name: obfuscation
    node_hostnames: ["a"]
    address: "203.0.113.1/24"
    listen_port: 51821
    obfuscation:
      jc: 4
      jmin: 81
      jmax: 408
      s1: 1114
      s2: 131
      h1: 883683258
      h2: 2249923740
      h3: 891489045
      h4: 2070706730
    clients:
      - {name: carol, public_key: "CCC=", allowed_ips: ["203.0.113.22/32"]}
"#
    }

    fn mesh() -> MeshConfig {
        yaml_serde::from_str(fixture()).unwrap()
    }

    fn secrets(mesh: &MeshConfig) -> ResolvedSecrets {
        crate::secrets::resolve(mesh).0
    }

    #[test]
    fn pool_endpoints_put_the_chosen_node_first() {
        let m = mesh();
        let pool = find_pool(&m, "plain").unwrap();
        assert_eq!(
            pool_endpoints(&m, pool, None).unwrap(),
            ["192.0.2.10:51820", "192.0.2.11:51820"]
        );
        assert_eq!(
            pool_endpoints(&m, pool, Some("b")).unwrap(),
            ["192.0.2.11:51820", "192.0.2.10:51820"]
        );
        let err = pool_endpoints(&m, pool, Some("ghost")).unwrap_err();
        assert!(err.to_string().contains("ghost"), "error was: {err}");
    }

    #[test]
    fn inspect_fills_in_a_private_key_only_when_it_matches() {
        let carol_priv = keys::generate_private_key();
        let mut m = mesh();
        m.roadwarriors[1].clients[0].public_key =
            keys::public_key_from_private(&carol_priv).unwrap();
        let inspect_carol =
            |key: Option<&str>| inspect(&m, &secrets(&m), "obfuscation", "carol", key, None);

        let cfg = inspect_carol(None).unwrap();
        assert!(cfg.contains("<enter your private key here>"), "{cfg}");
        assert!(cfg.contains("Address = 203.0.113.22/32"), "{cfg}");
        assert!(cfg.contains("Jc = 4"), "{cfg}");

        let cfg = inspect_carol(Some(&carol_priv)).unwrap();
        assert!(cfg.contains(&format!("PrivateKey = {carol_priv}")), "{cfg}");

        let err = inspect_carol(Some(&keys::generate_private_key())).unwrap_err();
        assert!(
            err.to_string().contains("doesn't match"),
            "error was: {err}"
        );
    }

    #[test]
    fn resolve_dns_prefers_the_pools_own_then_the_cluster_coredns() {
        let mut m = mesh();
        assert_eq!(
            resolve_dns(&m, &m.roadwarriors[0]),
            Some("100.64.0.10".to_string())
        );
        m.roadwarriors[0].dns = Some("9.9.9.9".to_string());
        assert_eq!(
            resolve_dns(&m, &m.roadwarriors[0]),
            Some("9.9.9.9".to_string())
        );
        m.roadwarriors[0].dns = None;
        m.cluster.service_subnet = None;
        assert_eq!(resolve_dns(&m, &m.roadwarriors[0]), None);
    }

    #[test]
    fn parse_allowed_ip_adds_a_host_prefix_only_where_none_is_given() {
        for (given, parsed) in [
            ("198.51.100.99", "198.51.100.99/32"),
            ("2001:db8::1", "2001:db8::1/128"),
            ("203.0.113.0/28", "203.0.113.0/28"),
            ("2001:db8::/120", "2001:db8::/120"),
        ] {
            assert_eq!(parse_allowed_ip(given).unwrap(), parsed);
        }
        assert!(parse_allowed_ip("not-an-ip").is_err());
        assert!(parse_allowed_ip("198.51.100.99/99").is_err());
    }

    #[test]
    fn find_client_returns_its_position_and_names_the_clients_on_a_miss() {
        let m = mesh();
        let (index, client) = find_client(&m, "plain", "bob").unwrap();
        assert_eq!((index, client.public_key.as_str()), (1, "BBB="));
        let err = find_client(&m, "plain", "nope").unwrap_err();
        assert!(err.to_string().contains("alice"), "error was: {err}");
    }

    #[test]
    fn check_not_duplicate_refuses_a_taken_name_or_key() {
        let m = mesh();
        let pool = find_pool(&m, "plain").unwrap();
        assert!(check_not_duplicate(pool, "alice", "fresh-key=").is_err());
        assert!(check_not_duplicate(pool, "fresh-name", "AAA=").is_err());
        assert!(check_not_duplicate(pool, "dave", "DDD=").is_ok());
    }

    #[test]
    fn render_client_config_includes_amneziawg_fields_for_a_non_plain_pool() {
        let m = mesh();
        let pool = find_pool(&m, "obfuscation").unwrap();
        let (server_key, obf) = pool_identity(pool, &secrets(&m)).unwrap();
        let server_pub = keys::public_key_from_private(&server_key).unwrap();
        let endpoints = pool_endpoints(&m, pool, None).unwrap();
        let cfg = render_client_config(
            &ClientPrivateKey::Unknown,
            &["203.0.113.22/32".to_string()],
            resolve_dns(&m, pool).as_deref(),
            &server_pub,
            &endpoints,
            &obf,
        );
        assert!(cfg.contains("Jc = 4"));
        assert!(cfg.contains("H4 = 2070706730"));
        assert!(cfg.contains("<enter your private key here>"));
        assert!(cfg.contains("Endpoint = 192.0.2.10:51821"));
        assert!(!cfg.contains("# Name"));
        assert!(cfg.contains("DNS = 100.64.0.10"));
        assert!(cfg.contains("PersistentKeepalive = 25"));
    }

    #[test]
    fn render_client_config_omits_amneziawg_fields_for_a_plain_pool() {
        let m = mesh();
        let pool = find_pool(&m, "plain").unwrap();
        let (server_key, obf) = pool_identity(pool, &secrets(&m)).unwrap();
        assert_eq!(obf, Obfuscation::default());
        let server_pub = keys::public_key_from_private(&server_key).unwrap();
        let endpoints = pool_endpoints(&m, pool, None).unwrap();
        let cfg = render_client_config(
            &ClientPrivateKey::Known("client-priv-key".to_string()),
            &["198.51.100.41/32".to_string()],
            resolve_dns(&m, pool).as_deref(),
            &server_pub,
            &endpoints,
            &obf,
        );
        assert!(!cfg.contains("Jc ="));
        assert!(cfg.contains("PrivateKey = client-priv-key"));
        assert!(cfg.contains("Endpoint = 192.0.2.10:51820"));
        assert!(cfg.contains("#Endpoint = 192.0.2.11:51820"));
        assert!(!cfg.contains("# Name"));
    }

    /// `add` of client `dave` to the `plain` pool.
    fn add_to_plain(public_key: Option<&str>, export: bool, keep_private: bool) -> Result<Added> {
        let m = mesh();
        add(
            &m,
            &secrets(&m),
            "plain",
            "dave",
            "198.51.100.99",
            public_key,
            None,
            export,
            false,
            keep_private,
        )
    }

    #[test]
    fn add_refuses_to_lose_a_generated_key_or_to_keep_a_missing_one() {
        let err = add_to_plain(None, false, false).err().unwrap();
        assert!(err.to_string().contains("lost"), "error was: {err}");
        let err = add_to_plain(Some("DDD="), false, true).err().unwrap();
        assert!(err.to_string().contains("--public-key"), "error was: {err}");
    }

    #[test]
    fn add_with_public_key_and_no_export_succeeds_with_no_config() {
        let added = add_to_plain(Some("DDD="), false, false).unwrap();
        assert_eq!(added.client.name, "dave");
        assert_eq!(added.client.public_key, "DDD=");
        assert_eq!(added.client.allowed_ips, ["198.51.100.99/32"]);
        assert!(added.config.is_none());
    }

    #[test]
    fn add_without_public_key_but_with_export_generates_and_returns_a_key() {
        let added = add_to_plain(None, true, false).unwrap();
        let (key, text) = added.config.unwrap();
        let ClientPrivateKey::Known(key) = key else {
            panic!("no key returned");
        };
        assert_eq!(
            keys::public_key_from_private(&key).unwrap(),
            added.client.public_key
        );
        assert!(!text.contains("<enter your private key here>"));
    }

    #[test]
    fn render_qr_invert_actually_swaps_dark_and_light() {
        let normal = render_qr("[Interface]\nPrivateKey = x\n", false).unwrap();
        let inverted = render_qr("[Interface]\nPrivateKey = x\n", true).unwrap();
        assert_ne!(normal, inverted);
    }
}
