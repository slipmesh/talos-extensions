//! `rw-add`/`rw-del`/`rw-inspect` - manage a roadwarriors pool's `clients` entries and
//! render/print client-side configs, without disturbing anything else in that hand-edited file
//! (comments, existing flow-style entries, unrelated pools).
//!
//! Each pool is its own document in `slipmesh.yaml`, and the functions here edit that one document
//! through `yaml-rt`, which applies an edit as the smallest change to the text and leaves the rest
//! of the file as written. A client is found by name (`find_client_index`) and removed by its
//! position in the pool's `clients`.

use crate::addressing;
use crate::keys;
use crate::mesh_config::{MeshConfig, RoadwarriorClient, RoadwarriorPool};
use crate::render::ResolvedSecrets;
use anyhow::{Context, Result, bail};
use common::Obfuscation;
use std::net::{IpAddr, Ipv4Addr};
use yaml_rt::{YamlDoc, YamlRt};

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
/// mesh.yaml's own order; the rest keep their relative order behind it.
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

/// A pool document as far as its clients go - every other field of it is carried over as written.
#[derive(YamlRt)]
struct PoolClients {
    #[yaml(default)]
    clients: Vec<ClientFields>,
}

/// One client entry - `RoadwarriorClient`'s own field set.
#[derive(YamlRt)]
struct ClientFields {
    name: String,
    public_key: String,
    allowed_ips: Vec<String>,
}

/// Adds one client to the `clients` of the pool at `document` in `yaml`. Everything outside that
/// one sequence - comments, the rest of the pool, formatting - is untouched.
fn add_client_to_yaml(yaml: &mut YamlDoc, document: usize, client: ClientFields) -> Result<()> {
    let mut pool: PoolClients = yaml.read_document(document)?;
    pool.clients.push(client);
    yaml.write_document(document, &pool)?;
    Ok(())
}

/// Removes `clients[client_index]` from the pool at `document` in `yaml`, line and all - same
/// "everything else untouched" guarantee as `add_client_to_yaml`.
fn remove_client_from_yaml(yaml: &mut YamlDoc, document: usize, client_index: usize) -> Result<()> {
    let clients = yaml
        .get_path_in_document(document, &["clients"])?
        .context("pool has no clients list")?;
    let mut position = 0;
    yaml.sequence_editor(clients)?.retain(|_, _| {
        let keep = position != client_index;
        position += 1;
        keep
    })?;
    Ok(())
}

/// `rw-add`: validates, resolves/generates the client's keypair, adds it to the pool at `document`
/// in `yaml`, and (if `export`/`qr`) renders the client config. This module never touches the
/// filesystem itself, see `main.rs`.
#[allow(clippy::too_many_arguments)]
pub fn add(
    mesh: &MeshConfig,
    yaml: &mut YamlDoc,
    document: usize,
    secrets: &ResolvedSecrets,
    if_: &str,
    name: &str,
    allowed_ips_raw: &str,
    public_key: Option<&str>,
    endpoint: Option<&str>,
    export: bool,
    qr: bool,
) -> Result<Option<(ClientPrivateKey, String)>> {
    if public_key.is_none() && !export && !qr {
        bail!(
            "a private key would be generated and then lost - pass --export and/or --qr, or give --public-key"
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

    add_client_to_yaml(
        yaml,
        document,
        ClientFields {
            name: name.to_owned(),
            public_key: resolved_public_key,
            allowed_ips: allowed_ips.clone(),
        },
    )?;

    if !(export || qr) {
        return Ok(None);
    }
    let (server_private_key, obfuscation) = pool_identity(pool, secrets)?;
    let server_public_key = keys::public_key_from_private(&server_private_key)?;
    let endpoints = pool_endpoints(mesh, pool, endpoint)?;
    let text = render_client_config(
        &client_private_key,
        &allowed_ips,
        resolve_dns(mesh, pool).as_deref(),
        &server_public_key,
        &endpoints,
        &obfuscation,
    );
    Ok(Some((client_private_key, text)))
}

/// `rw-del`: removes the named client from the pool at `document` in `yaml`, returning the removed
/// client's public key (printed by `main.rs` for an operator-facing audit line).
pub fn del(
    mesh: &MeshConfig,
    yaml: &mut YamlDoc,
    document: usize,
    if_: &str,
    name: &str,
) -> Result<String> {
    let pool = find_pool(mesh, if_)?;
    let client_index = find_client_index(pool, name)?;
    let public_key = pool.clients[client_index].public_key.clone();
    remove_client_from_yaml(yaml, document, client_index)?;
    Ok(public_key)
}

/// `rw-inspect`: re-renders an existing client's config/QR - never writes anything. The private
/// key is never known (never persisted anywhere, see `add`'s footgun-avoidance rule), so the
/// config always carries the placeholder.
pub fn inspect(
    mesh: &MeshConfig,
    secrets: &ResolvedSecrets,
    if_: &str,
    name: &str,
    private_key: Option<&str>,
    endpoint: Option<&str>,
) -> Result<String> {
    let pool = find_pool(mesh, if_)?;
    let client_index = find_client_index(pool, name)?;
    let client: &RoadwarriorClient = &pool.clients[client_index];

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
        None => ClientPrivateKey::Unknown,
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
        crate::render::resolve_secrets(mesh, &crate::render::NothingStored)
    }

    /// The `plain` pool as its own `slipmesh.yaml` document.
    const PLAIN_POOL: &str = r#"slipmesh:
  kind: roadwarriors
name: plain
node_hostnames: ["a", "b"]
address: "198.51.100.1/24"
listen_port: 51820
plain: true
clients:
  - {name: alice, public_key: "AAA=", allowed_ips: ["198.51.100.41/32"]}
  - {name: bob, public_key: "BBB=", allowed_ips: ["198.51.100.32/32"]}
"#;

    #[test]
    fn pool_endpoints_defaults_to_node_hostnames_order() {
        let m = mesh();
        let pool = find_pool(&m, "plain").unwrap();
        let endpoints = pool_endpoints(&m, pool, None).unwrap();
        assert_eq!(endpoints, vec!["192.0.2.10:51820", "192.0.2.11:51820"]);
    }

    #[test]
    fn pool_endpoints_promotes_the_requested_endpoint_to_primary() {
        let m = mesh();
        let pool = find_pool(&m, "plain").unwrap();
        let endpoints = pool_endpoints(&m, pool, Some("b")).unwrap();
        assert_eq!(endpoints, vec!["192.0.2.11:51820", "192.0.2.10:51820"]);
    }

    #[test]
    fn pool_endpoints_errors_on_an_endpoint_not_in_node_hostnames() {
        let m = mesh();
        let pool = find_pool(&m, "plain").unwrap();
        let err = pool_endpoints(&m, pool, Some("ghost")).unwrap_err();
        assert!(err.to_string().contains("ghost"), "error was: {err}");
    }

    #[test]
    fn inspect_with_a_matching_private_key_fills_the_config_instead_of_a_placeholder() {
        let alice_priv = keys::generate_private_key();
        let alice_pub = keys::public_key_from_private(&alice_priv).unwrap();
        let yaml = fixture().replace(
            r#"{name: alice, public_key: "AAA=", allowed_ips: ["198.51.100.41/32"]}"#,
            &format!(
                r#"{{name: alice, public_key: "{alice_pub}", allowed_ips: ["198.51.100.41/32"]}}"#
            ),
        );
        let m: MeshConfig = yaml_serde::from_str(&yaml).unwrap();
        let cfg = inspect(&m, &secrets(&m), "plain", "alice", Some(&alice_priv), None).unwrap();
        assert!(cfg.contains(&format!("PrivateKey = {alice_priv}")));
        assert!(!cfg.contains("<enter your private key here>"));
    }

    #[test]
    fn inspect_rejects_a_private_key_that_does_not_match_the_stored_public_key() {
        let m = mesh();
        let wrong_priv = keys::generate_private_key();
        let err = inspect(&m, &secrets(&m), "plain", "alice", Some(&wrong_priv), None).unwrap_err();
        assert!(
            err.to_string().contains("doesn't match"),
            "error was: {err}"
        );
    }

    #[test]
    fn resolve_dns_falls_back_to_service_subnet_derived_coredns_ip() {
        let m = mesh();
        let pool = find_pool(&m, "plain").unwrap();
        assert_eq!(resolve_dns(&m, pool), Some("100.64.0.10".to_string()));
    }

    #[test]
    fn resolve_dns_prefers_an_explicit_pool_dns_over_the_derived_default() {
        let yaml = r#"cluster:
  bgp_as: 64512
  loopback_networks: {ipv4: "192.0.2.0/24", ipv6: "2001:db8::/32"}
  service_subnet: "100.64.0.0/16"
nodes:
  - {name: a, node_id: "0.0.0.1", endpoint: "192.0.2.10"}
roadwarriors:
  - name: plain
    node_hostnames: ["a"]
    address: "198.51.100.1/24"
    listen_port: 51820
    plain: true
    dns: "9.9.9.9"
    clients: []
"#;
        let m: MeshConfig = yaml_serde::from_str(yaml).unwrap();
        let pool = find_pool(&m, "plain").unwrap();
        assert_eq!(resolve_dns(&m, pool), Some("9.9.9.9".to_string()));
    }

    #[test]
    fn resolve_dns_is_none_without_an_explicit_dns_or_a_service_subnet() {
        let yaml = r#"cluster:
  bgp_as: 64512
  loopback_networks: {ipv4: "192.0.2.0/24", ipv6: "2001:db8::/32"}
nodes:
  - {name: a, node_id: "0.0.0.1", endpoint: "192.0.2.10"}
roadwarriors:
  - name: plain
    node_hostnames: ["a"]
    address: "198.51.100.1/24"
    listen_port: 51820
    plain: true
    clients: []
"#;
        let m: MeshConfig = yaml_serde::from_str(yaml).unwrap();
        let pool = find_pool(&m, "plain").unwrap();
        assert_eq!(resolve_dns(&m, pool), None);
    }

    #[test]
    fn parse_allowed_ip_normalizes_bare_v4_to_slash_32() {
        assert_eq!(
            parse_allowed_ip("198.51.100.99").unwrap(),
            "198.51.100.99/32"
        );
    }

    #[test]
    fn parse_allowed_ip_normalizes_bare_v6_to_slash_128() {
        assert_eq!(parse_allowed_ip("2001:db8::1").unwrap(), "2001:db8::1/128");
    }

    #[test]
    fn parse_allowed_ip_leaves_an_explicit_prefix_untouched() {
        assert_eq!(
            parse_allowed_ip("203.0.113.0/28").unwrap(),
            "203.0.113.0/28"
        );
        assert_eq!(
            parse_allowed_ip("2001:db8::/120").unwrap(),
            "2001:db8::/120"
        );
    }

    #[test]
    fn parse_allowed_ip_rejects_garbage() {
        assert!(parse_allowed_ip("not-an-ip").is_err());
        assert!(parse_allowed_ip("198.51.100.99/99").is_err());
    }

    #[test]
    fn find_pool_errors_with_known_names_on_miss() {
        let err = find_pool(&mesh(), "nope").unwrap_err();
        assert!(err.to_string().contains("plain"), "error was: {err}");
        assert!(err.to_string().contains("obfuscation"), "error was: {err}");
    }

    #[test]
    fn find_client_index_errors_with_known_names_on_miss() {
        let m = mesh();
        let pool = find_pool(&m, "plain").unwrap();
        let err = find_client_index(pool, "nope").unwrap_err();
        assert!(err.to_string().contains("alice"), "error was: {err}");
    }

    #[test]
    fn check_not_duplicate_rejects_existing_name() {
        let m = mesh();
        let pool = find_pool(&m, "plain").unwrap();
        assert!(check_not_duplicate(pool, "alice", "fresh-key=").is_err());
    }

    #[test]
    fn check_not_duplicate_rejects_existing_public_key() {
        let m = mesh();
        let pool = find_pool(&m, "plain").unwrap();
        assert!(check_not_duplicate(pool, "fresh-name", "AAA=").is_err());
    }

    #[test]
    fn check_not_duplicate_accepts_a_genuinely_new_client() {
        let m = mesh();
        let pool = find_pool(&m, "plain").unwrap();
        assert!(check_not_duplicate(pool, "dave", "DDD=").is_ok());
    }

    fn client(name: &str) -> ClientFields {
        ClientFields {
            name: name.to_owned(),
            public_key: format!("{name}="),
            allowed_ips: vec!["198.51.100.99/32".to_owned()],
        }
    }

    /// `source` after `edit`, as the text it comes back as.
    fn edited(source: &str, edit: impl FnOnce(&mut YamlDoc)) -> String {
        let mut yaml = YamlDoc::parse(source).unwrap();
        edit(&mut yaml);
        yaml.to_string()
    }

    fn client_names(source: &str) -> Vec<String> {
        let value: yaml_serde::Value = yaml_serde::from_str(source).unwrap();
        value["clients"]
            .as_sequence()
            .unwrap()
            .iter()
            .map(|c| c["name"].as_str().unwrap().to_owned())
            .collect()
    }

    #[test]
    fn add_client_to_yaml_appends_and_leaves_the_rest_untouched() {
        let out = edited(PLAIN_POOL, |yaml| {
            add_client_to_yaml(yaml, 0, client("dave")).unwrap()
        });
        assert!(out.starts_with(PLAIN_POOL), "{out}");
        assert_eq!(client_names(&out), ["alice", "bob", "dave"]);
    }

    #[test]
    fn add_client_to_yaml_starts_the_list_a_pool_lacks() {
        let pool = PLAIN_POOL.split("clients:").next().unwrap();
        let out = edited(pool, |yaml| {
            add_client_to_yaml(yaml, 0, client("dave")).unwrap()
        });
        assert!(out.starts_with(pool), "{out}");
        assert_eq!(client_names(&out), ["dave"]);
    }

    #[test]
    fn remove_client_from_yaml_deletes_exactly_the_target() {
        let out = edited(PLAIN_POOL, |yaml| {
            remove_client_from_yaml(yaml, 0, 0).unwrap() // alice
        });
        assert_eq!(
            out,
            PLAIN_POOL.replace(
                "  - {name: alice, public_key: \"AAA=\", allowed_ips: [\"198.51.100.41/32\"]}\n",
                ""
            )
        );
    }

    #[test]
    fn append_onto_an_empty_flow_clients_list() {
        let src = r#"slipmesh:
  kind: roadwarriors
name: fresh
node_hostnames: ["a"]
address: "198.51.100.250/24"
listen_port: 51830
clients: []
"#;
        let out = edited(src, |yaml| {
            add_client_to_yaml(yaml, 0, client("eve")).unwrap()
        });
        assert!(
            out.starts_with(&src[..src.find("clients").unwrap()]),
            "{out}"
        );
        assert_eq!(client_names(&out), ["eve"]);
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

    /// `add` on `PLAIN_POOL`: the pool as it comes back, and what `add` returned.
    fn add_to_plain(
        public_key: Option<&str>,
        export: bool,
    ) -> Result<(String, Option<(ClientPrivateKey, String)>)> {
        let m = mesh();
        let mut yaml = YamlDoc::parse(PLAIN_POOL).unwrap();
        let config = add(
            &m,
            &mut yaml,
            0,
            &secrets(&m),
            "plain",
            "dave",
            "198.51.100.99",
            public_key,
            None,
            export,
            false,
        )?;
        Ok((yaml.to_string(), config))
    }

    #[test]
    fn add_requires_export_or_qr_when_public_key_is_omitted() {
        let err = add_to_plain(None, false).unwrap_err();
        assert!(err.to_string().contains("lost"), "error was: {err}");
    }

    #[test]
    fn add_with_public_key_and_no_export_succeeds_with_no_config() {
        let (updated, config) = add_to_plain(Some("DDD="), false).unwrap();
        assert_eq!(client_names(&updated), ["alice", "bob", "dave"]);
        assert!(config.is_none());
    }

    #[test]
    fn add_without_public_key_but_with_export_generates_and_returns_a_key() {
        let (updated, config) = add_to_plain(None, true).unwrap();
        assert!(updated.contains("dave"));
        let (key, text) = config.unwrap();
        assert!(matches!(key, ClientPrivateKey::Known(_)));
        assert!(!text.contains("<enter your private key here>"));
    }

    #[test]
    fn del_removes_the_named_client_and_returns_its_public_key() {
        let m = mesh();
        let mut yaml = YamlDoc::parse(PLAIN_POOL).unwrap();
        let public_key = del(&m, &mut yaml, 0, "plain", "alice").unwrap();
        assert_eq!(client_names(&yaml.to_string()), ["bob"]);
        assert_eq!(public_key, "AAA=");
    }

    #[test]
    fn del_on_unknown_client_errors() {
        let m = mesh();
        let mut yaml = YamlDoc::parse(PLAIN_POOL).unwrap();
        assert!(del(&m, &mut yaml, 0, "plain", "nope").is_err());
    }

    #[test]
    fn render_qr_produces_nonempty_output() {
        let qr = render_qr("[Interface]\nPrivateKey = x\n", false).unwrap();
        assert!(!qr.trim().is_empty());
    }

    #[test]
    fn render_qr_invert_actually_swaps_dark_and_light() {
        let normal = render_qr("[Interface]\nPrivateKey = x\n", false).unwrap();
        let inverted = render_qr("[Interface]\nPrivateKey = x\n", true).unwrap();
        assert_ne!(normal, inverted);
    }

    #[test]
    fn inspect_renders_the_same_config_shape_as_add_with_a_placeholder_key() {
        let m = mesh();
        let cfg = inspect(&m, &secrets(&m), "obfuscation", "carol", None, None).unwrap();
        assert!(cfg.contains("<enter your private key here>"));
        assert!(cfg.contains("Address = 203.0.113.22/32"));
        assert!(cfg.contains("Jc = 4"));
    }
}
