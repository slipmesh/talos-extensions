//! `rw-add`/`rw-del`/`rw-inspect` - manage `mesh.yaml`'s `roadwarriors[].clients` entries and
//! render/print client-side configs, without disturbing anything else in that hand-edited file
//! (comments, existing flow-style entries, unrelated pools).
//!
//! `mesh.yaml` is edited via `yamlpatch` (comment/format-preserving YAML patch operations, part
//! of the `zizmor` project), addressed by numeric `Route` (no path-predicate syntax - the pool/
//! client index has to be found by hand first, see `find_pool`/`find_client_index`), not by a
//! hand-rolled text scan: a scan cannot add an entry without reflowing what surrounds it.

use crate::addressing;
use crate::existing::FileExistingState;
use crate::keys;
use crate::mesh_config::{MeshConfig, RoadwarriorClient, RoadwarriorPool};
use crate::render::{self, ExistingState};
use anyhow::{Context, Result, bail};
use common::Obfuscation;
use std::net::{IpAddr, Ipv4Addr};
use std::path::Path;

/// A private key we know (was just generated, or given via `--public-key`'s absence) vs. one we
/// never had (given via `--public-key`, or looking up an existing client with `rw-inspect`).
#[derive(Debug)]
pub enum ClientPrivateKey {
    Known(String),
    Unknown,
}

/// Finds a `roadwarriors[]` pool by `name`, returning its index (needed for `yamlpath::Route`,
/// which addresses by position, not by a `name==` predicate) alongside the pool itself.
fn find_pool<'a>(mesh: &'a MeshConfig, if_: &str) -> Result<(usize, &'a RoadwarriorPool)> {
    mesh.roadwarriors
        .iter()
        .enumerate()
        .find(|(_, p)| p.name == if_)
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

/// The pool's own resolved server identity: private key (mesh.yaml explicit -> existing
/// `patches/<node>.yaml` -> fresh generation, same tiers `generate` itself uses) and obfuscation
/// (empty for a `plain` pool, resolved the same way otherwise) - never a second, independently
/// generated set of values that could drift from what `generate` actually puts on the wire.
fn resolve_pool_identity(
    mesh: &MeshConfig,
    pool: &RoadwarriorPool,
    patches_dir: &Path,
) -> Result<(String, Obfuscation)> {
    let existing = FileExistingState::new(mesh, patches_dir)?;
    let private_key = render::resolve_string(
        pool.private_key.as_deref(),
        existing.roadwarrior_private_key(&pool.name),
        keys::generate_private_key,
    );
    let obfuscation = if pool.plain {
        Obfuscation::default()
    } else {
        render::resolve_obfuscation(
            &pool.obfuscation,
            &mesh.obfuscation,
            existing.roadwarrior_obfuscation(&pool.name).as_ref(),
        )
    };
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
pub(crate) fn render_qr(config_text: &str, invert: bool) -> Result<String> {
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

/// `yaml_serde::Value` for one flow-style client entry - name/public_key/allowed_ips, matching
/// `RoadwarriorClient`'s own field set.
fn client_value(name: &str, public_key: &str, allowed_ips: &[String]) -> yaml_serde::Value {
    let mut map = yaml_serde::Mapping::new();
    map.insert("name".into(), name.into());
    map.insert("public_key".into(), public_key.into());
    map.insert(
        "allowed_ips".into(),
        yaml_serde::Value::Sequence(allowed_ips.iter().map(|s| s.as_str().into()).collect()),
    );
    yaml_serde::Value::Mapping(map)
}

/// `yamlpatch::serialize_flow` pads `{ ` / ` }` - mesh.yaml's existing convention doesn't.
fn flow_style(value: &yaml_serde::Value) -> Result<String> {
    let s = yamlpatch::serialize_flow(value).context("rendering flow-style YAML")?;
    let s = s
        .strip_prefix("{ ")
        .map(|rest| format!("{{{rest}"))
        .unwrap_or(s);
    let s = s
        .strip_suffix(" }")
        .map(|rest| format!("{rest}}}"))
        .unwrap_or(s);
    Ok(s)
}

/// Appends one flow-style item to an existing block-sequence feature, in the same style
/// `mesh.yaml`'s existing client entries already use.
fn append_flow_item(
    doc: &yamlpath::Document,
    feature: &yamlpath::Feature,
    value: &yaml_serde::Value,
) -> Result<String> {
    let indent = yamlpatch::extract_leading_whitespace(doc, feature);
    let value_str = flow_style(value)?;
    let insertion_point = yamlpatch::find_content_end(feature, doc);
    let source = doc.source();
    let needs_leading_newline = !source[..insertion_point].ends_with('\n');
    let mut new_item = String::new();
    if needs_leading_newline {
        new_item.push('\n');
    }
    new_item.push_str(&format!("{indent}- {value_str}"));
    let mut result = source.to_string();
    result.insert_str(insertion_point, &new_item);
    Ok(result)
}

/// A pool whose `clients:` is still `[]` (empty flow sequence) doesn't go through
/// `append_flow_item` - `yamlpath`/`yamlpatch` only support appending onto a *block* sequence.
/// Replace the `[]` span directly with a one-item block sequence instead.
fn replace_empty_flow_sequence(
    doc: &yamlpath::Document,
    feature: &yamlpath::Feature,
    value: &yaml_serde::Value,
) -> Result<String> {
    let indent = yamlpatch::extract_leading_whitespace(doc, feature);
    let value_str = flow_style(value)?;
    let (start, end) = feature.location.byte_span;
    let mut result = doc.source().to_string();
    result.replace_range(start..end, &format!("\n{indent}- {value_str}"));
    Ok(result)
}

/// Adds one client to `roadwarriors[pool_index].clients` in `source`, returning the whole updated
/// file. Everything outside that one sequence - comments, other pools, unrelated formatting - is
/// untouched.
pub(crate) fn add_client_to_yaml(
    source: &str,
    pool_index: usize,
    value: &yaml_serde::Value,
) -> Result<String> {
    let doc = yamlpath::Document::new(source).context("parsing mesh.yaml")?;
    let route = yamlpath::route!["roadwarriors", pool_index, "clients"];
    let feature = yamlpatch::route_to_feature_exact(&route, &doc)
        .context("querying clients list")?
        .context("pool has no clients list")?;
    match yamlpatch::Style::from_feature(&feature, &doc) {
        yamlpatch::Style::BlockSequence => append_flow_item(&doc, &feature, value),
        yamlpatch::Style::FlowSequence if doc.extract(&feature).trim() == "[]" => {
            replace_empty_flow_sequence(&doc, &feature, value)
        }
        other => {
            bail!("clients list has unsupported YAML style {other:?} - expected a block sequence")
        }
    }
}

/// Removes `roadwarriors[pool_index].clients[client_index]` from `source`, returning the whole
/// updated file - same "everything else untouched" guarantee as `add_client_to_yaml`.
pub(crate) fn remove_client_from_yaml(
    source: &str,
    pool_index: usize,
    client_index: usize,
) -> Result<String> {
    let doc = yamlpath::Document::new(source).context("parsing mesh.yaml")?;
    let route = yamlpath::route!["roadwarriors", pool_index, "clients", client_index];
    let patch = yamlpatch::Patch {
        route,
        operation: yamlpatch::Op::Remove,
    };
    let out = yamlpatch::apply_yaml_patches(&doc, std::slice::from_ref(&patch))
        .context("removing client from mesh.yaml")?;
    Ok(out.source().to_string())
}

/// `rw-add`: validates, resolves/generates the client's keypair, patches `mesh.yaml`, and
/// (if `export`/`qr`) prints the client config/QR. Returns the updated `mesh.yaml` content for
/// the caller to write - this module never touches the filesystem itself, see `main.rs`.
#[allow(clippy::too_many_arguments)]
pub fn add(
    mesh: &MeshConfig,
    source: &str,
    patches_dir: &Path,
    if_: &str,
    name: &str,
    allowed_ips_raw: &str,
    public_key: Option<&str>,
    endpoint: Option<&str>,
    export: bool,
    qr: bool,
) -> Result<(String, Option<(ClientPrivateKey, String)>)> {
    if public_key.is_none() && !export && !qr {
        bail!(
            "a private key would be generated and then lost - pass --export and/or --qr, or give --public-key"
        );
    }

    let (pool_index, pool) = find_pool(mesh, if_)?;

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

    let value = client_value(name, &resolved_public_key, &allowed_ips);
    let updated = add_client_to_yaml(source, pool_index, &value)?;

    let config = if export || qr {
        let (server_private_key, obfuscation) = resolve_pool_identity(mesh, pool, patches_dir)?;
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
        Some((client_private_key, text))
    } else {
        None
    };

    Ok((updated, config))
}

/// `rw-del`: patches `mesh.yaml` to remove the named client, returning the updated content and
/// the removed client (name printed by `main.rs` for an operator-facing audit line).
pub fn del(mesh: &MeshConfig, source: &str, if_: &str, name: &str) -> Result<(String, String)> {
    let (pool_index, pool) = find_pool(mesh, if_)?;
    let client_index = find_client_index(pool, name)?;
    let public_key = pool.clients[client_index].public_key.clone();
    let updated = remove_client_from_yaml(source, pool_index, client_index)?;
    Ok((updated, public_key))
}

/// `rw-inspect`: re-renders an existing client's config/QR - never writes anything. The private
/// key is never known (never persisted anywhere, see `add`'s footgun-avoidance rule), so the
/// config always carries the placeholder.
pub fn inspect(
    mesh: &MeshConfig,
    patches_dir: &Path,
    if_: &str,
    name: &str,
    private_key: Option<&str>,
    endpoint: Option<&str>,
) -> Result<String> {
    let (_, pool) = find_pool(mesh, if_)?;
    let client_index = find_client_index(pool, name)?;
    let client: &RoadwarriorClient = &pool.clients[client_index];

    let (server_private_key, obfuscation) = resolve_pool_identity(mesh, pool, patches_dir)?;
    let server_public_key = keys::public_key_from_private(&server_private_key)?;
    let endpoints = pool_endpoints(mesh, pool, endpoint)?;
    let client_private_key = match private_key {
        Some(pk) => {
            let derived = keys::public_key_from_private(pk).context("--private-key")?;
            anyhow::ensure!(
                derived == client.public_key,
                "--private-key doesn't match {name:?}'s stored public_key in mesh.yaml \
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
        serde_yaml::from_str(fixture()).unwrap()
    }

    #[test]
    fn pool_endpoints_defaults_to_node_hostnames_order() {
        let m = mesh();
        let (_, pool) = find_pool(&m, "plain").unwrap();
        let endpoints = pool_endpoints(&m, pool, None).unwrap();
        assert_eq!(endpoints, vec!["192.0.2.10:51820", "192.0.2.11:51820"]);
    }

    #[test]
    fn pool_endpoints_promotes_the_requested_endpoint_to_primary() {
        let m = mesh();
        let (_, pool) = find_pool(&m, "plain").unwrap();
        let endpoints = pool_endpoints(&m, pool, Some("b")).unwrap();
        assert_eq!(endpoints, vec!["192.0.2.11:51820", "192.0.2.10:51820"]);
    }

    #[test]
    fn pool_endpoints_errors_on_an_endpoint_not_in_node_hostnames() {
        let m = mesh();
        let (_, pool) = find_pool(&m, "plain").unwrap();
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
        let m: MeshConfig = serde_yaml::from_str(&yaml).unwrap();
        let cfg = inspect(
            &m,
            Path::new("/nonexistent"),
            "plain",
            "alice",
            Some(&alice_priv),
            None,
        )
        .unwrap();
        assert!(cfg.contains(&format!("PrivateKey = {alice_priv}")));
        assert!(!cfg.contains("<enter your private key here>"));
    }

    #[test]
    fn inspect_rejects_a_private_key_that_does_not_match_the_stored_public_key() {
        let m = mesh();
        let wrong_priv = keys::generate_private_key();
        let err = inspect(
            &m,
            Path::new("/nonexistent"),
            "plain",
            "alice",
            Some(&wrong_priv),
            None,
        )
        .unwrap_err();
        assert!(
            err.to_string().contains("doesn't match"),
            "error was: {err}"
        );
    }

    #[test]
    fn resolve_dns_falls_back_to_service_subnet_derived_coredns_ip() {
        let m = mesh();
        let (_, pool) = find_pool(&m, "plain").unwrap();
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
        let m: MeshConfig = serde_yaml::from_str(yaml).unwrap();
        let (_, pool) = find_pool(&m, "plain").unwrap();
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
        let m: MeshConfig = serde_yaml::from_str(yaml).unwrap();
        let (_, pool) = find_pool(&m, "plain").unwrap();
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
        let (_, pool) = find_pool(&m, "plain").unwrap();
        let err = find_client_index(pool, "nope").unwrap_err();
        assert!(err.to_string().contains("alice"), "error was: {err}");
    }

    #[test]
    fn check_not_duplicate_rejects_existing_name() {
        let m = mesh();
        let (_, pool) = find_pool(&m, "plain").unwrap();
        assert!(check_not_duplicate(pool, "alice", "fresh-key=").is_err());
    }

    #[test]
    fn check_not_duplicate_rejects_existing_public_key() {
        let m = mesh();
        let (_, pool) = find_pool(&m, "plain").unwrap();
        assert!(check_not_duplicate(pool, "fresh-name", "AAA=").is_err());
    }

    #[test]
    fn check_not_duplicate_accepts_a_genuinely_new_client() {
        let m = mesh();
        let (_, pool) = find_pool(&m, "plain").unwrap();
        assert!(check_not_duplicate(pool, "dave", "DDD=").is_ok());
    }

    #[test]
    fn add_client_to_yaml_appends_flow_style_and_leaves_the_rest_untouched() {
        let value = client_value("dave", "DDD=", &["198.51.100.99/32".to_string()]);
        let out = add_client_to_yaml(fixture(), 0, &value).unwrap();
        assert!(
            out.contains(
                r#"- {name: dave, public_key: "DDD=", allowed_ips: ["198.51.100.99/32"]}"#
            )
        );
        // untouched: the other pool, and its own clients/obfuscation
        assert!(out.contains("carol"));
        assert!(out.contains("jc: 4"));
        assert!(out.contains("h4: 2070706730"));
        // untouched: existing entries in the same pool
        assert!(
            out.contains(r#"{name: alice, public_key: "AAA=", allowed_ips: ["198.51.100.41/32"]}"#)
        );
    }

    #[test]
    fn add_client_to_yaml_errors_on_unknown_pool_index() {
        let value = client_value("dave", "DDD=", &["198.51.100.99/32".to_string()]);
        assert!(add_client_to_yaml(fixture(), 99, &value).is_err());
    }

    #[test]
    fn remove_client_from_yaml_deletes_exactly_the_target() {
        let out = remove_client_from_yaml(fixture(), 0, 0).unwrap(); // alice
        assert!(!out.contains("alice"));
        assert!(out.contains("bob"));
        assert!(out.contains("carol"));
        assert!(out.contains("jc: 4"));
    }

    #[test]
    fn append_onto_an_empty_flow_clients_list() {
        let src = r#"roadwarriors:
  - name: fresh
    node_hostnames: ["a"]
    address: "198.51.100.250/24"
    listen_port: 51830
    clients: []
"#;
        let value = client_value("eve", "EEE=", &["198.51.100.5/32".to_string()]);
        let out = add_client_to_yaml(src, 0, &value).unwrap();
        assert!(
            out.contains(r#"- {name: eve, public_key: "EEE=", allowed_ips: ["198.51.100.5/32"]}"#)
        );
    }

    #[test]
    fn render_client_config_includes_amneziawg_fields_for_a_non_plain_pool() {
        let m = mesh();
        let (_, pool) = find_pool(&m, "obfuscation").unwrap();
        let (server_key, obf) = resolve_pool_identity(&m, pool, Path::new("/nonexistent")).unwrap();
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
        let (_, pool) = find_pool(&m, "plain").unwrap();
        let (server_key, obf) = resolve_pool_identity(&m, pool, Path::new("/nonexistent")).unwrap();
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

    #[test]
    fn add_requires_export_or_qr_when_public_key_is_omitted() {
        let m = mesh();
        let err = add(
            &m,
            fixture(),
            Path::new("/nonexistent"),
            "plain",
            "dave",
            "198.51.100.99",
            None,
            None,
            false,
            false,
        )
        .unwrap_err();
        assert!(err.to_string().contains("lost"), "error was: {err}");
    }

    #[test]
    fn add_with_public_key_and_no_export_succeeds_with_no_config() {
        let m = mesh();
        let (updated, config) = add(
            &m,
            fixture(),
            Path::new("/nonexistent"),
            "plain",
            "dave",
            "198.51.100.99",
            Some("DDD="),
            None,
            false,
            false,
        )
        .unwrap();
        assert!(updated.contains("dave"));
        assert!(config.is_none());
    }

    #[test]
    fn add_without_public_key_but_with_export_generates_and_returns_a_key() {
        let m = mesh();
        let (updated, config) = add(
            &m,
            fixture(),
            Path::new("/nonexistent"),
            "plain",
            "dave",
            "198.51.100.99",
            None,
            None,
            true,
            false,
        )
        .unwrap();
        assert!(updated.contains("dave"));
        let (key, text) = config.unwrap();
        assert!(matches!(key, ClientPrivateKey::Known(_)));
        assert!(!text.contains("<enter your private key here>"));
    }

    #[test]
    fn del_removes_the_named_client_and_returns_its_public_key() {
        let m = mesh();
        let (updated, public_key) = del(&m, fixture(), "plain", "alice").unwrap();
        assert!(!updated.contains("alice"));
        assert_eq!(public_key, "AAA=");
    }

    #[test]
    fn del_on_unknown_client_errors() {
        let m = mesh();
        assert!(del(&m, fixture(), "plain", "nope").is_err());
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
        let cfg = inspect(
            &m,
            Path::new("/nonexistent"),
            "obfuscation",
            "carol",
            None,
            None,
        )
        .unwrap();
        assert!(cfg.contains("<enter your private key here>"));
        assert!(cfg.contains("Address = 203.0.113.22/32"));
        assert!(cfg.contains("Jc = 4"));
    }
}
