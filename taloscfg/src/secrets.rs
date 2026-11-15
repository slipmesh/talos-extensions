//! The topology's secrets, with whatever `slipmesh.yaml` leaves unset generated: every node's mesh
//! private key, every link's and pool's obfuscation, every pool's private key. What was generated
//! comes back as `Minted` for `edit::record` to write into the field it belongs to - the next run
//! finds it there and generates nothing.
//!
//! They are resolved once for the whole topology, not per node: a link's two ends need the same
//! obfuscation, and rendering node A's config needs node B's private key.

use crate::obfuscation_gen;
use sliplib_config::Obfuscation;
use sliplib_config::mesh_config::MeshConfig;
use sliplib_mesh::secrets::{ResolvedSecrets, link_key};
use sliplib_secrets::wireguard::PrivateKey;

/// What a run generated, by the entry it belongs to.
#[derive(Default)]
pub struct Minted {
    /// By the node's position in `nodes`.
    pub node_keys: Vec<(usize, PrivateKey)>,
    /// By the link's position in `mesh.links`; only the fields generated.
    pub link_obfuscation: Vec<(usize, Obfuscation)>,
    pub pools: Vec<PoolMinted>,
    /// How a message names each value.
    names: Vec<String>,
}

pub struct PoolMinted {
    pub name: String,
    pub private_key: Option<PrivateKey>,
    /// Only the fields generated.
    pub obfuscation: Option<Obfuscation>,
}

impl Minted {
    pub fn is_empty(&self) -> bool {
        self.names.is_empty()
    }

    /// Where each value goes, the way a message names it.
    pub fn routes(&self) -> &[String] {
        &self.names
    }
}

/// Generates whatever of `obfuscation` is still unset - see `obfuscation_gen`'s own doc comment
/// for why that only ever fills in the "original nine" fields - and returns the fields generated,
/// `None` when there were none.
fn mint_obfuscation(obfuscation: &mut Obfuscation) -> Option<Obfuscation> {
    let fresh = obfuscation_gen::generate();
    let mut generated = Obfuscation::default();
    macro_rules! field {
        ($($f:ident),*) => {
            $(if obfuscation.$f.is_none() {
                generated.$f = fresh.$f.clone();
                obfuscation.$f = fresh.$f.clone();
            })*
        };
    }
    field!(
        jc,
        jmin,
        jmax,
        s1,
        s2,
        s3,
        s4,
        h1,
        h2,
        h3,
        h4,
        i1,
        i2,
        i3,
        i4,
        i5,
        header_protection_key,
        content_padding_addition,
        rekey_after_time,
        rekey_timeout,
        reject_after_time,
        keepalive_timeout,
        max_handshake_attempts,
        random_trailers,
        disable_cookies
    );
    (generated != Obfuscation::default()).then_some(generated)
}

/// The secrets `topology` sets, with the rest generated. A `plain` link or pool gets no
/// obfuscation generated: it would turn "no obfuscation" back into an obfuscated one.
pub fn resolve(topology: &MeshConfig) -> (ResolvedSecrets, Minted) {
    let mut resolved = sliplib_mesh::secrets::read(topology);
    let mut minted = Minted::default();

    for (index, node) in topology.nodes.iter().enumerate() {
        if resolved.mesh_private_keys.contains_key(&node.name) {
            continue;
        }
        let key = PrivateKey::generate();
        minted.node_keys.push((index, key.clone()));
        minted
            .names
            .push(format!("nodes[{}].mesh_private_key", node.name));
        resolved.mesh_private_keys.insert(node.name.clone(), key);
    }

    for (index, link) in topology.mesh.links.iter().enumerate() {
        if link.plain {
            continue;
        }
        let pair = link_key(&link.pair);
        let obfuscation = resolved
            .mesh_link_obfuscation
            .entry(pair.clone())
            .or_default();
        if let Some(generated) = mint_obfuscation(obfuscation) {
            minted.link_obfuscation.push((index, generated));
            minted.names.push(format!("mesh.links[{pair}].obfuscation"));
        }
    }

    for pool in &topology.roadwarriors {
        let private_key = (!resolved.roadwarrior_private_keys.contains_key(&pool.name))
            .then(PrivateKey::generate);
        if let Some(key) = &private_key {
            minted
                .names
                .push(format!("roadwarriors[{}].private_key", pool.name));
            resolved
                .roadwarrior_private_keys
                .insert(pool.name.clone(), key.clone());
        }
        let obfuscation = if pool.plain {
            None
        } else {
            mint_obfuscation(
                resolved
                    .roadwarrior_obfuscation
                    .entry(pool.name.clone())
                    .or_default(),
            )
        };
        if obfuscation.is_some() {
            minted
                .names
                .push(format!("roadwarriors[{}].obfuscation", pool.name));
        }
        if private_key.is_some() || obfuscation.is_some() {
            minted.pools.push(PoolMinted {
                name: pool.name.clone(),
                private_key,
                obfuscation,
            });
        }
    }

    (resolved, minted)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The 3.1 switches are never invented: `generate()` leaves them unset, so an
    /// unconfigured mesh stays as it was.
    #[test]
    fn mint_obfuscation_carries_the_31_switches_and_never_generates_them() {
        let mut resolved = Obfuscation {
            random_trailers: Some(true),
            ..Obfuscation::default()
        };
        let generated = mint_obfuscation(&mut resolved).unwrap();
        assert_eq!(resolved.random_trailers, Some(true));
        assert_eq!(resolved.disable_cookies, None);
        assert_eq!(generated.random_trailers, None);
    }

    #[test]
    fn mint_obfuscation_generates_when_nothing_else_is_set() {
        let mut resolved = Obfuscation::default();
        let generated = mint_obfuscation(&mut resolved).unwrap();
        assert!(resolved.jc.is_some());
        assert!(resolved.h1.is_some());
        assert_eq!(resolved, generated);
    }

    #[test]
    fn mint_obfuscation_reports_as_generated_only_what_no_layer_set() {
        let mut resolved = Obfuscation {
            jc: Some(9),
            h1: Some(42),
            ..Obfuscation::default()
        };
        let generated = mint_obfuscation(&mut resolved).unwrap();
        assert_eq!((generated.jc, generated.h1), (None, None));
        assert_eq!(generated.jmin, resolved.jmin);
        assert!(generated.jmin.is_some());
    }

    fn topology() -> MeshConfig {
        sliplib_yaml::from_str(
            r#"
cluster:
  bgp_as: 64512
  loopback_networks: {ipv4: "198.51.100.0/25", ipv6: "3fff::/32"}
nodes:
  - {name: a, node_id: "198.51.100.1"}
  - {name: b, node_id: "198.51.100.2"}
mesh:
  links:
    - {pair: [b, a], port: 51820}
roadwarriors:
  - name: obfuscated
    node_hostnames: [a]
    address: "203.0.113.1/27"
    listen_port: 51900
    obfuscation: {jc: 4, jmin: 10, jmax: 50, s1: 1, s2: 2, h1: 5, h2: 6, h3: 7, h4: 8}
  - name: plain
    node_hostnames: [b]
    address: "203.0.113.33/27"
    listen_port: 51901
    plain: true
"#,
        )
        .unwrap()
    }

    #[test]
    fn resolve_uses_explicit_node_private_key() {
        let mut topology = topology();
        topology.nodes[0].mesh_private_key = Some("explicit-key".into());
        let (resolved, minted) = resolve(&topology);
        assert_eq!(resolved.mesh_private_keys["a"], "explicit-key".into());
        assert_eq!(minted.node_keys.len(), 1);
        assert_eq!(minted.node_keys[0].0, 1);
    }

    #[test]
    fn resolve_plain_link_skips_obfuscation_generation_entirely() {
        let mut topology = topology();
        topology.mesh.links[0].plain = true;
        let (resolved, minted) = resolve(&topology);
        let obfuscation = &resolved.mesh_link_obfuscation[&link_key(&topology.mesh.links[0].pair)];
        assert_eq!(obfuscation, &Obfuscation::default());
        assert!(minted.link_obfuscation.is_empty());
    }

    #[test]
    fn resolve_non_plain_link_still_generates_obfuscation() {
        let topology = topology();
        let (resolved, _) = resolve(&topology);
        let obfuscation = &resolved.mesh_link_obfuscation[&link_key(&topology.mesh.links[0].pair)];
        assert_ne!(obfuscation, &Obfuscation::default());
    }

    #[test]
    fn resolve_plain_roadwarrior_pool_skips_obfuscation_generation_entirely() {
        let (resolved, _) = resolve(&topology());
        assert_eq!(
            resolved.roadwarrior_obfuscation["plain"],
            Obfuscation::default()
        );
    }

    #[test]
    fn resolve_non_plain_roadwarrior_pool_still_generates_obfuscation() {
        let mut topology = topology();
        topology.roadwarriors[0].obfuscation = Obfuscation::default();
        let (resolved, _) = resolve(&topology);
        assert_ne!(
            resolved.roadwarrior_obfuscation["obfuscated"],
            Obfuscation::default()
        );
    }

    #[test]
    fn routes_name_each_value_by_what_it_belongs_to() {
        let (_, minted) = resolve(&topology());
        assert_eq!(
            minted.routes(),
            [
                "nodes[a].mesh_private_key",
                "nodes[b].mesh_private_key",
                "mesh.links[a|b].obfuscation",
                "roadwarriors[obfuscated].private_key",
                "roadwarriors[plain].private_key",
            ]
        );
    }
}
