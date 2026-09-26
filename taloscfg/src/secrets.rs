//! The topology's secrets: every node's mesh private key, every link's and pool's obfuscation, every
//! pool's private key. Each is the value the topology sets, else a freshly generated one, and what
//! was generated comes back as `Minted` for `edit::record` to write into the field it belongs to -
//! the next run finds it there and generates nothing.
//!
//! They are resolved once for the whole topology, not per node:
//! - A mesh link's obfuscation (`h1-h4` especially) is declared once per link because AmneziaWG's
//!   magic-header substitution requires both peers to agree on the same values - generating it
//!   independently on each end would produce two different, incompatible values and break the link.
//! - A node's mesh private key is one identity shared across every `mesh.links` interface on that
//!   node; the *other* end of each link needs that node's *public* key, derived from it - so
//!   rendering node A's config requires already knowing node B's resolved private key, not just
//!   A's own.

use crate::keys;
use crate::mesh_config::MeshConfig;
use crate::obfuscation_gen;
use common::Obfuscation;
use std::collections::HashMap;

pub struct ResolvedSecrets {
    pub mesh_private_keys: HashMap<String, String>,
    pub mesh_link_obfuscation: HashMap<String, Obfuscation>,
    pub roadwarrior_private_keys: HashMap<String, String>,
    pub roadwarrior_obfuscation: HashMap<String, Obfuscation>,
}

/// Canonical, order-independent key for a mesh link's maps (`pair`'s two names, sorted).
pub fn link_key(pair: &[String; 2]) -> String {
    let mut sorted = pair.clone();
    sorted.sort();
    format!("{}|{}", sorted[0], sorted[1])
}

/// What a run generated, by the entry it belongs to.
#[derive(Default)]
pub struct Minted {
    /// By the node's position in `nodes`.
    pub node_keys: Vec<(usize, String)>,
    /// By the link's position in `mesh.links`; only the fields generated.
    pub link_obfuscation: Vec<(usize, Obfuscation)>,
    pub pools: Vec<PoolMinted>,
    /// How a message names each value.
    names: Vec<String>,
}

pub struct PoolMinted {
    pub name: String,
    pub private_key: Option<String>,
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

/// `specific`, else a fresh key - which is also returned as the one generated.
fn resolve_key(specific: Option<&str>) -> (String, Option<String>) {
    match specific {
        Some(key) => (key.to_owned(), None),
        None => {
            let key = keys::generate_private_key();
            (key.clone(), Some(key))
        }
    }
}

/// Layers `specific` (a link's or pool's own `obfuscation`) over `global` (the topology's
/// top-level default) field by field, and generates whatever is still unset - see
/// `obfuscation_gen`'s own doc comment for why that only ever fills in the "original nine" fields.
/// Returns the result and, apart, the fields that were generated.
fn resolve_obfuscation(specific: &Obfuscation, global: &Obfuscation) -> (Obfuscation, Obfuscation) {
    let fresh = obfuscation_gen::generate();
    let mut generated = Obfuscation::default();
    macro_rules! field {
        ($f:ident) => {
            match specific.$f.clone().or_else(|| global.$f.clone()) {
                Some(set) => Some(set),
                None => {
                    generated.$f = fresh.$f.clone();
                    fresh.$f.clone()
                }
            }
        };
    }
    let resolved = Obfuscation {
        jc: field!(jc),
        jmin: field!(jmin),
        jmax: field!(jmax),
        s1: field!(s1),
        s2: field!(s2),
        s3: field!(s3),
        s4: field!(s4),
        h1: field!(h1),
        h2: field!(h2),
        h3: field!(h3),
        h4: field!(h4),
        i1: field!(i1),
        i2: field!(i2),
        i3: field!(i3),
        i4: field!(i4),
        i5: field!(i5),
        header_protection_key: field!(header_protection_key),
        content_padding_addition: field!(content_padding_addition),
        rekey_after_time: field!(rekey_after_time),
        rekey_timeout: field!(rekey_timeout),
        reject_after_time: field!(reject_after_time),
        keepalive_timeout: field!(keepalive_timeout),
        max_handshake_attempts: field!(max_handshake_attempts),
        random_trailers: field!(random_trailers),
        disable_cookies: field!(disable_cookies),
    };
    (resolved, generated)
}

/// `plain` links and pools (e.g. a RouterOS peer, or a stock WireGuard app, that can't speak
/// AmneziaWG's extensions at all) skip resolution entirely - it would fill every unset field from
/// a fresh generation and silently turn "no obfuscation" back into an obfuscated one.
fn resolve_unless_plain(
    plain: bool,
    specific: &Obfuscation,
    global: &Obfuscation,
) -> (Obfuscation, Option<Obfuscation>) {
    if plain {
        return (Obfuscation::default(), None);
    }
    let (resolved, generated) = resolve_obfuscation(specific, global);
    let generated = (generated != Obfuscation::default()).then_some(generated);
    (resolved, generated)
}

pub fn resolve(topology: &MeshConfig) -> (ResolvedSecrets, Minted) {
    let mut minted = Minted::default();

    let mut mesh_private_keys = HashMap::new();
    for (index, node) in topology.nodes.iter().enumerate() {
        let (key, generated) = resolve_key(node.mesh_private_key.as_deref());
        if let Some(generated) = generated {
            minted.node_keys.push((index, generated));
            minted
                .names
                .push(format!("nodes[{}].mesh_private_key", node.name));
        }
        mesh_private_keys.insert(node.name.clone(), key);
    }

    let mut mesh_link_obfuscation = HashMap::new();
    for (index, link) in topology.mesh.links.iter().enumerate() {
        let pair = link_key(&link.pair);
        let (resolved, generated) =
            resolve_unless_plain(link.plain, &link.obfuscation, &topology.obfuscation);
        if let Some(generated) = generated {
            minted.link_obfuscation.push((index, generated));
            minted.names.push(format!("mesh.links[{pair}].obfuscation"));
        }
        mesh_link_obfuscation.insert(pair, resolved);
    }

    let mut roadwarrior_private_keys = HashMap::new();
    let mut roadwarrior_obfuscation = HashMap::new();
    for pool in &topology.roadwarriors {
        let (key, private_key) = resolve_key(pool.private_key.as_deref());
        if private_key.is_some() {
            minted
                .names
                .push(format!("roadwarriors[{}].private_key", pool.name));
        }
        let (resolved, obfuscation) =
            resolve_unless_plain(pool.plain, &pool.obfuscation, &topology.obfuscation);
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
        roadwarrior_private_keys.insert(pool.name.clone(), key);
        roadwarrior_obfuscation.insert(pool.name.clone(), resolved);
    }

    let resolved = ResolvedSecrets {
        mesh_private_keys,
        mesh_link_obfuscation,
        roadwarrior_private_keys,
        roadwarrior_obfuscation,
    };
    (resolved, minted)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn link_key_does_not_depend_on_the_order_of_the_pair() {
        let ab = link_key(&["a".to_owned(), "b".to_owned()]);
        let ba = link_key(&["b".to_owned(), "a".to_owned()]);
        assert_eq!(ab, ba);
    }

    #[test]
    fn resolve_obfuscation_prefers_specific_field_over_global() {
        let specific = Obfuscation {
            jc: Some(9),
            ..Obfuscation::default()
        };
        let global = Obfuscation {
            jc: Some(1),
            jmin: Some(10),
            ..Obfuscation::default()
        };
        let (resolved, _) = resolve_obfuscation(&specific, &global);
        assert_eq!(resolved.jc, Some(9));
        assert_eq!(resolved.jmin, Some(10));
    }

    /// The 3.1 switches are never invented: `generate()` leaves them unset, so an
    /// unconfigured mesh stays as it was.
    #[test]
    fn resolve_obfuscation_carries_the_31_switches_and_never_generates_them() {
        let global = Obfuscation {
            random_trailers: Some(true),
            ..Obfuscation::default()
        };
        let (resolved, generated) = resolve_obfuscation(&Obfuscation::default(), &global);
        assert_eq!(resolved.random_trailers, Some(true));
        assert_eq!(resolved.disable_cookies, None);
        assert_eq!(generated.random_trailers, None);
    }

    #[test]
    fn resolve_obfuscation_generates_when_nothing_else_is_set() {
        let (resolved, generated) =
            resolve_obfuscation(&Obfuscation::default(), &Obfuscation::default());
        assert!(resolved.jc.is_some());
        assert!(resolved.h1.is_some());
        assert_eq!(resolved, generated);
    }

    #[test]
    fn resolve_obfuscation_reports_as_generated_only_what_no_layer_set() {
        let specific = Obfuscation {
            jc: Some(9),
            ..Obfuscation::default()
        };
        let global = Obfuscation {
            h1: Some(42),
            ..Obfuscation::default()
        };
        let (resolved, generated) = resolve_obfuscation(&specific, &global);
        assert_eq!((generated.jc, generated.h1), (None, None));
        assert_eq!(generated.jmin, resolved.jmin);
        assert!(generated.jmin.is_some());
    }

    fn topology() -> MeshConfig {
        yaml_serde::from_str(
            r#"
cluster:
  bgp_as: 64512
  loopback_networks: {ipv4: "10.62.0.0/16", ipv6: "fd00:62::/32"}
nodes:
  - {name: a, node_id: "10.62.0.1"}
  - {name: b, node_id: "10.62.0.2"}
mesh:
  links:
    - {pair: [b, a], port: 51820}
roadwarriors:
  - name: obfuscated
    node_hostnames: [a]
    address: "10.99.0.1/24"
    listen_port: 51900
    obfuscation: {jc: 4, jmin: 10, jmax: 50, s1: 1, s2: 2, h1: 5, h2: 6, h3: 7, h4: 8}
  - name: plain
    node_hostnames: [b]
    address: "10.98.0.1/24"
    listen_port: 51901
    plain: true
"#,
        )
        .unwrap()
    }

    #[test]
    fn resolve_uses_explicit_node_private_key() {
        let mut topology = topology();
        topology.nodes[0].mesh_private_key = Some("explicit-key".to_owned());
        let (resolved, minted) = resolve(&topology);
        assert_eq!(resolved.mesh_private_keys["a"], "explicit-key");
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
