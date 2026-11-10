//! What every node publishes about the mesh as annotations on its Node object, for whatever runs in
//! the cluster and needs the same facts: one source, `slipmesh.yaml`, and nothing entered twice.
//!
//! An annotation is named after the path of its value in `slipmesh.yaml`: `slipmesh.net/` and the
//! path, each `<list>[]` in it replaced by the name of one element. The value sits on the Node of
//! the node it belongs to, so only a list whose element is that node can be in the path. Talos
//! keeps the annotations it sets in step with the config: a changed value is rewritten, a value no
//! longer given is taken off the Node.

use anyhow::{Context, Result, bail};
use sliplib_yaml::Value;
use std::collections::BTreeMap;

/// The namespace of every annotation this generator sets.
pub const NAMESPACE: &str = "slipmesh.net/";

/// The paths of the network document whose values every node publishes.
const PUBLISHED: [&str; 3] = [
    "cluster.interface_prefix.mesh",
    "cluster.route_proto_id.egress",
    "nodes[].endpoint",
];

/// The name of one element of each list a path may go through: only lists whose element is the
/// node the annotation sits on.
const ELEMENTS: [(&str, &str); 1] = [("nodes", "node")];

/// The annotation named after `path`.
pub fn name(path: &str) -> Result<String> {
    let segments = path
        .split('.')
        .map(|segment| match segment.strip_suffix("[]") {
            None => Ok(segment),
            Some(list) => element(path, list),
        })
        .collect::<Result<Vec<_>>>()?;
    Ok(format!("{NAMESPACE}{}", segments.join(".")))
}

fn element<'a>(path: &str, list: &str) -> Result<&'a str> {
    ELEMENTS
        .iter()
        .find(|(l, _)| *l == list)
        .map(|(_, element)| *element)
        .with_context(|| {
            format!(
                "{path}: an element of {list:?} is not the node an annotation sits on, so a node \
                 may have several"
            )
        })
}

/// The annotations of `node`: each published path that `network`, the network document, gives a
/// value at, a list in the path standing for the node's own element of it.
pub fn for_node(network: &Value, node: &str) -> Result<BTreeMap<String, String>> {
    let mut annotations = BTreeMap::new();
    for path in PUBLISHED {
        if let Some(value) = value_at(network, node, path)? {
            annotations.insert(name(path)?, value);
        }
    }
    Ok(annotations)
}

fn value_at(network: &Value, node: &str, path: &str) -> Result<Option<String>> {
    let mut at = network;
    for segment in path.split('.') {
        let next = match segment.strip_suffix("[]") {
            None => at.get(segment),
            Some(list) => {
                element(path, list)?;
                let element = at
                    .get(list)
                    .and_then(Value::as_sequence)
                    .into_iter()
                    .flatten()
                    .find(|e| e.get("name").and_then(Value::as_str) == Some(node));
                Some(element.with_context(|| format!("{path}: no {list} entry for {node:?}"))?)
            }
        };
        match next {
            Some(next) => at = next,
            None => return Ok(None),
        }
    }
    Ok(Some(match at {
        Value::String(text) => text.clone(),
        Value::Number(number) => number.to_string(),
        _ => bail!("{path}: an annotation takes a single value, not {at:?}"),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn network(cluster: &str, node: &str) -> Value {
        sliplib_yaml::from_str(&format!(
            "cluster:\n  bgp_as: 64512\n{cluster}nodes:\n  - {{name: a, node_id: \"10.62.0.1\"{node}}}\n"
        ))
        .unwrap()
    }

    const KEYS: &str = "  interface_prefix: {mesh: mesh-}\n  route_proto_id: {egress: 152}\n";
    const ENDPOINT: &str = ", endpoint: \"192.0.2.10\"";

    #[test]
    fn a_cluster_path_is_named_as_it_is() {
        assert_eq!(
            name("cluster.route_proto_id.egress").unwrap(),
            "slipmesh.net/cluster.route_proto_id.egress"
        );
    }

    #[test]
    fn a_list_in_the_path_is_named_by_one_element() {
        assert_eq!(
            name("nodes[].endpoint").unwrap(),
            "slipmesh.net/node.endpoint"
        );
    }

    #[test]
    fn a_list_whose_element_is_not_the_node_is_refused() {
        let err = name("mesh.links[].port").unwrap_err().to_string();
        assert!(err.contains("links"), "{err}");
    }

    #[test]
    fn every_published_name_is_one_kubernetes_accepts() {
        for path in PUBLISHED {
            let name = name(path).unwrap();
            let local = name.strip_prefix(NAMESPACE).unwrap();
            assert!(local.len() <= 63, "{name}");
            assert!(
                local.starts_with(|c: char| c.is_ascii_alphanumeric()),
                "{name}"
            );
            assert!(
                local.ends_with(|c: char| c.is_ascii_alphanumeric()),
                "{name}"
            );
            assert!(
                local
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || "-_.".contains(c)),
                "{name}"
            );
        }
    }

    #[test]
    fn a_node_publishes_each_value_at_its_path() {
        let annotations = for_node(&network(KEYS, ENDPOINT), "a").unwrap();
        assert_eq!(
            annotations,
            BTreeMap::from([
                (
                    "slipmesh.net/cluster.interface_prefix.mesh".to_owned(),
                    "mesh-".to_owned()
                ),
                (
                    "slipmesh.net/cluster.route_proto_id.egress".to_owned(),
                    "152".to_owned()
                ),
                (
                    "slipmesh.net/node.endpoint".to_owned(),
                    "192.0.2.10".to_owned()
                ),
            ])
        );
    }

    #[test]
    fn a_value_slipmesh_yaml_does_not_give_is_not_published() {
        let annotations = for_node(&network("", ""), "a").unwrap();
        assert!(annotations.is_empty(), "{annotations:?}");
    }

    #[test]
    fn a_value_that_is_not_a_scalar_is_an_error_naming_its_path() {
        let cluster = "  interface_prefix: {mesh: [a, b]}\n";
        let err = for_node(&network(cluster, ""), "a")
            .unwrap_err()
            .to_string();
        assert!(err.contains("cluster.interface_prefix.mesh"), "{err}");
    }

    #[test]
    fn an_unknown_node_is_an_error() {
        assert!(for_node(&network("", ""), "b").is_err());
    }
}
