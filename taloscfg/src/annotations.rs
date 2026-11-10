//! What every node publishes about the mesh as annotations on its Node object, for whatever runs in
//! the cluster and needs the same facts: one source, `slipmesh.yaml`, and nothing entered twice.
//!
//! An annotation is named after the path of its value in `slipmesh.yaml`: `slipmesh.net/` and the
//! path, each `<list>[]` in it replaced by the name of one element. The value sits on the Node of
//! the node it belongs to, so only a list whose element is that node can be in the path. Talos
//! keeps the annotations it sets in step with the config: a changed value is rewritten, a value no
//! longer given is taken off the Node.

use crate::mesh_config::MeshConfig;
use anyhow::{Context, Result};
use std::collections::BTreeMap;

/// The namespace of every annotation this generator sets.
pub const NAMESPACE: &str = "slipmesh.net/";

/// The name of one element of each list a path may go through: only lists whose element is the
/// node the annotation sits on.
const ELEMENTS: [(&str, &str); 1] = [("nodes", "node")];

/// The annotation named after `path`.
pub fn name(path: &str) -> Result<String> {
    let segments = path
        .split('.')
        .map(|segment| match segment.strip_suffix("[]") {
            None => Ok(segment),
            Some(list) => ELEMENTS
                .iter()
                .find(|(l, _)| *l == list)
                .map(|(_, element)| *element)
                .with_context(|| {
                    format!(
                        "{path}: an element of {list:?} is not the node an annotation sits on, so \
                         a node may have several"
                    )
                }),
        })
        .collect::<Result<Vec<_>>>()?;
    Ok(format!("{NAMESPACE}{}", segments.join(".")))
}

/// The annotations of `node`, by name.
pub fn for_node(mesh: &MeshConfig, node: &str) -> Result<BTreeMap<String, String>> {
    let entry = mesh
        .nodes
        .iter()
        .find(|n| n.name == node)
        .with_context(|| format!("unknown node {node:?}"))?;
    let values = [
        (
            "cluster.interface_prefix.mesh",
            Some(mesh.cluster.mesh_interface_prefix().to_owned()),
        ),
        (
            "cluster.route_proto_id.egress",
            Some(mesh.cluster.egress_route_proto_id().to_string()),
        ),
        ("nodes[].endpoint", entry.endpoint.clone()),
    ];
    values
        .into_iter()
        .filter_map(|(path, value)| value.map(|value| Ok((name(path)?, value))))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mesh(cluster: &str, node: &str) -> MeshConfig {
        sliplib_yaml::from_str(&format!(
            "cluster:\n  bgp_as: 64512\n{cluster}nodes:\n  - {{name: a, node_id: \"10.62.0.1\"{node}}}\n"
        ))
        .unwrap()
    }

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
    fn every_name_is_one_kubernetes_accepts() {
        let names = for_node(&mesh("", ", endpoint: \"192.0.2.10\""), "a").unwrap();
        assert_eq!(names.len(), 3);
        for name in names.keys() {
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
    fn a_node_publishes_the_prefix_the_protocol_and_its_endpoint() {
        let annotations = for_node(&mesh("", ", endpoint: \"192.0.2.10\""), "a").unwrap();
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
    fn a_node_without_an_endpoint_publishes_none() {
        let annotations = for_node(&mesh("", ""), "a").unwrap();
        assert!(!annotations.contains_key("slipmesh.net/node.endpoint"));
    }

    #[test]
    fn a_value_given_in_slipmesh_yaml_is_the_one_published() {
        let cluster = "  interface_prefix: {mesh: wg-}\n  route_proto_id: {egress: 160}\n";
        let annotations = for_node(&mesh(cluster, ""), "a").unwrap();
        assert_eq!(
            annotations["slipmesh.net/cluster.interface_prefix.mesh"],
            "wg-"
        );
        assert_eq!(
            annotations["slipmesh.net/cluster.route_proto_id.egress"],
            "160"
        );
    }

    #[test]
    fn an_unknown_node_is_an_error() {
        assert!(for_node(&mesh("", ""), "b").is_err());
    }
}
