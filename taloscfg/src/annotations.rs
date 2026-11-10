//! What every node publishes about the mesh as annotations on its Node object, for whatever runs in
//! the cluster and needs the same facts: one source, `slipmesh.yaml`, and nothing entered twice.
//!
//! An annotation is named after the path of its value in `slipmesh.yaml`: `slipmesh.net/` and the
//! path, with `nodes[]` read as `node`, since the value sits on that node's own Node object. Talos
//! keeps the annotations it sets in step with the config: a changed value is rewritten, a value no
//! longer given is taken off the Node.

use crate::mesh_config::MeshConfig;
use anyhow::{Context, Result};
use std::collections::BTreeMap;

/// The namespace of every annotation this generator sets.
pub const NAMESPACE: &str = "slipmesh.net/";

/// The annotations of `node`, by name.
pub fn for_node(mesh: &MeshConfig, node: &str) -> Result<BTreeMap<&'static str, String>> {
    let entry = mesh
        .nodes
        .iter()
        .find(|n| n.name == node)
        .with_context(|| format!("unknown node {node:?}"))?;
    let mut annotations = BTreeMap::from([
        (
            "slipmesh.net/cluster.interface_prefix.mesh",
            mesh.cluster.mesh_interface_prefix().to_owned(),
        ),
        (
            "slipmesh.net/cluster.route_proto_id.egress",
            mesh.cluster.egress_route_proto_id().to_string(),
        ),
    ]);
    if let Some(endpoint) = &entry.endpoint {
        annotations.insert("slipmesh.net/node.endpoint", endpoint.clone());
    }
    Ok(annotations)
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

    const ENDPOINT: &str = ", endpoint: \"192.0.2.10\"";

    #[test]
    fn every_name_is_one_kubernetes_accepts() {
        for name in for_node(&mesh("", ENDPOINT), "a").unwrap().keys() {
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
        assert_eq!(
            for_node(&mesh("", ENDPOINT), "a").unwrap(),
            BTreeMap::from([
                (
                    "slipmesh.net/cluster.interface_prefix.mesh",
                    "mesh-".to_owned()
                ),
                (
                    "slipmesh.net/cluster.route_proto_id.egress",
                    "152".to_owned()
                ),
                ("slipmesh.net/node.endpoint", "192.0.2.10".to_owned()),
            ])
        );
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
    fn a_node_without_an_endpoint_publishes_none() {
        let annotations = for_node(&mesh("", ""), "a").unwrap();
        assert!(!annotations.contains_key("slipmesh.net/node.endpoint"));
    }

    #[test]
    fn an_unknown_node_is_an_error() {
        assert!(for_node(&mesh("", ""), "b").is_err());
    }
}
