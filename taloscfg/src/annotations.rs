//! What every node publishes about the mesh as annotations on its Node object, for whatever runs in
//! the cluster and needs the same facts: one source, `slipmesh.yaml`, and nothing entered twice.
//!
//! An annotation is named after the key of its value in `slipmesh.yaml`. Talos keeps the annotations
//! it sets in step with the config: a changed value is rewritten, a value no longer given is taken
//! off the Node.

use crate::mesh_config::{ClusterConfig, NodeEntry};
use sliplib_yaml::Mapping;

/// The namespace of every annotation this generator sets.
pub const NAMESPACE: &str = "slipmesh.net/";

/// The annotations of `node`, by name. `mesh_mtu` is the one MTU of every mesh interface, as
/// [`crate::mtu::mesh_mtu`] works it out.
pub fn for_node(cluster: &ClusterConfig, node: &NodeEntry, mesh_mtu: Option<u32>) -> Mapping {
    let values = [
        (
            "interface_prefix.mesh",
            Some(cluster.mesh_interface_prefix().to_owned()),
        ),
        (
            "route_proto_id.egress",
            Some(cluster.egress_route_proto_id().to_string()),
        ),
        ("endpoint", node.endpoint.clone()),
        ("mesh_mtu", mesh_mtu.map(|mtu| mtu.to_string())),
    ];
    values
        .into_iter()
        .filter_map(|(key, value)| Some((format!("{NAMESPACE}{key}").into(), value?.into())))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mesh_config::MeshConfig;

    #[test]
    fn a_node_without_an_endpoint_publishes_none() {
        let mesh: MeshConfig = sliplib_yaml::from_str(
            "cluster: {}\nnodes:\n  - {name: a, node_id: \"198.51.100.1\"}\n",
        )
        .unwrap();
        let annotations = for_node(&mesh.cluster, &mesh.nodes[0], None);
        assert!(
            !annotations.contains_key("slipmesh.net/endpoint"),
            "{annotations:?}"
        );
    }
}
