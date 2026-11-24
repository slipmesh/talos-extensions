//! What every node publishes about the mesh as annotations on its Node object, for whatever runs in
//! the cluster and needs the same facts: one source, `slipmesh.yaml`, and nothing entered twice.
//!
//! The names are those the specification of `slipmesh.yaml` lists, each with the value it carries.
//! Talos keeps the annotations it sets in step with the config: a changed value is rewritten, a
//! value no longer given is taken off the Node.

use sliplib_config::v2::{ClassName, Map, network::Class};
use sliplib_net::mtu::MESH_MTU_ANNOTATION;
use sliplib_yaml::Mapping;

/// The namespace of every annotation this generator sets.
pub const NAMESPACE: &str = "slipmesh.net/";

/// What a node publishes about the mesh.
pub struct Values<'a> {
    /// What the name of every interface of a link starts with.
    pub interface_prefix: &'a str,
    /// Each route class by its name, with its protocol number, in the order written.
    pub classes: &'a Map<ClassName, Class>,
    /// The node's endpoint as the files give it: an address or a name.
    pub endpoint: Option<&'a str>,
    /// The one MTU of every mesh interface: the largest at which a full-size packet crosses every
    /// link's underlay unfragmented.
    pub mesh_mtu: Option<u32>,
}

/// The annotations of a node with `values`, by name, in the order of `values`.
pub fn for_node(values: &Values) -> Mapping {
    let prefix = (
        format!("{NAMESPACE}interface_prefix.mesh"),
        Some(values.interface_prefix.to_owned()),
    );
    let classes = values.classes.iter().map(|(name, class)| {
        (
            format!("{NAMESPACE}route_proto_id.{name}"),
            Some(class.protocol.to_string()),
        )
    });
    let rest = [
        (
            format!("{NAMESPACE}endpoint"),
            values.endpoint.map(str::to_owned),
        ),
        (
            MESH_MTU_ANNOTATION.to_owned(),
            values.mesh_mtu.map(|mtu| mtu.to_string()),
        ),
    ];
    std::iter::once(prefix)
        .chain(classes)
        .chain(rest)
        .filter_map(|(key, value)| Some((key.into(), value?.into())))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn names_and_values(annotations: &Mapping) -> Vec<(&str, &str)> {
        annotations
            .iter()
            .map(|(key, value)| (key.as_str().unwrap(), value.as_str().unwrap()))
            .collect()
    }

    #[test]
    fn a_node_publishes_each_value_it_has_under_the_namespace_in_order() {
        // Neither sorted by name nor by number: the order they are given in.
        let classes =
            sliplib_yaml::from_str("{transit: {protocol: 153}, egress: {protocol: 152}}").unwrap();
        let none = Map::new();
        for (values, published) in [
            (
                Values {
                    interface_prefix: "wg-",
                    classes: &classes,
                    endpoint: Some("node-a.example.com"),
                    mesh_mtu: Some(1420),
                },
                vec![
                    ("slipmesh.net/interface_prefix.mesh", "wg-"),
                    ("slipmesh.net/route_proto_id.transit", "153"),
                    ("slipmesh.net/route_proto_id.egress", "152"),
                    ("slipmesh.net/endpoint", "node-a.example.com"),
                    ("slipmesh.net/mesh_mtu", "1420"),
                ],
            ),
            (
                Values {
                    interface_prefix: "mesh-",
                    classes: &none,
                    endpoint: None,
                    mesh_mtu: None,
                },
                vec![("slipmesh.net/interface_prefix.mesh", "mesh-")],
            ),
        ] {
            assert_eq!(names_and_values(&for_node(&values)), published);
        }
    }
}
