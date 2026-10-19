//! The ruleset this daemon applies, as a template of the values only the running node knows -
//! which interface carries the default route, per address family.

use anyhow::Result;
use common::template::Template;

/// Where the template reaches the daemon - the `configFiles` entry of its `ExtensionServiceConfig`.
pub const TEMPLATE_PATH: &str = "/etc/talos-extensions/nftables.conf.j2";

/// The ruleset a mesh starts from: `taloscfg` writes it into `slipmesh.yaml` when that file has
/// none, and from then on the copy there is the one in force.
pub const REFERENCE_TEMPLATE: &str = include_str!("../templates/nftables.conf.j2");

pub const DEFAULT_ROUTE_IPV4: &str = "defaultroute_interface_ipv4";
pub const DEFAULT_ROUTE_IPV6: &str = "defaultroute_interface_ipv6";

/// Compiles a ruleset template, refusing one that reads anything but the default-route
/// interfaces.
pub fn compile(source: impl Into<String>) -> Result<Template> {
    Template::new(source, &[DEFAULT_ROUTE_IPV4, DEFAULT_ROUTE_IPV6])
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::{BTreeSet, HashMap};

    #[test]
    fn the_reference_ruleset_fills_in_the_ipv4_default_route_interface() {
        let template = compile(REFERENCE_TEMPLATE).unwrap();
        assert_eq!(
            template.variables(),
            BTreeSet::from([DEFAULT_ROUTE_IPV4.to_string()])
        );
        let values = HashMap::from([(DEFAULT_ROUTE_IPV4, "eth0")]);
        assert_eq!(
            template.render(values).unwrap(),
            REFERENCE_TEMPLATE.replace("{{ defaultroute_interface_ipv4 }}", "eth0")
        );
    }

    #[test]
    fn both_families_can_be_filled_in() {
        let template = compile(
            "oifname \"{{ defaultroute_interface_ipv4 }}\"\noifname \"{{defaultroute_interface_ipv6}}\"\n",
        )
        .unwrap();
        let values = HashMap::from([(DEFAULT_ROUTE_IPV4, "eth0"), (DEFAULT_ROUTE_IPV6, "eth1")]);
        assert_eq!(
            template.render(values).unwrap(),
            "oifname \"eth0\"\noifname \"eth1\"\n"
        );
    }

    #[test]
    fn an_unknown_variable_is_refused() {
        let err = compile("oifname \"{{ typo_placeholder }}\"").err().unwrap();
        assert!(format!("{err:#}").contains("typo_placeholder"), "{err:#}");
    }
}
