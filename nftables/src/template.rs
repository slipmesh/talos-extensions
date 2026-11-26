//! The ruleset this daemon applies, as a template of the values only the running node knows -
//! which interface carries the default route, per address family - and of the classes and `vars`
//! of its config.

use anyhow::Result;
use common::template::{Template, VALUES, Values, ValuesContext};
use serde::Serialize;
use std::collections::HashMap;
use std::path::Path;

/// A `configFiles` entry of its `ExtensionServiceConfig`.
pub const TEMPLATE_PATH: &str = "/etc/talos-extensions/nftables.conf.j2";

/// Its config, a `configFiles` entry beside the template. Not `nftables.yaml`, which the daemon
/// before templates read as its ruleset.
pub const CONFIG_PATH: &str = "/etc/talos-extensions/firewall.yaml";

/// The ruleset a mesh starts from: `taloscfg` writes it into `slipmesh.yaml` when that file has
/// none, and from then on the copy there is the one in force.
pub const REFERENCE_TEMPLATE: &str = include_str!("../templates/nftables.conf.j2");

pub const DEFAULT_ROUTE_IPV4: &str = "defaultroute_interface_ipv4";
pub const DEFAULT_ROUTE_IPV6: &str = "defaultroute_interface_ipv6";

/// Compiles a ruleset template, refusing one that reads anything but the default-route
/// interfaces and the [`Values`].
pub fn compile(source: impl Into<String>) -> Result<Template> {
    let [classes, vars] = VALUES;
    Template::new(
        source,
        &[DEFAULT_ROUTE_IPV4, DEFAULT_ROUTE_IPV6, classes, vars],
    )
}

/// Empty without the file.
pub fn read_values(path: &Path) -> Result<Values> {
    match std::fs::metadata(path) {
        Err(absent) if absent.kind() == std::io::ErrorKind::NotFound => Ok(Values::default()),
        _ => Values::read(path),
    }
}

#[derive(Serialize)]
struct RulesetContext<'a> {
    #[serde(flatten)]
    interfaces: &'a HashMap<&'a str, String>,
    #[serde(flatten)]
    values: ValuesContext<'a>,
}

/// `interfaces` holds those of the default routes the template reads.
pub fn render(
    template: &Template,
    interfaces: &HashMap<&str, String>,
    values: &Values,
) -> Result<String> {
    template.render(RulesetContext {
        interfaces,
        values: values.context(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

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
    fn a_ruleset_reads_the_classes_and_vars_beside_the_interfaces() {
        let template = compile(
            "oifname \"{{ defaultroute_interface_ipv4 }}\" meta mark set \
             {{ classes.egress.rules['uplink-replies'].mark.value }} ip saddr {{ vars.source }}\n",
        )
        .unwrap();
        let values: Values = sliplib_yaml::from_str(
            "classes: {egress: {protocol: 152, rules: {uplink-replies: \
             {priority: 1000, mark: 0x100000/0x100000}}}}\nvars: {source: 203.0.113.0/26}\n",
        )
        .unwrap();
        let interfaces = HashMap::from([(DEFAULT_ROUTE_IPV4, "eth0".to_owned())]);
        assert_eq!(
            render(&template, &interfaces, &values).unwrap(),
            "oifname \"eth0\" meta mark set 0x100000 ip saddr 203.0.113.0/26\n"
        );
    }

    #[test]
    fn without_its_config_file_the_firewall_has_no_classes_and_no_vars() {
        let dir = tempfile::tempdir().unwrap();
        let absent = dir.path().join("firewall.yaml");
        assert_eq!(read_values(&absent).unwrap(), Values::default());
        std::fs::write(&absent, "vars: {a: 1}\n").unwrap();
        assert_eq!(
            read_values(&absent).unwrap().vars,
            sliplib_yaml::from_str("{a: 1}").unwrap()
        );
        assert!(read_values(dir.path()).is_err());
        assert!(read_values(&absent.join("under-a-file")).is_err());
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
}
