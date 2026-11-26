//! Against the kernel, each test in a network namespace of its own. Run as the README's Development
//! section says.

#[path = "support/netns.rs"]
mod support;

use common::netlink::rt::{Family, RtClient};
use support::{ip, own_network_namespace};

#[tokio::test]
#[ignore = "needs its own network namespace"]
async fn the_default_route_is_the_main_tables_even_when_another_table_lists_one_first() {
    own_network_namespace();
    for link in ["main0", "other0"] {
        ip(&format!("link add {link} type dummy"));
        ip(&format!("link set {link} up"));
    }
    let rt = RtClient::connect().unwrap();
    for (family, flag) in [(Family::Ipv4, "-4"), (Family::Ipv6, "-6")] {
        ip(&format!("{flag} route add default dev other0 table 152"));
        ip(&format!("{flag} route add default dev main0"));
        let listed = ip(&format!("{flag} route show table all default"));
        assert!(
            listed.starts_with("default dev other0 table 152"),
            "{listed}"
        );

        assert_eq!(
            rt.default_iface(family).await.unwrap().as_deref(),
            Some("main0")
        );
    }
}

#[tokio::test]
#[ignore = "needs its own network namespace"]
async fn an_uplink_has_the_addresses_of_its_family_on_its_own_interface() {
    own_network_namespace();
    for link in ["up0", "side0"] {
        ip(&format!("link add {link} type dummy"));
        ip(&format!("link set {link} up"));
    }
    ip("addr add 192.0.2.5/24 dev up0");
    ip("addr add 192.0.2.6/24 dev up0");
    ip("addr add 2001:db8::5/64 dev up0 nodad");
    ip("addr add 198.51.100.5/24 dev side0");
    ip("-4 route add default dev up0");
    let rt = RtClient::connect().unwrap();

    assert_eq!(
        rt.uplink(Family::Ipv4).await.unwrap(),
        Some((
            "up0".to_owned(),
            vec!["192.0.2.5".parse().unwrap(), "192.0.2.6".parse().unwrap()]
        ))
    );
    assert_eq!(rt.uplink(Family::Ipv6).await.unwrap(), None);
}
