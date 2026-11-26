//! Against the kernel, in a network namespace of the test's own: `unshare -rn cargo test -p common
//! --test netns -- --ignored`.

use common::netlink::rt::{Family, RtClient};
use std::process::Command;

fn ip(args: &str) -> String {
    let output = Command::new("ip").args(args.split(' ')).output().unwrap();
    assert!(output.status.success(), "ip {args}: {output:?}");
    String::from_utf8(output.stdout).unwrap()
}

#[tokio::test]
#[ignore = "needs its own network namespace"]
async fn the_default_route_is_the_main_tables_even_when_another_table_lists_one_first() {
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
