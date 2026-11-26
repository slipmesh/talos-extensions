//! Following the uplinks against the kernel, in a network namespace of the test's own. Run as the
//! README's Development section says.

#[path = "../../common/tests/support/netns.rs"]
mod support;

use common::netlink::rt::{self, RtClient};
use nftables::follow::{follow, lookup};
use nftables::template::{Uplink, Uplinks};
use std::time::Duration;
use support::{ip, own_network_namespace};
use tokio::sync::mpsc;

fn uplink(interface: &str, addresses: &[&str]) -> Option<Uplink> {
    Some(Uplink {
        interface: interface.to_owned(),
        addresses: addresses.iter().map(|a| a.parse().unwrap()).collect(),
    })
}

/// Follows the uplinks from those found now; gives them and the changes it hands on.
async fn follow_from_now() -> (Uplinks, mpsc::UnboundedReceiver<Uplinks>) {
    let rt = RtClient::connect().unwrap();
    let changes = rt::link_route_and_address_changes().unwrap();
    let start = lookup(&rt).await.unwrap();
    let (tx, handed) = mpsc::unbounded_channel();
    tokio::spawn(follow(
        changes,
        start.clone(),
        move || {
            let rt = rt.clone();
            async move { lookup(&rt).await }
        },
        move |uplinks| {
            tx.send(uplinks.clone()).unwrap();
            async { Ok(()) }
        },
    ));
    (start, handed)
}

async fn next(handed: &mut mpsc::UnboundedReceiver<Uplinks>) -> Uplinks {
    tokio::time::timeout(Duration::from_secs(10), handed.recv())
        .await
        .expect("no change handed on")
        .unwrap()
}

#[tokio::test]
#[ignore = "needs its own network namespace"]
async fn the_uplinks_are_followed_as_routes_and_addresses_change() {
    own_network_namespace();
    for link in ["four0", "six0"] {
        ip(&format!("link add {link} type dummy"));
        ip(&format!("link set {link} up"));
    }
    ip("addr add 192.0.2.5/24 dev four0");
    ip("addr add 2001:db8::5/64 dev six0 nodad");

    let (start, mut handed) = follow_from_now().await;
    assert_eq!(start, Uplinks::default());

    ip("-4 route add default dev four0");
    let ipv4 = uplink("four0", &["192.0.2.5"]);
    assert_eq!(
        next(&mut handed).await,
        Uplinks {
            ipv4: ipv4.clone(),
            ipv6: None
        }
    );

    ip("-6 route add default dev six0");
    let ipv6 = uplink("six0", &["2001:db8::5"]);
    assert_eq!(
        next(&mut handed).await,
        Uplinks {
            ipv4: ipv4.clone(),
            ipv6: ipv6.clone()
        }
    );

    ip("-4 route del default dev four0");
    assert_eq!(
        next(&mut handed).await,
        Uplinks {
            ipv4: None,
            ipv6: ipv6.clone()
        }
    );

    ip("addr del 2001:db8::5/64 dev six0");
    ip("addr add 2001:db8::6/64 dev six0 nodad");
    let moved = uplink("six0", &["2001:db8::6"]);
    assert_eq!(
        next(&mut handed).await,
        Uplinks {
            ipv4: None,
            ipv6: moved
        }
    );
}

/// The kernel drops an IPv4 route whose link goes down without a route event; with IPv6 off no
/// IPv6 event wakes the follower either.
#[tokio::test]
#[ignore = "needs its own network namespace"]
async fn an_uplink_whose_link_goes_down_is_followed_to_the_next_default_route() {
    own_network_namespace();
    for conf in ["all", "default"] {
        std::fs::write(format!("/proc/sys/net/ipv6/conf/{conf}/disable_ipv6"), "1").unwrap();
    }
    for (link, address, metric) in [("d0", "192.0.2.5", 100), ("d1", "198.51.100.5", 200)] {
        ip(&format!("link add {link} type dummy"));
        ip(&format!("link set {link} up"));
        ip(&format!("addr add {address}/24 dev {link}"));
        ip(&format!("route add default dev {link} metric {metric}"));
    }

    let (start, mut handed) = follow_from_now().await;
    assert_eq!(start.ipv4, uplink("d0", &["192.0.2.5"]));

    ip("link set d0 down");
    assert_eq!(
        next(&mut handed).await,
        Uplinks {
            ipv4: uplink("d1", &["198.51.100.5"]),
            ipv6: None
        }
    );
}
