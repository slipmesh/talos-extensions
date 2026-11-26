//! Thin wrapper around `rtnetlink` - the route/link/address netlink family (`NETLINK_ROUTE`,
//! distinct from the "amneziawg" genl one in `awg.rs`). Replaces `ip` subprocess calls entirely.
//! Routes carry a `RouteProtocol` tag, so a daemon's own routes are told apart from any other on
//! the same interface (see `crate::ROUTE_PROTOCOL`).

use anyhow::{Context, Result};
use futures::TryStreamExt;
use rtnetlink::packet_route::address::AddressMessage;
use rtnetlink::packet_route::link::InfoKind;
use rtnetlink::packet_route::route::{RouteMessage, RouteProtocol};
use rtnetlink::{
    AddressMessageBuilder, Handle, LinkMessageBuilder, RouteMessageBuilder, new_connection,
};
pub use sliplib_config::v2::network::Family;
use sliplib_net::IpNet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use tokio::sync::Mutex;

#[derive(Clone)]
pub struct RtClient {
    handle: Handle,
    /// Serializes every netlink request issued through this client: a shared netlink socket under
    /// concurrent requests can return kernel `EBUSY` even across unrelated links/request types. A
    /// `Mutex` rather than a retry loop sidesteps picking a retry budget that's merely "probably
    /// enough".
    ///
    /// Internal call sites that need what a locked public method already does (e.g. `ensure_link`
    /// needs `link_index`) go through a private `_inner` helper directly, not the public locked
    /// method - `tokio::sync::Mutex` isn't reentrant.
    netlink_lock: Arc<Mutex<()>>,
}

/// Which of `current` addresses should be removed so only `desired` remains.
fn to_remove(current: &[IpNet], desired: &[IpNet]) -> Vec<IpNet> {
    current
        .iter()
        .copied()
        .filter(|a| !desired.contains(a))
        .collect()
}

impl RtClient {
    pub fn connect() -> Result<Self> {
        let (connection, handle, _) =
            new_connection().context("failed to open rtnetlink socket")?;
        tokio::spawn(connection);
        Ok(Self {
            handle,
            netlink_lock: Arc::new(Mutex::new(())),
        })
    }

    async fn link_index_inner(&self, name: &str) -> Result<Option<u32>> {
        let mut links = self
            .handle
            .link()
            .get()
            .match_name(name.to_string())
            .execute();
        match links.try_next().await {
            Ok(Some(msg)) => Ok(Some(msg.header.index)),
            Ok(None) => Ok(None),
            Err(rtnetlink::Error::NetlinkError(ref e)) if e.raw_code() == -19 => Ok(None), // ENODEV
            Err(e) => Err(e).with_context(|| format!("failed to look up link {name:?}")),
        }
    }

    /// Looks up a link's ifindex by name, without creating it. `Ok(None)` means the link doesn't
    /// exist.
    pub async fn link_index(&self, name: &str) -> Result<Option<u32>> {
        let _guard = self.netlink_lock.lock().await;
        self.link_index_inner(name).await
    }

    /// Creates the link if it doesn't exist yet (`ip link add <name> type <kind>`). Returns its
    /// ifindex plus whether it was just created.
    pub async fn ensure_link(&self, name: &str, kind: &str) -> Result<(u32, bool)> {
        let _guard = self.netlink_lock.lock().await;
        if let Some(index) = self.link_index_inner(name).await? {
            return Ok((index, false));
        }
        let msg = LinkMessageBuilder::<()>::new_with_info_kind(InfoKind::Other(kind.to_string()))
            .name(name.to_string())
            .build();
        self.handle
            .link()
            .add(msg)
            .execute()
            .await
            .with_context(|| format!("failed to create link {name:?} type {kind:?}"))?;
        let index = self
            .link_index_inner(name)
            .await?
            .with_context(|| format!("link {name:?} missing immediately after creation"))?;
        Ok((index, true))
    }

    async fn list_links_inner(&self) -> Result<Vec<(String, u32, Option<String>)>> {
        use rtnetlink::packet_route::link::LinkAttribute;
        let mut links = self.handle.link().get().execute();
        let mut out = Vec::new();
        while let Some(msg) = links.try_next().await.context("failed to list links")? {
            let name = msg.attributes.iter().find_map(|a| match a {
                LinkAttribute::IfName(name) => Some(name.clone()),
                _ => None,
            });
            let kind = msg.attributes.iter().find_map(|a| match a {
                LinkAttribute::LinkInfo(info) => info.iter().find_map(|i| match i {
                    rtnetlink::packet_route::link::LinkInfo::Kind(InfoKind::Other(k)) => {
                        Some(k.clone())
                    }
                    _ => None,
                }),
                _ => None,
            });
            if let Some(name) = name {
                out.push((name, msg.header.index, kind));
            }
        }
        Ok(out)
    }

    /// Lists every link on the host as (name, ifindex) pairs - equivalent to `ip -o link show`.
    pub async fn list_links(&self) -> Result<Vec<(String, u32)>> {
        let _guard = self.netlink_lock.lock().await;
        Ok(self
            .list_links_inner()
            .await?
            .into_iter()
            .map(|(name, index, _)| (name, index))
            .collect())
    }

    /// Lists every link on the host whose netlink link-kind (`IFLA_INFO_KIND`, what `ip -d link
    /// show` reports as `type <kind>`) matches exactly - e.g. `"amneziawg"`. This is how the `awg`
    /// daemon finds "every interface I might own" for GC, without needing any naming convention.
    pub async fn list_links_by_kind(&self, kind: &str) -> Result<Vec<(String, u32)>> {
        let _guard = self.netlink_lock.lock().await;
        Ok(self
            .list_links_inner()
            .await?
            .into_iter()
            .filter_map(|(name, index, k)| (k.as_deref() == Some(kind)).then_some((name, index)))
            .collect())
    }

    /// Equivalent to `ip link del <index>`.
    pub async fn delete_link(&self, index: u32) -> Result<()> {
        let _guard = self.netlink_lock.lock().await;
        self.handle
            .link()
            .del(index)
            .execute()
            .await
            .with_context(|| format!("failed to delete link {index}"))
    }

    /// Equivalent to `ip link set <index> up`.
    pub async fn set_up(&self, index: u32) -> Result<()> {
        let _guard = self.netlink_lock.lock().await;
        let msg = LinkMessageBuilder::<()>::default()
            .index(index)
            .up()
            .build();
        self.handle
            .link()
            .set(msg)
            .execute()
            .await
            .with_context(|| format!("failed to set link {index} up"))
    }

    /// Equivalent to `ip link set <index> mtu <mtu>`.
    pub async fn set_mtu(&self, index: u32, mtu: u32) -> Result<()> {
        let _guard = self.netlink_lock.lock().await;
        let msg = LinkMessageBuilder::<()>::default()
            .index(index)
            .mtu(mtu)
            .build();
        self.handle
            .link()
            .set(msg)
            .execute()
            .await
            .with_context(|| format!("failed to set the mtu of link {index} to {mtu}"))
    }

    async fn addresses(&self, index: u32) -> Result<Vec<IpNet>> {
        use rtnetlink::packet_route::address::AddressAttribute;
        let mut addrs = self
            .handle
            .address()
            .get()
            .set_link_index_filter(index)
            .execute();
        let mut out = Vec::new();
        while let Some(msg) = addrs
            .try_next()
            .await
            .with_context(|| format!("failed to list addresses on link {index}"))?
        {
            let prefix_len = msg.header.prefix_len;
            for attr in &msg.attributes {
                if let AddressAttribute::Address(addr) = attr {
                    out.extend(IpNet::new(*addr, prefix_len).ok());
                }
            }
        }
        Ok(out)
    }

    /// Idempotent, self-correcting address assignment for a mix of IPv4/IPv6 CIDRs at once -
    /// equivalent to `ip addr replace` for each entry, plus removing every other address already
    /// on the interface, of either family.
    ///
    /// Takes every address this interface should carry at once, not one at a time: two separate
    /// calls, each with one address, would each remove the other's address as stale.
    pub async fn ensure_addresses(&self, index: u32, cidrs: &[IpNet]) -> Result<()> {
        let _guard = self.netlink_lock.lock().await;
        let current = self.addresses(index).await?;
        for cidr in to_remove(&current, cidrs) {
            self.handle
                .address()
                .del(address_message(index, cidr))
                .execute()
                .await
                .with_context(|| {
                    format!("failed to remove stale address {cidr} from link {index}")
                })?;
        }
        for cidr in cidrs {
            self.handle
                .address()
                .add(index, cidr.addr(), cidr.prefix_len())
                .replace()
                .execute()
                .await
                .with_context(|| format!("failed to assign address {cidr} to link {index}"))?;
        }
        Ok(())
    }

    /// Equivalent to `ip route replace <cidr> dev <index> proto <protocol>` - either address
    /// family. `protocol` marks the route as ours - see `crate::ROUTE_PROTOCOL`.
    pub async fn route_add(&self, index: u32, cidr: IpNet, protocol: RouteProtocol) -> Result<()> {
        let _guard = self.netlink_lock.lock().await;
        self.handle
            .route()
            .add(route_message(index, cidr, protocol)?)
            .replace()
            .execute()
            .await
            .with_context(|| format!("failed to add route {cidr} dev {index}"))
    }

    /// Equivalent to `ip route del <cidr> dev <index> proto <protocol>`. Deleting a missing route
    /// is success (ESRCH). `protocol` scopes the delete to a route this daemon itself installed -
    /// a route with the same destination but a different `proto` (BIRD, static, ...) is left
    /// alone.
    pub async fn route_del(&self, index: u32, cidr: IpNet, protocol: RouteProtocol) -> Result<()> {
        let _guard = self.netlink_lock.lock().await;
        match self
            .handle
            .route()
            .del(route_message(index, cidr, protocol)?)
            .execute()
            .await
        {
            Ok(()) => Ok(()),
            Err(rtnetlink::Error::NetlinkError(ref e)) if e.raw_code() == -3 => Ok(()), // ESRCH
            Err(e) => Err(e).with_context(|| format!("failed to delete route {cidr} dev {index}")),
        }
    }

    async fn routes_matching(
        &self,
        query: RouteMessage,
        index: u32,
        protocol: RouteProtocol,
    ) -> Result<Vec<IpNet>> {
        use rtnetlink::packet_route::route::RouteAttribute;
        let mut routes = self.handle.route().get(query).execute();
        let mut out = Vec::new();
        while let Some(route) = routes.try_next().await.context("failed to list routes")? {
            if route.header.protocol != protocol {
                continue;
            }
            let oif = route.attributes.iter().find_map(|a| match a {
                RouteAttribute::Oif(i) => Some(*i),
                _ => None,
            });
            if oif != Some(index) {
                continue;
            }
            let Some((addr, prefix)) = destination_of(&route) else {
                continue;
            };
            out.extend(IpNet::new(addr, prefix).ok());
        }
        Ok(out)
    }

    /// Every route on `index` tagged with `protocol` (our own `ROUTE_PROTOCOL`, in practice) -
    /// used at startup to seed route tracking from what's actually in the kernel, rather than
    /// assuming nothing survived a previous instance of this process (see `handshake.rs`).
    pub async fn routes_by_protocol(
        &self,
        index: u32,
        protocol: RouteProtocol,
    ) -> Result<Vec<IpNet>> {
        let _guard = self.netlink_lock.lock().await;
        let mut out = self
            .routes_matching(
                RouteMessageBuilder::<Ipv4Addr>::new().build(),
                index,
                protocol,
            )
            .await?;
        out.extend(
            self.routes_matching(
                RouteMessageBuilder::<Ipv6Addr>::new().build(),
                index,
                protocol,
            )
            .await?,
        );
        Ok(out)
    }

    /// Name of the interface the `family` default route of the main table points at - equivalent
    /// to `ip -4 route show default` or `ip -6 …`, then resolving the `dev` name. `Ok(None)` if that
    /// family has none, a common case on a single-stack node. A dual-stack node's two default
    /// routes need not share an interface.
    pub async fn default_iface(&self, family: Family) -> Result<Option<String>> {
        use rtnetlink::packet_route::route::RouteAttribute;

        let _guard = self.netlink_lock.lock().await;
        let query = match family {
            Family::Ipv4 => RouteMessageBuilder::<Ipv4Addr>::new().build(),
            Family::Ipv6 => RouteMessageBuilder::<Ipv6Addr>::new().build(),
        };
        let mut default_oif = None;
        let mut stream = self.handle.route().get(query).execute();
        while let Some(route) = stream.try_next().await.context("failed to list routes")? {
            if route.header.destination_prefix_length != 0 || !in_main_table(&route) {
                continue;
            }
            if let Some(oif) = route.attributes.iter().find_map(|a| match a {
                RouteAttribute::Oif(index) => Some(*index),
                _ => None,
            }) {
                default_oif = Some(oif);
                break;
            }
        }
        let Some(oif) = default_oif else {
            return Ok(None);
        };

        let links = self.list_links_inner().await?;
        Ok(links
            .into_iter()
            .find(|(_, index, _)| *index == oif)
            .map(|(name, _, _)| name))
    }
}

/// `cidr` on `index`, tagged `protocol`: the route to add or to delete.
fn route_message(index: u32, cidr: IpNet, protocol: RouteProtocol) -> Result<RouteMessage> {
    Ok(RouteMessageBuilder::<IpAddr>::new()
        .destination_prefix(cidr.addr(), cidr.prefix_len())
        .with_context(|| format!("route {cidr}"))?
        .output_interface(index)
        .protocol(protocol)
        .build())
}

/// `cidr` on `index`. rtnetlink builds an address message for one family at a time.
fn address_message(index: u32, cidr: IpNet) -> AddressMessage {
    match cidr {
        IpNet::V4(net) => AddressMessageBuilder::<Ipv4Addr>::new()
            .index(index)
            .address(net.addr(), net.prefix_len())
            .build(),
        IpNet::V6(net) => AddressMessageBuilder::<Ipv6Addr>::new()
            .index(index)
            .address(net.addr(), net.prefix_len())
            .build(),
    }
}

/// A dump lists the routes of every table, and the header carries only the low byte of the table.
fn in_main_table(route: &RouteMessage) -> bool {
    use rtnetlink::packet_route::route::{RouteAttribute, RouteHeader};
    let table = route.attributes.iter().find_map(|a| match a {
        RouteAttribute::Table(table) => Some(*table),
        _ => None,
    });
    table.unwrap_or(route.header.table.into()) == u32::from(RouteHeader::RT_TABLE_MAIN)
}

/// Extracts `(destination, prefix_len)` from a route message, either address family.
fn destination_of(route: &RouteMessage) -> Option<(IpAddr, u8)> {
    use rtnetlink::packet_route::route::RouteAttribute;
    let prefix = route.header.destination_prefix_length;
    route.attributes.iter().find_map(|a| match a {
        RouteAttribute::Destination(rtnetlink::packet_route::route::RouteAddress::Inet(a)) => {
            Some((IpAddr::V4(*a), prefix))
        }
        RouteAttribute::Destination(rtnetlink::packet_route::route::RouteAddress::Inet6(a)) => {
            Some((IpAddr::V6(*a), prefix))
        }
        _ => None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn to_remove_keeps_every_entry_in_a_multi_address_desired_set() {
        let net = |text: &str| -> IpNet { text.parse().unwrap() };
        let global = net("3fff::1/128");
        let link_local = net("fe80::1/64");
        let stale = net("fe80::dead/64");
        let also_stale = net("fe80::beef/64");
        let mut removed = to_remove(
            &[global, stale, link_local, also_stale],
            &[global, link_local],
        );
        removed.sort();
        assert_eq!(removed, vec![also_stale, stale]);
    }

    #[test]
    fn a_route_without_the_table_attribute_is_in_the_table_its_header_names() {
        let main = RouteMessageBuilder::<Ipv4Addr>::new().build();
        assert!(
            !main
                .attributes
                .iter()
                .any(|a| matches!(a, rtnetlink::packet_route::route::RouteAttribute::Table(_)))
        );
        assert!(in_main_table(&main));
        let mut other = main.clone();
        other.header.table = 152;
        assert!(!in_main_table(&other));
    }

    #[test]
    fn a_route_and_an_address_message_carry_the_family_link_and_protocol_of_either_kind() {
        use rtnetlink::packet_route::AddressFamily;
        use rtnetlink::packet_route::address::AddressAttribute;
        use rtnetlink::packet_route::route::{RouteAttribute, RouteHeader, RouteScope, RouteType};
        for (cidr, family) in [
            ("192.0.2.0/24", AddressFamily::Inet),
            ("2001:db8::/32", AddressFamily::Inet6),
        ] {
            let cidr: IpNet = cidr.parse().unwrap();
            let route = route_message(7, cidr, crate::ROUTE_PROTOCOL).unwrap();
            assert_eq!(route.header.address_family, family, "{cidr}");
            assert_eq!(route.header.protocol, crate::ROUTE_PROTOCOL, "{cidr}");
            assert_eq!(route.header.table, RouteHeader::RT_TABLE_MAIN, "{cidr}");
            assert_eq!(route.header.scope, RouteScope::Universe, "{cidr}");
            assert_eq!(route.header.kind, RouteType::Unicast, "{cidr}");
            assert_eq!(
                destination_of(&route),
                Some((cidr.addr(), cidr.prefix_len()))
            );
            assert!(route.attributes.contains(&RouteAttribute::Oif(7)), "{cidr}");

            let address = address_message(7, cidr);
            assert_eq!(address.header.family, family, "{cidr}");
            assert_eq!(address.header.index, 7, "{cidr}");
            assert_eq!(address.header.prefix_len, cidr.prefix_len(), "{cidr}");
            assert!(
                address
                    .attributes
                    .contains(&AddressAttribute::Address(cidr.addr())),
                "{cidr}"
            );
        }
    }
}
