//! Thin wrapper around `rtnetlink` for links and addresses - the route/link/address netlink family
//! (`NETLINK_ROUTE`, distinct from the "amneziawg" genl one in `awg.rs`). Routes are
//! `sliplib_net::route`'s.

use anyhow::{Context, Result};
use futures::TryStreamExt;
use rtnetlink::packet_route::address::AddressMessage;
use rtnetlink::packet_route::link::InfoKind;
use rtnetlink::{AddressMessageBuilder, Handle, LinkMessageBuilder, new_connection};
use sliplib_net::IpNet;
use std::net::{Ipv4Addr, Ipv6Addr};
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
    fn an_address_message_carries_the_family_and_link_of_either_kind() {
        use rtnetlink::packet_route::AddressFamily;
        use rtnetlink::packet_route::address::AddressAttribute;
        for (cidr, family) in [
            ("192.0.2.0/24", AddressFamily::Inet),
            ("2001:db8::/32", AddressFamily::Inet6),
        ] {
            let cidr: IpNet = cidr.parse().unwrap();
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
