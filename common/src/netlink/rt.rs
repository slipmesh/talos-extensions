//! Thin wrapper around `rtnetlink` - the route/link/address netlink family (`NETLINK_ROUTE`,
//! distinct from the "amneziawg" genl one in `awg.rs`). Replaces `ip` subprocess calls entirely.
//!
//! Ported from slipmesh-operators' `common::netlink::rt` (github.com/slipmesh/operators), with two
//! changes beyond the re-home: address handling is generalized from "one IPv4 address" (`
//! ensure_address`) / "N IPv6 addresses" (`ensure_address_v6`) into one `ensure_addresses` that
//! takes any mix of IPv4/IPv6 CIDRs; and routes carry an explicit `RouteProtocol` tag (`route_add`/
//! `route_del`/new `routes_by_protocol`) so this daemon's own routes are unambiguously
//! distinguishable from anything else that might exist on the same interface (see
//! `crate::ROUTE_PROTOCOL`'s doc comment for why this matters).
//!
//! Route/link types are imported via `rtnetlink::packet_route::...`, not a separate top-level
//! `netlink-packet-route` dependency - see this workspace's root `Cargo.toml` comment on why.

use anyhow::{Context, Result};
use futures::TryStreamExt;
use rtnetlink::packet_route::link::InfoKind;
use rtnetlink::packet_route::route::{RouteMessage, RouteProtocol};
use rtnetlink::{
    AddressMessageBuilder, Handle, LinkMessageBuilder, RouteMessageBuilder, new_connection,
};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use tokio::sync::Mutex;

#[derive(Clone)]
pub struct RtClient {
    handle: Handle,
    /// Serializes every netlink request issued through this client - see slipmesh-operators'
    /// original doc comment (same file, same reasoning): a shared netlink socket under concurrent
    /// requests can return kernel `EBUSY` even across unrelated links/request types. A `Mutex`
    /// rather than a retry loop sidesteps picking a retry budget that's merely "probably enough".
    ///
    /// Internal call sites that need what a locked public method already does (e.g. `ensure_link`
    /// needs `link_index`) go through a private `_inner` helper directly, not the public locked
    /// method - `tokio::sync::Mutex` isn't reentrant.
    netlink_lock: Arc<Mutex<()>>,
}

/// Which of `current` addresses/routes should be removed so only `desired` remains - pure,
/// independent of any netlink call, unit-testable without a real link/kernel. Generic over
/// anything comparable-by-value (address+prefix pairs here).
fn to_remove<A: PartialEq + Copy>(current: &[A], desired: &[A]) -> Vec<A> {
    current
        .iter()
        .copied()
        .filter(|a| !desired.contains(a))
        .collect()
}

/// Parses `"<addr>/<prefix>"` for either address family.
pub fn parse_cidr(cidr: &str) -> Result<(IpAddr, u8)> {
    let (addr, prefix) = cidr
        .split_once('/')
        .with_context(|| format!("{cidr:?} is not a CIDR (missing '/')"))?;
    let addr: IpAddr = addr
        .parse()
        .with_context(|| format!("invalid address in {cidr:?}"))?;
    let prefix: u8 = prefix
        .parse()
        .with_context(|| format!("invalid prefix length in {cidr:?}"))?;
    let max = if addr.is_ipv4() { 32 } else { 128 };
    anyhow::ensure!(
        prefix <= max,
        "invalid prefix length in {cidr:?}: {prefix} > {max}"
    );
    Ok((addr, prefix))
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

    async fn v4_addresses(&self, index: u32) -> Result<Vec<(Ipv4Addr, u8)>> {
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
                if let AddressAttribute::Address(IpAddr::V4(addr)) = attr {
                    out.push((*addr, prefix_len));
                }
            }
        }
        Ok(out)
    }

    async fn v6_addresses(&self, index: u32) -> Result<Vec<(Ipv6Addr, u8)>> {
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
                if let AddressAttribute::Address(IpAddr::V6(addr)) = attr {
                    out.push((*addr, prefix_len));
                }
            }
        }
        Ok(out)
    }

    async fn ensure_v4_addresses(&self, index: u32, desired: &[(Ipv4Addr, u8)]) -> Result<()> {
        let current = self.v4_addresses(index).await?;
        for (addr, prefix) in to_remove(&current, desired) {
            self.handle
                .address()
                .del(
                    AddressMessageBuilder::<Ipv4Addr>::new()
                        .index(index)
                        .address(addr, prefix)
                        .build(),
                )
                .execute()
                .await
                .with_context(|| {
                    format!("failed to remove stale address {addr}/{prefix} from link {index}")
                })?;
        }
        for (addr, prefix) in desired {
            self.handle
                .address()
                .add(index, (*addr).into(), *prefix)
                .replace()
                .execute()
                .await
                .with_context(|| {
                    format!("failed to assign address {addr}/{prefix} to link {index}")
                })?;
        }
        Ok(())
    }

    async fn ensure_v6_addresses(&self, index: u32, desired: &[(Ipv6Addr, u8)]) -> Result<()> {
        let current = self.v6_addresses(index).await?;
        for (addr, prefix) in to_remove(&current, desired) {
            self.handle
                .address()
                .del(
                    AddressMessageBuilder::<Ipv6Addr>::new()
                        .index(index)
                        .address(addr, prefix)
                        .build(),
                )
                .execute()
                .await
                .with_context(|| {
                    format!("failed to remove stale address {addr}/{prefix} from link {index}")
                })?;
        }
        for (addr, prefix) in desired {
            self.handle
                .address()
                .add(index, (*addr).into(), *prefix)
                .replace()
                .execute()
                .await
                .with_context(|| {
                    format!("failed to assign address {addr}/{prefix} to link {index}")
                })?;
        }
        Ok(())
    }

    /// Idempotent, self-correcting address assignment for a mix of IPv4/IPv6 CIDRs at once -
    /// equivalent to `ip addr replace` for each entry, plus removing every other address already
    /// on the interface *within the same family* (an interface can carry addresses of both
    /// families simultaneously; each family's desired set only ever displaces stale entries of its
    /// own family, never the other's).
    ///
    /// Takes every address this interface should carry at once, not one at a time - two separate
    /// calls, each with one address, would have each call remove the other's address as "stale"
    /// (see slipmesh-operators' `ensure_address_v6` doc comment for the concrete bug this avoids -
    /// same reasoning here, just generalized to both families and any address count).
    pub async fn ensure_addresses(&self, index: u32, cidrs: &[String]) -> Result<()> {
        let _guard = self.netlink_lock.lock().await;
        let mut v4 = Vec::new();
        let mut v6 = Vec::new();
        for cidr in cidrs {
            match parse_cidr(cidr)? {
                (IpAddr::V4(a), p) => v4.push((a, p)),
                (IpAddr::V6(a), p) => v6.push((a, p)),
            }
        }
        self.ensure_v4_addresses(index, &v4).await?;
        self.ensure_v6_addresses(index, &v6).await?;
        Ok(())
    }

    async fn route_add_v4(
        &self,
        index: u32,
        addr: Ipv4Addr,
        prefix: u8,
        protocol: RouteProtocol,
    ) -> Result<()> {
        let msg: RouteMessage = RouteMessageBuilder::<Ipv4Addr>::new()
            .destination_prefix(addr, prefix)
            .output_interface(index)
            .protocol(protocol)
            .build();
        self.handle
            .route()
            .add(msg)
            .replace()
            .execute()
            .await
            .with_context(|| format!("failed to add route {addr}/{prefix} dev {index}"))
    }

    async fn route_add_v6(
        &self,
        index: u32,
        addr: Ipv6Addr,
        prefix: u8,
        protocol: RouteProtocol,
    ) -> Result<()> {
        let msg: RouteMessage = RouteMessageBuilder::<Ipv6Addr>::new()
            .destination_prefix(addr, prefix)
            .output_interface(index)
            .protocol(protocol)
            .build();
        self.handle
            .route()
            .add(msg)
            .replace()
            .execute()
            .await
            .with_context(|| format!("failed to add route {addr}/{prefix} dev {index}"))
    }

    /// Equivalent to `ip route replace <cidr> dev <index> proto <protocol>` - either address
    /// family. `protocol` marks the route as ours - see `crate::ROUTE_PROTOCOL`.
    pub async fn route_add(&self, index: u32, cidr: &str, protocol: RouteProtocol) -> Result<()> {
        let _guard = self.netlink_lock.lock().await;
        match parse_cidr(cidr)? {
            (IpAddr::V4(a), p) => self.route_add_v4(index, a, p, protocol).await,
            (IpAddr::V6(a), p) => self.route_add_v6(index, a, p, protocol).await,
        }
    }

    /// Equivalent to `ip route del <cidr> dev <index> proto <protocol>`. Deleting a missing route
    /// is success (ESRCH). `protocol` scopes the delete to a route this daemon itself installed -
    /// a route with the same destination but a different `proto` (BIRD, static, ...) is left
    /// alone.
    pub async fn route_del(&self, index: u32, cidr: &str, protocol: RouteProtocol) -> Result<()> {
        let _guard = self.netlink_lock.lock().await;
        let del = |msg: RouteMessage| {
            let handle = self.handle.clone();
            async move {
                match handle.route().del(msg).execute().await {
                    Ok(()) => Ok(()),
                    Err(rtnetlink::Error::NetlinkError(ref e)) if e.raw_code() == -3 => Ok(()), // ESRCH
                    Err(e) => Err(e).context("failed to delete route"),
                }
            }
        };
        match parse_cidr(cidr)? {
            (IpAddr::V4(a), p) => {
                let msg: RouteMessage = RouteMessageBuilder::<Ipv4Addr>::new()
                    .destination_prefix(a, p)
                    .output_interface(index)
                    .protocol(protocol)
                    .build();
                del(msg).await
            }
            (IpAddr::V6(a), p) => {
                let msg: RouteMessage = RouteMessageBuilder::<Ipv6Addr>::new()
                    .destination_prefix(a, p)
                    .output_interface(index)
                    .protocol(protocol)
                    .build();
                del(msg).await
            }
        }
    }

    async fn routes_matching(
        &self,
        query: RouteMessage,
        index: u32,
        protocol: RouteProtocol,
    ) -> Result<Vec<String>> {
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
            out.push(format!("{addr}/{prefix}"));
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
    ) -> Result<Vec<String>> {
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
    fn to_remove_empty_current_removes_nothing() {
        assert_eq!(
            to_remove(&[], &[(Ipv4Addr::new(10, 0, 0, 1), 31)]),
            Vec::new()
        );
    }

    #[test]
    fn to_remove_matching_current_removes_nothing() {
        let desired = (Ipv4Addr::new(10, 0, 0, 1), 31);
        assert_eq!(to_remove(&[desired], &[desired]), Vec::new());
    }

    #[test]
    fn to_remove_flags_a_single_stale_address() {
        let stale = (Ipv4Addr::new(10, 62, 255, 6), 31);
        let desired = (Ipv4Addr::new(10, 62, 255, 10), 31);
        assert_eq!(to_remove(&[stale], &[desired]), vec![stale]);
    }

    #[test]
    fn to_remove_keeps_desired_and_flags_every_other_one() {
        let stale_a = (Ipv4Addr::new(10, 0, 0, 2), 31);
        let stale_b = (Ipv4Addr::new(10, 0, 0, 4), 31);
        let desired = (Ipv4Addr::new(10, 0, 0, 6), 31);
        let mut removed = to_remove(&[stale_a, desired, stale_b], &[desired]);
        removed.sort();
        assert_eq!(removed, vec![stale_a, stale_b]);
    }

    #[test]
    fn to_remove_works_for_ipv6_too() {
        let stale: (Ipv6Addr, u8) = ("fe80::1".parse().unwrap(), 64);
        let desired: (Ipv6Addr, u8) = ("fe80::2".parse().unwrap(), 64);
        assert_eq!(to_remove(&[stale], &[desired]), vec![stale]);
    }

    #[test]
    fn to_remove_keeps_every_entry_in_a_multi_address_desired_set() {
        let global: (Ipv6Addr, u8) = ("fd00::1".parse().unwrap(), 128);
        let link_local: (Ipv6Addr, u8) = ("fe80::1".parse().unwrap(), 64);
        let stale: (Ipv6Addr, u8) = ("fe80::dead".parse().unwrap(), 64);
        let mut removed = to_remove(&[global, link_local, stale], &[global, link_local]);
        removed.sort();
        assert_eq!(removed, vec![stale]);
    }

    #[test]
    fn parse_cidr_accepts_ipv4() {
        assert_eq!(
            parse_cidr("10.0.0.1/24").unwrap(),
            (IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 24)
        );
    }

    #[test]
    fn parse_cidr_accepts_ipv6() {
        assert_eq!(
            parse_cidr("fe80::1/64").unwrap(),
            (IpAddr::V6("fe80::1".parse().unwrap()), 64)
        );
    }

    #[test]
    fn parse_cidr_rejects_prefix_over_family_max() {
        assert!(parse_cidr("10.0.0.1/33").is_err());
        assert!(parse_cidr("fe80::1/129").is_err());
    }

    #[test]
    fn parse_cidr_rejects_missing_slash() {
        assert!(parse_cidr("10.0.0.1").is_err());
    }
}
