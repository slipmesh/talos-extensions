//! CIDR parsing shared by the daemons and by `taloscfg`, which generates the configs they read.
//!
//! Lives outside `netlink` deliberately: it is pure string handling, and keeping it here is what
//! lets a config-only build of this crate (`--no-default-features`) skip rtnetlink entirely - the
//! netlink stack is Linux-only, while the generator has to build wherever it is run.

use anyhow::{Context, Result};
use std::net::IpAddr;

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

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

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
