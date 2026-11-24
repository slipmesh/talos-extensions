//! Name lookups for the daemons.

use anyhow::{Context, Result};
use std::net::SocketAddr;
use std::time::Duration;
use tokio::net::ToSocketAddrs;

/// A resolver that does not answer is an error after this, not a hang that holds the caller.
pub const LOOKUP_TIMEOUT: Duration = Duration::from_secs(15);

/// The addresses `target` resolves to.
pub async fn lookup(target: impl ToSocketAddrs) -> Result<impl Iterator<Item = SocketAddr>> {
    Ok(
        tokio::time::timeout(LOOKUP_TIMEOUT, tokio::net::lookup_host(target))
            .await
            .with_context(|| format!("no answer within {LOOKUP_TIMEOUT:?}"))??,
    )
}
