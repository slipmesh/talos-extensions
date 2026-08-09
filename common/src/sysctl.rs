//! Plain `/proc/sys` writes - no `sysctl` binary involved.

use anyhow::{Context, Result};

pub async fn write(path: &str, value: &str) -> Result<()> {
    tokio::fs::write(path, value)
        .await
        .with_context(|| format!("failed to write {value:?} to {path}"))
}
