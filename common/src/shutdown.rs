use anyhow::{Context, Result};
use tokio::signal::unix::{Signal, SignalKind, signal};

/// SIGTERM is how Talos stops an extension service. A daemon runs as PID 1 in its container, and
/// the kernel drops a signal PID 1 has no handler for, so without one every stop waits out Talos's
/// stop timeout and ends in SIGKILL.
pub struct Shutdown(Signal);

impl Shutdown {
    /// Install before anything that can take time: a SIGTERM that arrives earlier is lost.
    pub fn install() -> Result<Self> {
        signal(SignalKind::terminate())
            .map(Self)
            .context("failed to install the SIGTERM handler")
    }

    /// Resolves once SIGTERM has arrived, including one that came before the first call.
    pub async fn requested(&mut self) {
        self.0.recv().await;
    }
}
