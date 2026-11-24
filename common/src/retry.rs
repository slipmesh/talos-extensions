//! Retries at a daemon's start, where what it needs may not be up yet.

use anyhow::{Context, Result};
use std::time::Duration;

/// Calls `attempt` until it succeeds, at most `tries` times, `interval` apart, with a warning
/// naming `what` for each failure but the last, which it returns.
pub async fn retry<T, Fut: Future<Output = Result<T>>>(
    what: &str,
    tries: u32,
    interval: Duration,
    mut attempt: impl FnMut() -> Fut,
) -> Result<T> {
    for tried in 1..tries {
        match attempt().await {
            Ok(value) => return Ok(value),
            Err(error) => {
                tracing::warn!(
                    error = %format_args!("{error:#}"),
                    tried,
                    "{what} failed, retrying in {interval:?}"
                );
                tokio::time::sleep(interval).await;
            }
        }
    }
    attempt()
        .await
        .with_context(|| format!("{what} failed {tries} times"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;
    use tokio::time::Instant;

    #[tokio::test(start_paused = true)]
    async fn tries_until_one_succeeds_interval_apart_and_no_more_than_it_is_given() {
        let calls = Cell::new(0);
        let fails_twice = || {
            calls.set(calls.get() + 1);
            let call = calls.get();
            async move {
                anyhow::ensure!(call >= 3, "try {call}");
                Ok(call)
            }
        };
        let start = Instant::now();
        assert_eq!(
            retry("a lookup", 3, Duration::from_secs(1), fails_twice)
                .await
                .unwrap(),
            3
        );
        assert_eq!(start.elapsed(), Duration::from_secs(2));
        calls.set(0);
        let failed = retry("a lookup", 2, Duration::from_secs(1), fails_twice)
            .await
            .unwrap_err();
        assert_eq!(failed.root_cause().to_string(), "try 2");
        assert!(failed.to_string().contains("2 times"), "{failed:#}");
    }
}
