//! Retries at a daemon's start, where what it needs may not be up yet.

use std::fmt::Display;
use std::time::Duration;

/// Calls `attempt` until it succeeds, at most `tries` times, `interval` apart, with a warning for
/// each failure but the last, which it returns.
pub async fn retry<T, E: Display, Fut: Future<Output = Result<T, E>>>(
    tries: u32,
    interval: Duration,
    mut attempt: impl FnMut() -> Fut,
) -> Result<T, E> {
    for tried in 1..tries {
        match attempt().await {
            Ok(value) => return Ok(value),
            Err(error) => {
                tracing::warn!(%error, tried, "retrying in {interval:?}");
                tokio::time::sleep(interval).await;
            }
        }
    }
    attempt().await
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    #[tokio::test(start_paused = true)]
    async fn tries_until_one_succeeds_and_no_more_than_it_is_given() {
        let calls = Cell::new(0);
        let fails_twice = || {
            calls.set(calls.get() + 1);
            let call = calls.get();
            async move { if call < 3 { Err(call) } else { Ok(call) } }
        };
        assert_eq!(retry(5, Duration::from_secs(1), fails_twice).await, Ok(3));
        calls.set(0);
        assert_eq!(retry(2, Duration::from_secs(1), fails_twice).await, Err(2));
    }
}
