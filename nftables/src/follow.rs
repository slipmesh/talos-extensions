//! Following the uplinks: a burst of link, route and address changes becomes one lookup, and a
//! lookup that finds them as they were changes nothing.

use crate::template::Uplinks;
use anyhow::{Context, Result};
use futures::{FutureExt, Stream, StreamExt};
use std::future::Future;
use std::time::Duration;

/// Collects the address and route events of one link change into one apply.
pub const SETTLE: Duration = Duration::from_secs(1);

/// Looks the uplinks up after each settled burst of `changes`, and hands `changed` those that
/// differ from the last, starting from `current`. Returns only on an error, the end of `changes`
/// among them.
pub async fn follow<L, LF, C, CF>(
    changes: impl Stream<Item = ()> + Send + Unpin + 'static,
    mut current: Uplinks,
    lookup: L,
    mut changed: C,
) -> Result<()>
where
    L: Fn() -> LF,
    LF: Future<Output = Result<Uplinks>>,
    C: FnMut(&Uplinks) -> CF,
    CF: Future<Output = Result<()>>,
{
    let mut changes = read_as_they_come(changes);
    loop {
        settled(&mut changes).await?;
        let found = lookup().await?;
        if found != current {
            changed(&found).await?;
            current = found;
        }
    }
}

/// The uplinks of the node as they are now.
#[cfg(feature = "runtime")]
pub async fn lookup(rt: &common::netlink::rt::RtClient) -> Result<Uplinks> {
    use crate::template::Uplink;
    use common::netlink::rt::Family;
    let uplink = |(interface, addresses)| Uplink {
        interface,
        addresses,
    };
    Ok(Uplinks {
        ipv4: rt.uplink(Family::Ipv4).await?.map(uplink),
        ipv6: rt.uplink(Family::Ipv6).await?.map(uplink),
    })
}

/// `changes` read as they come and dropped, leaving only that one came. A burst left unread while
/// [`settled`] waits would stay queued.
fn read_as_they_come(
    mut changes: impl Stream<Item = ()> + Send + Unpin + 'static,
) -> impl Stream<Item = ()> + Unpin {
    let (came, seen) = tokio::sync::watch::channel(());
    tokio::spawn(async move {
        while changes.next().await.is_some() {
            if came.send(()).is_err() {
                break;
            }
        }
    });
    Box::pin(
        futures::stream::unfold(seen, |mut seen| async move {
            seen.changed().await.ok().map(|()| ((), seen))
        })
        .fuse(),
    )
}

/// Waits for a change, then for [`SETTLE`], and takes the changes that came meanwhile.
async fn settled(changes: &mut (impl Stream<Item = ()> + Unpin)) -> Result<()> {
    changes
        .next()
        .await
        .context("the link, route and address changes ended")?;
    tokio::time::sleep(SETTLE).await;
    while let Some(Some(())) = changes.next().now_or_never() {}
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::template::Uplink;
    use futures::channel::mpsc;
    use std::cell::RefCell;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn on(interface: &str) -> Uplinks {
        Uplinks {
            ipv4: Some(Uplink {
                interface: interface.to_owned(),
                addresses: vec!["192.0.2.5".parse().unwrap()],
            }),
            ipv6: None,
        }
    }

    /// Runs `follow` from no uplink over `changes` until they end, each lookup taking the next of
    /// `found`; gives the number of lookups and what `changed` was handed.
    async fn run(
        changes: mpsc::UnboundedReceiver<()>,
        found: Vec<Uplinks>,
    ) -> (usize, Vec<Uplinks>) {
        let found = RefCell::new(found.into_iter());
        let lookups = RefCell::new(0);
        let handed = RefCell::new(Vec::new());
        let ended = follow(
            changes,
            Uplinks::default(),
            || {
                *lookups.borrow_mut() += 1;
                let next = found.borrow_mut().next().expect("a lookup too many");
                async move { Ok(next) }
            },
            |uplinks| {
                handed.borrow_mut().push(uplinks.clone());
                async { Ok(()) }
            },
        )
        .await;
        assert!(format!("{:#}", ended.unwrap_err()).contains("ended"));
        (lookups.into_inner(), handed.into_inner())
    }

    #[tokio::test(start_paused = true)]
    async fn a_burst_of_changes_is_one_lookup() {
        let (tx, rx) = mpsc::unbounded();
        for _ in 0..5 {
            tx.unbounded_send(()).unwrap();
        }
        drop(tx);
        assert_eq!(run(rx, vec![on("eth0")]).await, (1, vec![on("eth0")]));
    }

    #[tokio::test(start_paused = true)]
    async fn a_change_after_the_settling_time_is_another_lookup() {
        let (tx, rx) = mpsc::unbounded();
        tx.unbounded_send(()).unwrap();
        tokio::spawn(async move {
            tokio::time::sleep(SETTLE * 2).await;
            tx.unbounded_send(()).unwrap();
        });
        assert_eq!(
            run(rx, vec![on("eth0"), on("eth1")]).await,
            (2, vec![on("eth0"), on("eth1")])
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_change_within_the_settling_time_is_the_same_lookup() {
        let (tx, rx) = mpsc::unbounded();
        tx.unbounded_send(()).unwrap();
        tokio::spawn(async move {
            tokio::time::sleep(SETTLE / 2).await;
            tx.unbounded_send(()).unwrap();
        });
        assert_eq!(run(rx, vec![on("eth0")]).await, (1, vec![on("eth0")]));
    }

    #[tokio::test(start_paused = true)]
    async fn a_lookup_that_finds_the_uplinks_unchanged_hands_nothing_on() {
        let (tx, rx) = mpsc::unbounded();
        tokio::spawn(async move {
            for _ in 0..3 {
                tx.unbounded_send(()).unwrap();
                tokio::time::sleep(SETTLE * 2).await;
            }
        });
        assert_eq!(
            run(rx, vec![Uplinks::default(), on("eth0"), on("eth0")]).await,
            (3, vec![on("eth0")])
        );
    }

    /// A change not read yet, counted in `unread` until it is dropped.
    struct Unread(Arc<AtomicUsize>);

    impl Drop for Unread {
        fn drop(&mut self) {
            self.0.fetch_sub(1, Ordering::SeqCst);
        }
    }

    #[tokio::test(start_paused = true)]
    async fn the_changes_are_read_as_they_come_rather_than_kept_while_settling() {
        let unread = Arc::new(AtomicUsize::new(0));
        let (tx, rx) = mpsc::unbounded();
        let send = |count| {
            for _ in 0..count {
                unread.fetch_add(1, Ordering::SeqCst);
                tx.unbounded_send(Unread(unread.clone())).unwrap();
            }
        };
        let following = follow(
            rx.map(drop),
            Uplinks::default(),
            || async { Ok(Uplinks::default()) },
            |_| async { Ok(()) },
        );
        let settling = async {
            send(1);
            tokio::time::sleep(SETTLE / 4).await;
            send(1000);
            tokio::time::sleep(SETTLE / 4).await;
            assert_eq!(unread.load(Ordering::SeqCst), 0);
        };
        tokio::select! {
            ended = following => panic!("follow ended: {ended:?}"),
            () = settling => {}
        }
    }

    #[tokio::test(start_paused = true)]
    async fn a_failed_lookup_ends_following() {
        let (tx, rx) = mpsc::unbounded();
        tx.unbounded_send(()).unwrap();
        let ended = follow(
            rx,
            Uplinks::default(),
            || async { anyhow::bail!("no netlink") },
            |_| async { Ok(()) },
        )
        .await;
        assert!(format!("{:#}", ended.unwrap_err()).contains("no netlink"));
        drop(tx);
    }
}
