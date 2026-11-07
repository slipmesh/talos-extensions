use anyhow::{Context, Result};
use nix::sys::signal::{Signal, kill};
use nix::unistd::Pid;
use std::future::Future;
use std::process::ExitStatus;
use std::time::Duration;
use tokio::process::Child;

/// Talos sends SIGKILL 10 s after SIGTERM, to `bird` along with this process; `bird` has to be gone
/// by then, having closed its sessions.
pub const STOP_TIMEOUT: Duration = Duration::from_secs(8);

/// Waits on `bird` until it exits, which is fatal, or `shutdown` resolves, which stops it.
pub async fn supervise(mut bird: Child, shutdown: impl Future<Output = ()>) -> Result<()> {
    tokio::select! {
        status = bird.wait() => {
            let status = status.context("failed to wait on bird child process")?;
            anyhow::bail!("bird exited unexpectedly: {status}");
        }
        () = shutdown => {}
    }
    shut_down(bird).await
}

pub async fn shut_down(mut bird: Child) -> Result<()> {
    tracing::info!("SIGTERM received, stopping bird");
    let status = stop(&mut bird, STOP_TIMEOUT).await?;
    tracing::info!(%status, "bird stopped");
    Ok(())
}

/// SIGTERM is `bird`'s orderly shutdown, the same as `birdc down`: BGP sessions close with a
/// NOTIFICATION and the kernel protocol withdraws the routes it exported. SIGKILL only if it hangs.
pub async fn stop(bird: &mut Child, timeout: Duration) -> Result<ExitStatus> {
    let pid = bird.id().context("bird has already been reaped")?;
    let pid = Pid::from_raw(i32::try_from(pid).context("bird's pid does not fit pid_t")?);
    kill(pid, Signal::SIGTERM).context("failed to send SIGTERM to bird")?;
    match tokio::time::timeout(timeout, bird.wait()).await {
        Ok(status) => status.context("failed to wait on bird child process"),
        Err(_) => {
            bird.kill().await.context("failed to kill bird")?;
            anyhow::bail!("bird did not stop within {timeout:?} of SIGTERM, killed it");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::process::ExitStatusExt;
    use std::process::Stdio;
    use std::time::Instant;
    use tokio::io::{AsyncBufReadExt, BufReader};
    use tokio::process::Command;

    fn spawn(script: &str) -> Child {
        Command::new("sh")
            .args(["-c", script])
            .stdout(Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .unwrap()
    }

    /// Waits for the script's first line, so a signal sent next cannot beat its `trap`.
    async fn ready(child: &mut Child) {
        let stdout = child.stdout.take().unwrap();
        BufReader::new(stdout).lines().next_line().await.unwrap();
    }

    #[tokio::test]
    async fn bird_exiting_on_its_own_is_an_error() {
        let err = supervise(spawn("exit 3"), std::future::pending())
            .await
            .unwrap_err();
        assert!(err.to_string().contains("exited unexpectedly"), "{err}");
    }

    #[tokio::test]
    async fn shutdown_stops_bird_and_returns() {
        let started = Instant::now();
        supervise(spawn("exec sleep 30"), std::future::ready(()))
            .await
            .unwrap();
        assert!(started.elapsed() < Duration::from_secs(5));
    }

    #[tokio::test]
    async fn stop_sends_sigterm() {
        let mut bird = spawn("echo ready; exec sleep 30");
        ready(&mut bird).await;
        let status = stop(&mut bird, Duration::from_secs(5)).await.unwrap();
        assert_eq!(
            status.signal(),
            Some(nix::sys::signal::Signal::SIGTERM as i32)
        );
    }

    #[tokio::test]
    async fn bird_ignoring_sigterm_is_killed_after_the_timeout() {
        let mut bird = spawn("trap '' TERM; echo ready; exec sleep 30");
        ready(&mut bird).await;
        let err = stop(&mut bird, Duration::from_millis(200))
            .await
            .unwrap_err();
        assert!(err.to_string().contains("did not stop"), "{err}");
        assert!(bird.try_wait().unwrap().is_some(), "bird is still running");
    }
}
