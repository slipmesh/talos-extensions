//! Runs `bird_exporter` beside BIRD: it reads the same control socket this daemon writes the
//! config for, and serves BIRD's protocol state to Prometheus.
//!
//! Supervised here rather than left to the container's `restart: always`, which is how `main`
//! treats BIRD exiting. The two are not the same failure: BIRD dying means the node stops
//! routing, while the exporter dying means a scrape fails - and restarting the container to fix
//! metrics would tear down every adjacency BIRD holds. So this restarts only the exporter, and
//! never reports failure upwards.

use std::time::Duration;
use tokio::process::Command;

const BIN: &str = "./bird_exporter";

/// Long enough that a binary failing on every start (a bad listen address, a missing socket)
/// cannot spin, short enough that a scrape gap after a one-off crash stays under a scrape
/// interval.
const RESTART_DELAY: Duration = Duration::from_secs(10);

/// `-bird.v2` covers BIRD 3 as well: it selects the single-socket, multi-channel protocol
/// arrangement 2.0 introduced, not a specific major version. `-format.new` and the per-protocol
/// switches are left at their defaults, which are already on.
fn args(socket: &str, listen: &str) -> Vec<String> {
    vec![
        "-bird.v2".to_string(),
        "-bird.socket".to_string(),
        socket.to_string(),
        "-web.listen-address".to_string(),
        listen.to_string(),
    ]
}

/// Never returns: restarts the exporter for as long as this daemon lives.
pub async fn supervise(socket: String, listen: String) {
    loop {
        match Command::new(BIN).args(args(&socket, &listen)).spawn() {
            Ok(mut child) => match child.wait().await {
                Ok(status) => eprintln!("bird_exporter exited ({status}), restarting"),
                Err(e) => eprintln!("failed to wait on bird_exporter: {e}"),
            },
            Err(e) => eprintln!("failed to spawn {BIN}: {e}"),
        }
        tokio::time::sleep(RESTART_DELAY).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The listen address is the whole point of running it ourselves: the exporter's own default
    /// is `:9324`, every interface, and this endpoint belongs on the node's overlay loopback
    /// alone. A missing `-bird.v2` is the other silent one - it would read a BIRD 1 socket
    /// arrangement and report nothing.
    #[test]
    fn the_exporter_is_pointed_at_our_socket_and_our_address() {
        let a = args("/run/bird.ctl", "10.62.0.1:9324");
        assert_eq!(
            a,
            [
                "-bird.v2",
                "-bird.socket",
                "/run/bird.ctl",
                "-web.listen-address",
                "10.62.0.1:9324"
            ]
        );
    }
}
