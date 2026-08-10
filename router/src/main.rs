mod bird;
mod birdc;
mod cidr;
mod config;
mod resolver;

use anyhow::{Context, Result};
use common::netlink::rt::RtClient;
use config::RouterConfig;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::Path;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;
use tokio::process::Command;
use tokio::sync::Mutex;

/// Fixed path, matching `extension-services/router.yaml`'s `configFiles[].mountPath` - never an
/// env var or CLI flag (same invariant `awg`'s `CONFIG_PATH` documents).
const CONFIG_PATH: &str = "/etc/talos-extensions/router.yaml";

/// Relative to this service's own entrypoint directory - `bird`/`birdc` are staged into the same
/// `rootfs/usr/local/lib/containers/router/` directory as this binary (see the packaging plan),
/// the same convention `extension-services/awg.yaml`'s `container.entrypoint: ./awg` uses for
/// itself.
const BIRD_BIN: &str = "./bird";

/// `/run` is writable regardless of `extension-services/router.yaml`'s `writeableRootfs: false`
/// (the same reason `bird::BIRD_CONTROL_SOCKET` already lives under `/run`) - `bird.conf` needs
/// to exist here before `bird` is even spawned (see `run()`), not just at reconcile time.
const BIRD_CONF_PATH: &str = "/run/bird/bird.conf";

/// How often `bird_health_watchdog` re-checks BIRD's live state - see `bird::protocols_healthy`'s
/// doc comment for what it's watching for.
const BIRD_HEALTH_CHECK_INTERVAL: Duration = Duration::from_secs(15);

#[tokio::main]
async fn main() -> ExitCode {
    // No timestamp/ANSI: this only ever runs as a container's stdout, which Talos's own logging
    // (`logToConsole: true` -> dmesg, or the container runtime's own log capture) already
    // timestamps - matches `awg`'s own reasoning for the same choice. `bird` itself logs to its
    // own stderr (`log stderr { ... };` in the rendered config), inherited by this process's
    // stdio by default, so both daemons' logs land in the same place with no extra plumbing.
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .without_time()
        .with_ansi(false)
        .init();

    match run().await {
        Ok(()) => unreachable!("run() only returns via bird exiting, which is always an Err"),
        Err(e) => {
            tracing::error!(error = %e, "router failed");
            ExitCode::FAILURE
        }
    }
}

/// Shared state for the two background loops (`bypass_refresh_loop`, `bird_health_watchdog`) -
/// everything here is either read-only for the process lifetime (config is never re-read; a
/// config change means Talos restarts this whole container, same as `awg`) or behind its own
/// lock. No `Store`/reflector/CRD-cache of any kind - unlike the k8s original's `reconcile::Context`,
/// there's nothing here that's watched, only what `router.yaml` declared once at startup.
struct RouterState {
    identity_loopback: Ipv4Addr,
    identity_ipv6_loopback: Ipv6Addr,
    as_number: u32,
    ospf_interfaces: Vec<String>,
    bgp_peers: Vec<bird::BgpPeer>,
    announce: Vec<bird::AnnounceRoute>,
    learn: Vec<String>,
    bypass_cfg: Option<config::BypassConfig>,
    /// Last-successful bypass resolution - re-resolving (RIPEstat/DNS) only happens on the
    /// startup/refresh-interval schedule (`bypass_refresh_loop`); a resolve failure serves this
    /// instead of blanking the bypass out over a transient upstream outage.
    bypass_cache: Mutex<Option<Vec<bird::BypassRoute>>>,
    /// Serializes every call into `bird::reconcile`/`bird::force_reconfigure`: `bypass_refresh_loop`
    /// and `bird_health_watchdog` both run concurrently with each other for the process lifetime,
    /// and without this a health-watchdog nudge could interleave with a bypass-refresh write to
    /// `BIRD_CONF_PATH`.
    render_lock: Mutex<()>,
}

async fn run() -> Result<()> {
    let raw = tokio::fs::read_to_string(CONFIG_PATH)
        .await
        .with_context(|| format!("failed to read config file {CONFIG_PATH}"))?;
    let cfg: RouterConfig =
        serde_yaml::from_str(&raw).context("failed to parse config file as YAML")?;
    config::validate(&cfg).context("config validation failed")?;

    tracing::info!(
        bgp_peers = cfg.bgp_peers.len(),
        ospf_interfaces = cfg.ospf_interfaces.len(),
        bypass = cfg.bypass.is_some(),
        "starting router"
    );

    let (loopback, ipv6_loopback) = node_loopbacks(&cfg)?;

    let rt = RtClient::connect().context("failed to open rtnetlink socket")?;
    bird::ensure_loopback(&rt, loopback, ipv6_loopback)
        .await
        .context("failed to converge router-lo")?;

    let bgp_peers: Vec<bird::BgpPeer> = cfg
        .bgp_peers
        .iter()
        .map(|p| bird::BgpPeer {
            name: p.name.clone(),
            address: p
                .address
                .parse()
                .expect("bgp_peers[].address already validated as IPv6 by config::validate"),
        })
        .collect();
    let announce: Vec<bird::AnnounceRoute> = cfg
        .announce
        .iter()
        .map(|a| bird::AnnounceRoute {
            net: a.net.clone(),
            label: a.label.clone().unwrap_or_default(),
        })
        .collect();

    let ctx = Arc::new(RouterState {
        identity_loopback: loopback,
        identity_ipv6_loopback: ipv6_loopback,
        as_number: cfg.bgp_as,
        ospf_interfaces: cfg.ospf_interfaces,
        bgp_peers,
        announce,
        learn: cfg.learn,
        bypass_cfg: cfg.bypass,
        bypass_cache: Mutex::new(None),
        render_lock: Mutex::new(()),
    });

    // Render and write bird.conf *before* spawning bird: this daemon controls startup order
    // itself now (unlike the k8s original, where `router` and `bird` were independently
    // scheduled sidecar containers racing to start first - see `slipmesh/bird`'s own
    // "wait-for-config-file-to-appear" patch, written for exactly that race). `bird::reconcile`
    // can't be used here - its diff-then-`birdc configure` path assumes bird is already running
    // and listening, which it isn't yet.
    if let Some(parent) = Path::new(BIRD_CONF_PATH).parent() {
        tokio::fs::create_dir_all(parent)
            .await
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }
    let bypass_routes = current_bypass_routes(&ctx).await;
    let initial_conf = bird::render(
        identity(&ctx),
        ctx.as_number,
        &render_inputs(&ctx, &bypass_routes),
    )?;
    tokio::fs::write(BIRD_CONF_PATH, &initial_conf)
        .await
        .with_context(|| format!("failed to write {BIRD_CONF_PATH}"))?;

    let mut bird_child = Command::new(BIRD_BIN)
        .args(["-f", "-c", BIRD_CONF_PATH, "-s", bird::BIRD_CONTROL_SOCKET])
        .spawn()
        .with_context(|| format!("failed to spawn {BIRD_BIN}"))?;

    wait_for_control_socket().await?;

    // Same render as the pre-spawn write above (bypass_routes hasn't changed) - a deliberate
    // no-op that seeds `bird::reconcile`'s file-diff baseline through the normal code path rather
    // than trusting the pre-spawn write as a special case.
    reconcile(&ctx, &bypass_routes).await?;

    if ctx.bypass_cfg.is_some() {
        tokio::spawn(bypass_refresh_loop(ctx.clone()));
    }
    tokio::spawn(bird_health_watchdog(ctx.clone()));

    // `router` treats "bird exited" as its own fatal condition, the same way `awg` treats any
    // exit from its handshake loop as fatal: `extension-services/router.yaml`'s `restart: always`
    // is what actually recovers from this, by restarting the whole container (both processes,
    // fresh) - there's no separate in-process supervision/restart-just-bird logic here on purpose.
    let status = bird_child
        .wait()
        .await
        .context("failed to wait on bird child process")?;
    anyhow::bail!("bird exited unexpectedly: {status}");
}

fn identity(ctx: &RouterState) -> bird::RouterIdentity {
    bird::RouterIdentity {
        loopback: ctx.identity_loopback,
        ipv6_loopback: ctx.identity_ipv6_loopback,
    }
}

fn render_inputs<'a>(
    ctx: &'a RouterState,
    bypass_routes: &'a [bird::BypassRoute],
) -> bird::RenderInputs<'a> {
    bird::RenderInputs {
        ospf_interfaces: &ctx.ospf_interfaces,
        bgp_peers: &ctx.bgp_peers,
        bypass: bypass_routes,
        announce: &ctx.announce,
        learn: &ctx.learn,
    }
}

/// Splits `cfg.node.loopback_addresses` into its (already `config::validate`d) single IPv4 and
/// single IPv6 entry.
fn node_loopbacks(cfg: &RouterConfig) -> Result<(Ipv4Addr, Ipv6Addr)> {
    let mut v4 = None;
    let mut v6 = None;
    for addr in &cfg.node.loopback_addresses {
        let (addr, _prefix) = config::parse_loopback_address(addr)?;
        match addr {
            IpAddr::V4(a) => v4 = Some(a),
            IpAddr::V6(a) => v6 = Some(a),
        }
    }
    Ok((
        v4.context("node.loopback_addresses has no IPv4 entry (should have been caught by config::validate)")?,
        v6.context("node.loopback_addresses has no IPv6 entry (should have been caught by config::validate)")?,
    ))
}

/// Polls for `bird::BIRD_CONTROL_SOCKET` to appear after spawning `bird` - bounded (10s at
/// 100ms), rather than assuming it's instant: failing loudly here (causing this whole process to
/// exit, same as any other startup failure) is preferable to the background loops below silently
/// logging connection-refused warnings on every tick until bird eventually comes up.
async fn wait_for_control_socket() -> Result<()> {
    let path = Path::new(bird::BIRD_CONTROL_SOCKET);
    for _ in 0..100 {
        if tokio::fs::try_exists(path).await.unwrap_or(false) {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    anyhow::bail!(
        "bird's control socket {} never appeared after spawning {BIRD_BIN}",
        path.display()
    )
}

async fn reconcile(ctx: &RouterState, bypass_routes: &[bird::BypassRoute]) -> Result<()> {
    let _guard = ctx.render_lock.lock().await;
    bird::reconcile(
        Path::new(BIRD_CONF_PATH),
        identity(ctx),
        ctx.as_number,
        &render_inputs(ctx, bypass_routes),
    )
    .await
}

/// Resolves `ctx.bypass_cfg` (if any) into concrete blackhole routes. A resolve failure keeps
/// serving the last-known-good cached result rather than blanking the bypass out over a
/// transient RIPEstat/DNS outage - same reasoning as the k8s original's `current_bypass_routes`,
/// minus the per-node CRD status patching and multi-`BypassSource`-per-node conflict handling
/// neither of which apply to a single static config block.
async fn current_bypass_routes(ctx: &RouterState) -> Vec<bird::BypassRoute> {
    let Some(bypass_cfg) = &ctx.bypass_cfg else {
        return Vec::new();
    };
    match resolver::resolve(&bypass_cfg.include, &bypass_cfg.exclude).await {
        Ok(resolved) => {
            let routes: Vec<bird::BypassRoute> = resolved
                .into_iter()
                .map(|(net, label)| bird::BypassRoute { net, label })
                .collect();
            *ctx.bypass_cache.lock().await = Some(routes.clone());
            routes
        }
        Err(e) => {
            let cached = ctx.bypass_cache.lock().await.clone();
            match cached {
                Some(routes) => {
                    tracing::warn!(error = %e, "bypass resolution failed, keeping last-known-good routes");
                    routes
                }
                None => {
                    tracing::warn!(error = %e, "bypass resolution failed with nothing cached yet - serving no bypass routes this pass");
                    Vec::new()
                }
            }
        }
    }
}

/// Runs forever as its own background task - only spawned when `ctx.bypass_cfg` is `Some` (see
/// `run()`). The periodic re-resolve must happen even without any external trigger, since there's
/// no watch mechanism at all in this daemon.
async fn bypass_refresh_loop(ctx: Arc<RouterState>) -> ! {
    let refresh_interval = Duration::from_secs(
        ctx.bypass_cfg
            .as_ref()
            .expect("only spawned when bypass_cfg is Some")
            .refresh_interval_secs,
    );
    let mut tick = tokio::time::interval(refresh_interval);
    tick.tick().await; // first tick fires immediately; the real work already happened at startup
    loop {
        tick.tick().await;
        let routes = current_bypass_routes(&ctx).await;
        if let Err(e) = reconcile(&ctx, &routes).await {
            tracing::warn!(error = %e, "bypass refresh reconcile failed");
        }
    }
}

/// Runs forever as its own background task, independent of `bypass_refresh_loop` - see
/// `bird::protocols_healthy`'s and `bird::force_reconfigure`'s doc comments for what this
/// recovers from and why a config-diff-gated reconcile alone can never catch it.
async fn bird_health_watchdog(ctx: Arc<RouterState>) -> ! {
    let exact_ifaces = bird::exact_iface_names(&ctx.ospf_interfaces);
    let mut tick = tokio::time::interval(BIRD_HEALTH_CHECK_INTERVAL);
    loop {
        tick.tick().await;
        let _guard = ctx.render_lock.lock().await;
        match bird::protocols_healthy(&exact_ifaces).await {
            Ok(true) => {}
            Ok(false) => {
                tracing::warn!(
                    ospf_interfaces = ?ctx.ospf_interfaces,
                    "BIRD hasn't converged to the last-rendered OSPF interfaces/BGP peers, re-nudging"
                );
                if let Err(e) = bird::force_reconfigure().await {
                    tracing::warn!(error = %e, "BIRD health-watchdog re-configure nudge failed");
                }
            }
            Err(e) => {
                tracing::warn!(error = %e, "BIRD health check failed")
            }
        }
    }
}
