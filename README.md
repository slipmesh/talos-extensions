# talos-extensions

A single Rust binary, `awg`, that brings up AmneziaWG interfaces directly on a Talos Linux node -
no Kubernetes API involved. Runs as a Talos "extension service" (`ext-awg`), packaged and released
by the sibling `talos-awg-extension` repository alongside the `amneziawg.ko` kernel module (one
extension, one release - see that repo's README for the packaging/build side).

## Why this exists

Talos nodes need mesh connectivity established before kubelet/the Kubernetes API is even reachable
- in a multi-site WAN mesh, the API server itself may only be reachable *through* this overlay, so
a boot-time dependency on it would be circular. `slipmesh-operators`' `mesh`/`roadwarriors` (see
github.com/slipmesh/operators) solve the equivalent problem for already-clustered nodes, driven by
Kubernetes CRDs; `awg` solves it for a node that hasn't joined a cluster yet (or never will), driven
by a static config file instead.

`operators/` is not a dependency of this project - `common/` here is a fresh, from-scratch, purely
netlink-facing crate (no `kube`/`k8s-openapi`), inspired by (not imported from)
`operators/common/src/netlink/`.

## One interface shape, no discriminator

There is no "mesh interface" or "roadwarriors interface" type. Every interface is the same shape:
a name, addresses, a private key, and a list of peers. What used to be two different Kubernetes
operators collapses into one behavioral distinction, per peer:

- A peer with **no `allowed_ips`** gets the full-tunnel default (`0.0.0.0/0` + `::/0`) as its
  AllowedIPs. Its handshake is never polled and no kernel route is ever installed for it -
  connectivity comes from whatever routing protocol runs over the tunnel once it's up (e.g. OSPFv3
  over a link-local address), not from a per-peer route. This is what used to be a "mesh" link.
- A peer with an **explicit `allowed_ips`** gets exactly those CIDRs as AllowedIPs, and is
  handshake-tracked at 1Hz: while its handshake stays fresher than `handshake_stale_secs` (default
  180), a kernel route is installed for each CIDR; once it goes stale, the route is removed. This is
  what used to be a "roadwarriors" peer - the route's mere presence in the kernel *is* the "this
  client is currently connected" signal (`talosctl get routes`), with no status field anywhere.

One interface can freely mix both kinds of peer.

## Config

Read from a fixed path (`/etc/talos-extensions/awg.yaml` inside the container, matching
`extension-services/awg.yaml`'s `mountPath`) - never an environment variable or CLI flag. The whole
file is rendered into the node's machine config as an `ExtensionServiceConfig` document's
`configFiles[].content`. See `talos-awg-extension/docs/extension-services.md` for the full machine
config example and every field.

```yaml
interfaces:
  - name: mesh-a1b2c3d4
    listen_port: 51820
    addresses: ["fe80::a1b2:c3d4/64"]
    private_key: "...base64, this node's own..."
    obfuscation: {jc: 4, jmin: 40, jmax: 70, h1: 1, h2: 2, h3: 3, h4: 4}
    peers:
      - public_key: "...peer's base64 public key..."
        endpoint: "203.0.113.7:51820"
        # no allowed_ips -> full-tunnel, untracked
  - name: rw-eu
    listen_port: 51900
    addresses: ["10.99.0.1/24", "fd00:99::1/64"]
    private_key: "...base64, same value on every node that should share this identity..."
    peers:
      - public_key: "...client's base64 public key..."
        allowed_ips: ["10.99.0.5/32"]   # tracked: handshake polled, route installed while fresh
        advanced_security: true         # requires header_protection_key below, same on both ends
    obfuscation:
      jc: 4
      jmin: 40
      jmax: 70
      s1: 50
      s2: 100
      h1: 1
      h2: 2
      h3: 3
      h4: 4
      s3: 60                           # junk size, cookie-reply packets
      s4: 90                           # junk size, transport (data) packets
      i1: "5-10"                       # decoy/cover packet header spec
      header_protection_key: "...base64, same wire format as private_key..."
      content_padding_addition: 128
      rekey_after_time: 120
      max_handshake_attempts: 90
```

**Private keys always come from the config - this binary never generates or persists one.**
Whoever renders the machine config is responsible for giving a node its own per-interface key, or
placing the same key in every node's config when a single shared identity is needed (e.g. so a
roaming client sees one consistent server identity no matter which node it's currently connected
to). This is a config-authoring concern, not something `awg` decides. The same applies to
`header_protection_key`.

**Every AmneziaWG 3.0 obfuscation parameter is exposed**, not just the original nine
(jc/jmin/jmax/s1/s2/h1-h4) - confirmed field-by-field against the current kernel module's
`src/netlink.c` and amneziawg-tools' own config parser (`src/config.c`), since the kernel module's
own README only documents the original set. See `common::Obfuscation`'s doc comment for the full
field list and what each one does. `header_protection_key` + a peer's `advanced_security: true` are
a matched pair - the key alone does nothing without the flag, and both ends of a peering need the
same key.

## Ownership: the whole `amneziawg` netlink kind, no naming convention

`awg` treats itself as the sole owner of every interface on the host whose netlink link-kind
(`IFLA_INFO_KIND`, what `ip -d link show` reports as `type amneziawg`) is `amneziawg` - not just
ones matching some name prefix. On every start, anything of that kind not named in the current
config gets deleted (`gc.rs`). This is safe *because* nothing else on a node is expected to ever
create an `amneziawg`-kind interface - if that assumption is ever wrong, GC will delete it.

Routes this daemon installs are tagged with a dedicated `RouteProtocol` value
(`common::ROUTE_PROTOCOL`, see its doc comment) - the same mechanism BIRD/other routing daemons use
to mark their own routes. This is what makes route bookkeeping correct across a restart (see below):
only routes carrying that exact tag are ever treated as "ours".

## Restarts are the reload mechanism

Talos restarts an extension service's container whenever its `ExtensionServiceConfig` changes -
confirmed directly from Talos source (`internal/app/machined/pkg/controllers/runtime/
extension_service.go`'s `handleRestart()`), regardless of the service's own `restart:` policy. So
`awg` never needs to watch its own config file for changes - a config edit always means a fresh
process, from scratch. Every startup step is written to be correct under that assumption:
`ensure_link`/`ensure_addresses` are idempotent, peer sync reads the kernel's actual peer set
(`interface::current_peers`) rather than assuming none exist, and route tracking seeds its
"already installed" set from the kernel's own `ROUTE_PROTOCOL`-tagged routes (`handshake.rs`)
before doing anything else - not from an empty set, which would leak routes across a restart.

`restart: always` in `extension-services/awg.yaml`: `awg` is a perpetual daemon (the route-tracking
loop never returns under normal operation), not a one-shot job, so any exit - success or failure -
is grounds for a restart.

## `router`: BIRD-based OSPF/iBGP routing, also driven by a static config file

A second binary, `router`, ported from `operators/router`'s BIRD-config rendering/reload logic the
same way `awg` was ported from `operators/mesh`/`operators/roadwarriors` - no Kubernetes CRDs, one
static file (`/etc/talos-extensions/router.yaml`), read once at startup. It bundles `bird`/`birdc`
directly (spawned and supervised as a child process, staged into the same
`rootfs/usr/local/lib/containers/router/` directory as the `router` binary itself) rather than
running BIRD as a separate sidecar container the way `operators/router` does - Talos extension
services have no sidecar concept, a service is always one `container.entrypoint`.

Unlike `operators/router`, there's no CRD-derived topology to read: `router.yaml` declares
`node.loopback_addresses` (this node's own IPv4+IPv6 loopback identity), `bgp_peers` (every other
mesh node's name + IPv6 loopback - can't be discovered, must be static), `ospf_interfaces` (a list
of exact interface names, shell-glob patterns like `"mesh-*"`, or CIDRs matching an interface's
address - fed straight into BIRD's own `interface` clause, so no code here needs to know `ext-awg`'s
actual interface names), `learn` (IPv4 CIDR *ranges*, not exact per-peer `/32`s, re-announced over
iBGP whenever a kernel route falls inside one), `announce` (static routes to redistribute), and an
optional `bypass` block (RIPEstat/DNS-resolved blackhole routes, refreshed on an interval - this
part stays "live", unlike everything else in this workspace, since resolving ASN/geoip/DNS sources
is the whole point of the feature). See `router/src/config.rs`'s doc comments for the full schema
and `router/src/bird.rs` for how each field becomes BIRD config.

One behavioral change worth calling out: `operators/router`'s automatic "never blackhole any
cluster node's own endpoint" exclusion isn't ported (there's no cluster-wide node list a static,
per-node config file could read) - whoever authors `router.yaml`'s `bypass.exclude` is responsible
for excluding this node's own (and any peer's) public endpoint themselves, the same
config-authoring-is-a-human-responsibility pattern already documented above for `awg`'s private
keys.

## `nftables`: ruleset loader with a table-loss watchdog

A third binary, `nftables`, ported from `operators/nftables`'s MSS-clamp/NAT ruleset text and its
"identify our own tables by name, delete-then-recreate" idiom. Applies
`/etc/talos-extensions/nftables.yaml`'s `ruleset:` once at startup, same as `awg`/`router` converge
their own state once at startup - but unlike a true oneshot, it doesn't exit afterward.

**Why it stays resident**: confirmed directly on a real node - something else's first
`iptables`/`ip6tables` invocation transitioning into iptables-nft mode (timed around kubelet/
kube-proxy's own first sync on a freshly booted node) can do a one-time broad nftables reset that
catches tables it doesn't recognize, including ours, *if* our own apply happens to run before that
reset. Observed both outcomes on the same node across reboots depending on scheduling alone - not a
perpetual conflict, but an unpredictable one-time boot race that a bare "apply once and exit"
can't be reliable against. `extension-services/nftables.yaml`'s `restart: always` plus a
`nft monitor`-driven watchdog loop in `main.rs` (every nftables event on the node wakes it to
re-check its own tables via `nftables::all_present` and reapply if any are missing) is the same
strategy Talos's own `network.NfTablesChainController` uses to keep *its* table present - see that
controller's source (`internal/app/machined/pkg/controllers/network/nftables_chain.go`) for the
same event-driven reconcile pattern, and `nftables.rs`'s own doc comment for the full story.

The config is not a set of structured fields this binary renders into rules - `ruleset:` is the
actual nftables syntax, verbatim, fed to a vendored static `nft -f` almost unmodified. This binary
only does two things to it:

1. **`{{ name }}` placeholder substitution** (`template.rs`) for values that can't be known when
   the ruleset text is written - currently `defaultroute_interface_ipv4`/
   `defaultroute_interface_ipv6`, resolved via `common::netlink::rt::RtClient::
   default_iface_v4`/`default_iface_v6`. Only placeholders the ruleset actually references get
   resolved (and retried, bounded, if no default route exists yet) - a v4-only node applying a
   ruleset that never mentions `defaultroute_interface_ipv6` doesn't need one to exist.
2. **Own-table identification by scanning, not hardcoding** (`nftables.rs`): before applying, it
   finds every `table <family> <name>` the (substituted) ruleset declares and issues `nft delete
   table <family> <name>` for each (errors ignored - the table not existing yet is normal on the
   first run). This is deliberately *not* `flush ruleset` - kube-proxy, Talos's own ingress
   firewall, or anything else on the same node may have nftables tables of its own that must
   survive. Unlike `operators/nftables`, which hardcodes its table names in Rust, the names live in
   whoever authors `ruleset:` - if a table gets renamed between two config versions, the old name
   is orphaned rather than cleaned up automatically, the same class of limitation the original
   hardcoded-name approach already had, just relocated.

Rules content (MSS clamp on `forward`, NAT of RFC1918/private ranges on egress via the default
route interface) is not baked into this binary at all - it's just the first real `ruleset:` deployed
through it. See `../talos-nftables-extension/`'s README for the packaging side (why `nft` is a
statically-linked binary built from source rather than the dynamically-linked package
`siderolabs/pkgs` already ships) and an example `ruleset:` value.

A live handshake-polling *watcher* independent of route installation (i.e. something readable via
`talosctl` beyond "does a route exist") was deliberately deferred - if it's ever wanted, the hook
point is `handshake.rs`'s `dump_handshakes`, which already has the parsed per-peer handshake
timestamps.

## Development

```sh
cargo test
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
```

No mocking framework - pure logic (`config::validate`, `interface::diff_peers`,
`rt::{to_remove,parse_cidr}`) is unit-tested directly; netlink I/O is a thin, not-unit-tested shim
around it (see `common/src/netlink/`). Requires a real Linux host with the `amneziawg` kernel module
loaded and `CAP_NET_ADMIN` to exercise end-to-end - see `talos-awg-extension/docs/
extension-services.md` for a local smoke-test recipe.

Building the actual release artifact (cross-compiling `awg` and baking it into the Talos system
extension alongside the kernel module) happens in the sibling `talos-awg-extension` repo, not here -
this repo only needs to produce a plain binary:

```sh
cargo zigbuild --release --target x86_64-unknown-linux-musl -p awg
cargo zigbuild --release --target aarch64-unknown-linux-musl -p awg
```
