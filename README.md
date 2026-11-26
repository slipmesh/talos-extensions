# talos-extensions

The Rust workspace behind the slipmesh Talos system extensions: three daemons that bring up a
node's mesh networking with no Kubernetes API involved, plus the offline generator that writes
their config.

| crate | binary | runs | what it does |
| --- | --- | --- | --- |
| `awg` | `awg` | on the node, as `ext-awg` | brings up AmneziaWG interfaces and peers over netlink |
| `router` | `router` | on the node, as `ext-router` | renders BIRD config (OSPFv3 + iBGP), supervises `bird` |
| `nftables` | `nftables` | on the node, as `ext-nftables` | applies an nftables ruleset and keeps it applied |
| `taloscfg` | `slipmesh-taloscfg` | on your workstation | renders every `talos` node's patch from the files of `slipmesh.yaml` |
| `common` | — | — | netlink, obfuscation types, shared route tagging |

This repository produces plain binaries and nothing else. They ship in the
`ghcr.io/slipmesh/talos-extensions` image with their `extension-services/` specs, and
[talos-installer](https://github.com/slipmesh/talos-installer) takes that image by digest,
packages each daemon into a Talos system extension and bakes the extensions into an installer.

## Why none of this talks to Kubernetes

A node needs mesh connectivity established before kubelet or the Kubernetes API is reachable at
all: in a multi-site WAN mesh the API server itself may only be reachable *through* the overlay,
so a boot-time dependency on it would be circular. Every daemon here is therefore driven by a
static file placed in the machine config, read once at startup — no API client, no CRDs, no
cluster membership required. A node that hasn't joined a cluster yet, or never will, works the
same as one that has.

`common/` is purely netlink-facing for the same reason: no `kube`, no `k8s-openapi`, nothing that
implies a running cluster.

---

## `awg`: AmneziaWG interfaces from a static file

### One interface shape, no discriminator

There is no "mesh interface" or "road-warrior interface" type. Every interface is the same shape:
a name, addresses, a private key, and a list of peers. The only behavioral distinction is per
peer:

- A peer with **no `allowed_ips`** gets the full-tunnel default (`0.0.0.0/0` + `::/0`) as its
  AllowedIPs. Its handshake is never polled and no kernel route is ever installed for it -
  connectivity comes from whatever routing protocol runs over the tunnel once it's up (e.g. OSPFv3
  over a link-local address), not from a per-peer route. This is a mesh link between two nodes.
- A peer with an **explicit `allowed_ips`** gets exactly those CIDRs as AllowedIPs, and is
  handshake-tracked at 1Hz: while its last handshake is less than 180 seconds old, a kernel route is
  installed for each CIDR; once it goes stale, the route is removed. This
  is a roaming client - the route's mere presence in the kernel *is* the "this client is currently
  connected" signal, with no status field anywhere. `slipmesh_awg_peer_connected` (below) reports
  that same verdict without reading the FIB by hand.

One interface can freely mix both kinds of peer.

### Config

Read from a fixed path (`/etc/talos-extensions/awg.yaml` inside the container) - never an
environment variable or CLI flag. The whole file is rendered into the node's machine config as an
`ExtensionServiceConfig` document's `configFiles[].content`. See talos-installer's
[docs/awg.md](https://github.com/slipmesh/talos-installer/blob/main/docs/awg.md) for a full
machine config example.

```yaml
interfaces:
  - name: mesh-a1b2c3d4
    listen_port: 51820
    addresses: ["fe80::a1b2:c3d4/64"]
    private_key: "...base64, this node's own..."
    obfuscation: {jc: 4, jmin: 40, jmax: 70, h1: 1, h2: 2, h3: 3, h4: 4}
    mtu: 1420                          # unset leaves the kernel's default
    peers:
      - public_key: "...peer's base64 public key..."
        endpoint: "192.0.2.7:51820"
        # no allowed_ips -> full-tunnel, untracked
  - name: rw-north
    listen_port: 51900
    addresses: ["203.0.113.1/27", "3fff:99::1/64"]
    private_key: "...base64, same value on every node that should share this identity..."
    peers:
      - public_key: "...client's base64 public key..."
        allowed_ips: ["203.0.113.5/32"] # tracked: handshake polled, route installed while fresh
    obfuscation:
      jc: 4
      jmin: 40
      jmax: 70
      s1: 50
      s2: 100
      h1: 5-1000                       # a header is one number or a range lo-hi
      h2: 1001
      h3: 1002
      h4: 1003
      s3: 60                           # junk size, cookie-reply packets
      s4: 20                           # junk size, transport (data) packets; lowers the MTU that fits
      i1: "5-10"                       # decoy/cover packet header spec
      header_protection_key: "...base64, same wire format as private_key..."  # every peer needs it
      content_padding_addition: 0-128  # bytes; a number or a range, ends up to 65535
      rekey_after_time: 100-140        # seconds
      max_handshake_attempts: 90
      random_trailers: true            # 3.1: pad outgoing packets to a varying length; both ends
      disable_cookies: true            # 3.1: never send cookie replies
metrics:
  listen: "198.51.100.4:9586"           # omit the whole section to serve nothing
```

**Private keys always come from the config - this binary never generates or persists one.**
Whoever renders the machine config is responsible for giving a node its own per-interface key, or
placing the same key in every node's config when a single shared identity is needed (e.g. so a
roaming client sees one consistent server identity no matter which node it's currently connected
to). This is a config-authoring concern, not something `awg` decides. The same applies to
`header_protection_key`. `taloscfg` (below) is one such config author.

A peer with an `endpoint` is one this node dials, and after a time of silence it is sent a packet,
so that a NAT on the way keeps the tunnel's mapping. `persistent_keepalive` on the peer sets that
time in seconds: a number, or a range `lo-hi` that starts at 1 or above, from which the kernel
module draws at every timer; `0` sends none. Left out, it is 25 on an interface that sets no
obfuscation and `20-30` on one that sets any. A peer without an `endpoint` is only waited for and
is sent none, whatever it sets.

**Every AmneziaWG obfuscation parameter is exposed**, through 3.1, not just the original nine
(jc/jmin/jmax/s1/s2/h1-h4) - confirmed field-by-field against the current kernel module's
`src/netlink.c` and amneziawg-tools' own config parser (`src/config.c`), since the kernel module's
own README only documents the original set. See `sliplib_config::Obfuscation`'s doc comment for the
full field list and what each one does. `header_protection_key` belongs to the interface: once it is
set, the kernel module protects the header of every handshake, cookie and data packet to and from
every peer of that interface, so each peer needs the same key and the same `s1`..`s4`; junk and
decoy packets are not protected, and there is no per-peer switch. `awg` leaves the key out of its
request when the config has none, and the module has no way to take a key off an interface, so a
key removed from the config stays in force until the interface is created anew, at the next boot.
So does the module's check of the junk sizes below: a config that drops the key and takes any of
`s1`..`s4` below 12 is refused on every pass until then, by the module at `SetDevice` once the link
is up, since the config alone does not show it. The kernel module also accepts the key
only when every junk size `s1`..`s4` is at least 12, room for the header protection nonce (an
unset size counts as 0), and refuses magic headers `h1`..`h4` that share a value (an unset one
counts as 1..4); both come back as a bare `Invalid argument` for that interface. It never checks
that `jmin` does not exceed `jmax` before drawing junk packet sizes between them. `awg` refuses an
interface that breaks one of these three without touching it - one an earlier run left up stays as
it is - brings up the others, then exits and is restarted, so route tracking and metrics wait until
the config is fixed. `taloscfg` refuses to render it, see `sliplib_config::Obfuscation::validate`.

`h1`..`h4` and the six values `content_padding_addition`, `rekey_after_time`, `rekey_timeout`,
`reject_after_time`, `keepalive_timeout` and `max_handshake_attempts` are each a number or a range
written `lo-hi`: the module draws the header of every packet, and each timing or padding value where
it uses one, out of the range. A number is the range of that one value. Both ends of a tunnel carry
the same four header ranges. The six values need not be equal on the two ends, but
`keepalive_timeout` meets the peer's timers: an end that sends without hearing back starts a new
handshake after its own `keepalive_timeout` plus `rekey_timeout`, so a `keepalive_timeout` above
that sum on the other end makes one-way traffic re-handshake. Their ends go up to 65535, the width
the module holds them in. Zero or an unset one leaves a timing value to the module's own constants
and a data packet to the padding it gets without `content_padding_addition`: WireGuard's own, or the
random trailer when `random_trailers` is on. All six are sent on every reconcile, so a value taken
out of the config is taken off the interface. A non-zero `content_padding_addition` replaces the
padding of a data packet, `random_trailers`' included. `rekey_after_time` has to end below 180: the
module stops using a key 180 seconds after its handshake, whatever `reject_after_time` says, so an
initiator that only sends would renew after the key is gone. One that also receives renews once the
key is older than `reject_after_time` less the low ends of `keepalive_timeout` and `rekey_timeout`,
165 seconds by default; keep that below 180 too. Keep `rekey_after_time` well below 180; the
module's own value is 120. A config with a range in it needs this release of `awg` or a later one:
an earlier one refuses it.

Of the two 3.1 switches, `random_trailers` has to be the same on both ends: it appends a
random-length trailer to outgoing packets, and only an end that sets it accepts a handshake or
cookie message longer than its exact size, so an end without it drops what an end with it sends.
`disable_cookies` is each end's own: it suppresses cookie replies, whose own message type is a
signature - at the cost of the load-shedding they exist for.

Both are sent explicitly on every reconcile, set or not: an omitted attribute leaves the
kernel's current value alone. A module older than 3.1 rejects them - generic netlink validates against
the family's own attribute maximum and fails the whole request rather than ignoring what it
does not know - so a refused `SetDevice` is retried once without them, and the interface comes
up without the two switches instead of not at all. Older than 3.0 the module takes none of this:
the six values and the magic headers go out in the form of 3.0, so `awg` needs AmneziaWG 3.0 or
later, and 3.1 for the two switches.

### Ownership: the whole `amneziawg` netlink kind, no naming convention

`awg` treats itself as the sole owner of every interface on the host whose netlink link-kind
(`IFLA_INFO_KIND`, what `ip -d link show` reports as `type amneziawg`) is `amneziawg` - not just
ones matching some name prefix. On every start, anything of that kind not named in the current
config gets deleted (`gc.rs`). This is safe *because* nothing else on a node is expected to ever
create an `amneziawg`-kind interface - if that assumption is ever wrong, GC will delete it.

Routes this daemon installs are tagged with a dedicated `RouteProtocol` value
(`common::ROUTE_PROTOCOL`, see its doc comment) - the same mechanism BIRD/other routing daemons use
to mark their own routes. This is what makes route bookkeeping correct across a restart (see below):
only routes carrying that exact tag are ever treated as "ours".

### Metrics

With a `metrics` section in the config, `awg` serves `GET /metrics` on that address; without one it
opens nothing, because a node not set up for scraping should not open a port on a default.
`taloscfg` (below) renders the section from the `talos` `platform` document's `metrics.mesh.port`,
binding it to the node's own v4 mesh loopback - the address kubelet reports as `InternalIP`, so
Prometheus reaches it through node discovery plus a port relabel, exactly the way node-exporter is
reached. That address belongs to `ext-router`, and Talos does not order extension startup, so the
socket is bound with `IP_FREEBIND` and starts answering once the address appears; until then the
scrape fails, which is the honest reading rather than a fault to paper over.

What it answers is the one thing per-interface counters cannot: whether a link is quiet or dead.
Both read as zero bytes, the last handshake separates them, and that lives only in the `amneziawg`
genl family - `WG_GENL_NAME` is `"amneziawg"`, not `"wireguard"`, so every exporter built on
`wgctrl` looks at the wrong family and sees nothing.

| metric | type | meaning |
| --- | --- | --- |
| `slipmesh_awg_peer_last_handshake_seconds` | gauge | unix time; no series at all if the peer never handshook |
| `slipmesh_awg_peer_rx_bytes_total` / `..._tx_bytes_total` | counter | per-peer traffic |
| `slipmesh_awg_peer_connected` | gauge | 1/0, this daemon's own verdict - roadwarrior peers only |
| `slipmesh_awg_interface_peers` | gauge | peers *configured*, by `interface` and `kind` |
| `slipmesh_awg_interface_dump_ok` | gauge | 1/0 per interface, this scrape |
| `slipmesh_awg_reconcile_last_success_seconds` | gauge | the routing loop's last completed pass |
| `slipmesh_build_info` | gauge | `component="awg"`, `version` |

Peer series carry `interface`, `kind`, `peer` (the base64 public key) and `peer_name` (the config's
own name for it, empty when it has none - a dashboard needs something a human can read). `kind` is
`mesh` or `roadwarrior`, decided by `allowed_ips` and nothing else: matching on the interface name
would work today and break the first time something is named differently.

Labels come from the config and values from the dump, joined on the public key, so a peer removed
from the config disappears on the next scrape and a peer the kernel still has but the config no
longer names is not reported at all. `slipmesh_awg_peer_connected` is the routing loop's own
verdict, published over a watch channel and emitted only while the snapshot behind it is fresh: it
says a route is installed, which is not the same as "the handshake looks recent" whenever
`route_add` failed. A peer's `Endpoint` is deliberately never read into a label - a roaming client
changes address with its network, and each change would mint a new time series.

The prefix is `slipmesh_awg_`, not `slipmesh_`: `ext-router` has peers of its own (BGP, OSPF) and
would collide on `slipmesh_peer_*` the day it exports anything. `slipmesh_build_info` is the one
family deliberately without a subsystem, so `component` separates the extensions there.

### Restarts are the reload mechanism

Talos restarts an extension service's container whenever its `ExtensionServiceConfig` changes -
per Talos source (`internal/app/machined/pkg/controllers/runtime/extension_service.go`'s
`handleRestart()`), regardless of the service's own `restart:` policy. So
`awg` never needs to watch its own config file for changes - a config edit always means a fresh
process, from scratch. Every startup step is written to be correct under that assumption:
`ensure_link`/`ensure_addresses` are idempotent, peer sync reads the kernel's actual peer set
(`interface::current_peers`) rather than assuming none exist, and route tracking seeds its
"already installed" set from the kernel's own `ROUTE_PROTOCOL`-tagged routes (`handshake.rs`)
before doing anything else - not from an empty set, which would leak routes across a restart.

`restart: always` in `extension-services/awg.yaml`: `awg` is a perpetual daemon (the route-tracking
loop never returns under normal operation), not a one-shot job, so any exit - success or failure -
is grounds for a restart.

The stop itself changes nothing: on SIGTERM, which is how Talos stops a service, `awg` exits and
leaves its interfaces, peers and routes as they are, so a restart does not take the mesh down.

---

## `router`: BIRD-based OSPF/iBGP routing, also driven by a static file

`router` reads two files at startup - `/etc/talos-extensions/router.yaml`, the facts, and
`/etc/talos-extensions/router.conf.j2`, BIRD's config as a template of them - renders the one with
the other, and spawns `bird` as a supervised child process - staged into the same
`rootfs/usr/local/lib/containers/router/` directory as the `router` binary itself, rather than
running as a separate sidecar container: Talos extension services have no sidecar concept, a
service is always one `container.entrypoint`. It talks to BIRD over BIRD's own control socket
protocol directly, so no `birdc` binary is shipped.

On SIGTERM `router` passes the signal on to `bird`, whose own shutdown closes the BGP sessions with a
NOTIFICATION and withdraws the routes it exported to the kernel, and exits once `bird` has. A `bird`
still running 8 s later is killed, ahead of Talos's own SIGKILL at 10 s.

There is no topology to discover, because there is nothing to discover it from. `router.yaml`
declares it all:

- `node.loopback_addresses` - this node's own IPv4+IPv6 loopback identity;
- `bgp_peers` - every other mesh node's name + IPv6 loopback (static by necessity);
- `ospf_interfaces` - interface names, or a prefix and `*` like `"mesh-*"` - fed straight into
  BIRD's own `interface` clause, so nothing here needs to know what `awg` actually named its
  interfaces;
- `direct_interfaces` - interfaces whose own addresses should be announced (`protocol direct`);
- `learn` - IPv4 CIDRs: any kernel route equal to or inside one is picked up and re-announced over
  iBGP, whoever installed it. This is how a node's pod subnet gets announced without naming the
  CNI's interface;
- `announce` - static routes to redistribute;
- `bypass` (optional) - RIPEstat/DNS-resolved blackhole routes, refreshed on an interval. This
  part stays "live", unlike everything else in this workspace, since resolving ASN/geoip/DNS
  sources is the whole point of the feature;
- `classes` and `vars` (optional) - the route classes of `slipmesh.yaml`, in its shape, and this
  node's `vars`, given to the template in the shape below and read by nothing else.

See the doc comments of `sliplib_config::router::RouterConfig` for the full schema, with
`metrics` from `common/src/daemon.rs`, `classes` and `vars` from `common/src/template.rs`, and the
template below for how each field becomes BIRD config.

Whoever authors `router.yaml` is responsible for `bypass.exclude` covering this node's own (and
every peer's) public endpoint - a blackholed endpoint takes the mesh link down with it. There is no
cluster-wide node list a static per-node file could consult, so this is the same
config-authoring-is-a-human-responsibility pattern documented above for `awg`'s private keys.
`taloscfg` writes no `bypass`, so a `router.yaml` it generates blackholes nothing.

### The `bird.conf` template

`router.conf.j2` is a [minijinja](https://docs.rs/minijinja) template, rendered again on every
bypass refresh. It sees these variables, every value from `router.yaml` already sanitized for
where BIRD syntax puts it:

| variable | value |
| --- | --- |
| `loopback`, `ipv6_loopback` | this node's loopbacks |
| `as_number` | `bgp_as` |
| `router_loopback_iface` | the dummy interface carrying the loopbacks, `router-lo` |
| `ospf_interfaces` | `{pattern, bfd}` each: the entry as an `interface` clause takes it, and whether BFD is asked for on it |
| `bgp_peers` | `{protocol_id, address}` each |
| `direct_interfaces` | `{protocol_id, pattern}` each |
| `bypass`, `announce` | `{net, label}` each |
| `learn` | the `learn` CIDRs, each with BIRD's `+` |
| `bfd` | `{min_rx_ms, min_tx_ms, multiplier}`, or none |
| `awg_route_protocol` | the protocol number `awg` tags its routes with |
| `classes` | the route classes by name: `protocol`; `table`, or none; `rules` by name, each `{priority, mark, lookup}`, `mark` as `{value, mask}` in `0x` form, or none, and `lookup` `main`, or none for the class's table. Empty without `classes` |
| `vars` | `vars` as YAML reads it, empty without it |

A template reads a class, a rule or a value that a node may lack behind `is defined`, the outer
name first: `{% if classes.egress is defined and classes.egress.table %}`. Read without it, a
missing one fails the rendering. A value that is none, such as a class's `table` or a rule's
`lookup` left out, is no error: it prints `None`, and a template tests it with `is none` or by its
truth. A mapping iterates by name, not in the order written.

A template that reads any other variable is refused when it is compiled - in any branch, not only
the ones a given node takes - and `router` exits without one rather than fall back on anything.
The reference template, [`router/templates/router.conf.j2`](router/templates/router.conf.j2), runs
OSPFv3 over the mesh links and iBGP over the loopbacks, and learns the routes of the roadwarrior
clients a node holds by their protocol number (`krt_source`): `awg`'s `awg_route_protocol`, or the
roadwarriors operator's 151, whatever `learn` says. A pool runs on several nodes under one address,
and that route is how the others know which node a client is on. iBGP carries IPv4 and IPv6; a
peer that offers only IPv4 keeps its session.

Where the `egress` route class has a `table`, the reference template exports the bypass routes to
iBGP with the large community `(<as_number>, <table>, 0)`. A node puts the iBGP routes that carry
it into that kernel table, for both families, and not into `main`.

On an exit node, the egress agent puts its route for the class straight into that table, under
the class's `protocol` and with any metric but BIRD's 32: at that one the kernel refuses the route
while BIRD's path is in the table. BIRD learns it at preference 200, above BGP's 100, so another
exit node's path to the same prefix stays out of the table while it is there and takes its place
once it goes. BIRD announces it with the community, like a bypass route.

---

### BIRD metrics

The `talos` `platform` document's `metrics.router.port` makes `ext-router` run
[`bird_exporter`] beside BIRD, reading the same control socket for protocol state - session
up/down, uptime, prefix counts, BFD sessions.
The address is derived the same way `awg`'s is, from the node's own v4 loopback, so the two
cannot drift; unset means no node runs it. It needs no `IP_FREEBIND` counterpart, because
`ext-router` brings that address up itself before it starts either child.

Unlike `bird` exiting, the exporter exiting is not fatal: it is restarted in place, since a
failed scrape is not a reason to restart the container and tear down every adjacency.

[`bird_exporter`]: https://github.com/czerwonk/bird_exporter

## `nftables`: ruleset loader with a table-loss watchdog

Applies the ruleset template `/etc/talos-extensions/nftables.conf.j2` once at startup, the same way
`awg`/`router` converge their own state once at startup - but unlike a true oneshot, it doesn't
exit afterward.

**Why it stays resident**: something else's first `iptables`/`ip6tables` invocation transitioning
into iptables-nft mode (timed around kubelet/kube-proxy's own first sync on a freshly booted node)
can do a one-time broad nftables reset that catches tables it doesn't recognize, including ours,
*if* our own apply happens to run before that reset. Which side of the race wins depends on
scheduling alone, so a bare "apply once and exit" is not reliable against it.
`extension-services/nftables.yaml`'s `restart: always` plus a
`nft monitor`-driven watchdog loop in `main.rs` (every nftables event on the node wakes it to
re-check its own tables via `nftables::all_present` and reapply if any are missing) is the same
strategy Talos's own `network.NfTablesChainController` uses to keep *its* table present - see that
controller's source (`internal/app/machined/pkg/controllers/network/nftables_chain.go`) for the
same event-driven reconcile pattern, and `nftables.rs`'s own doc comment for the full story.
On SIGTERM it exits with the ruleset still loaded.

The config is not a set of structured fields this binary renders into rules - the template is the
actual nftables syntax, fed to a vendored static `nft -f` almost unmodified. This binary only does
two things to it:

1. **Rendering** (`template.rs`, a minijinja template like `router`'s) with the values that can't
   be known when the ruleset is written - currently `defaultroute_interface_ipv4`/
   `defaultroute_interface_ipv6`, resolved via `common::netlink::rt::RtClient::
   default_iface_v4`/`default_iface_v6` - and with `classes` and `vars` from
   `/etc/talos-extensions/firewall.yaml`, given as `router` gives them. Without that file both
   are empty; a file there that does not read stops the daemon. A template reading any other
   variable is refused before anything is applied. Only the variables the template actually
   reads get resolved (and retried, bounded, if no default route exists yet) - a v4-only node
   applying a ruleset that never mentions `defaultroute_interface_ipv6` doesn't need one to exist.
2. **Own-table identification by scanning, not hardcoding** (`nftables.rs`): before applying, it
   finds every `table <family> <name>` the rendered ruleset declares and issues `nft delete
   table <family> <name>` for each (errors ignored - the table not existing yet is normal on the
   first run). This is deliberately *not* `flush ruleset` - kube-proxy, Talos's own ingress
   firewall, or anything else on the same node may have nftables tables of its own that must
   survive. The table names live in whoever authors the template, not in this binary; the cost of
   that is that renaming a table between two config versions orphans the old one rather than
   cleaning it up.

No rule content is baked into this binary at all - MSS clamping, NAT, or anything else is just
whatever the template says; [`nftables/templates/nftables.conf.j2`](nftables/templates/nftables.conf.j2)
is the reference one, with those two.

Where the `egress` route class has a rule `uplink-replies` with a mark, the reference ruleset also
gives that mark to the replies to a connection that came in on the IPv4 default-route interface,
for both families. Only the bits of the mark's mask are set; the others stay as they are. The
`RoutingRuleConfig` that `generate` makes of that rule then sends those replies out through `main`
rather than the class's table. An IPv6 connection that comes in on another interface is not marked,
and its replies take the class's table; a template that names that interface, through a `vars`
value, covers it.

The reference ruleset starts by removing the tables of the mark, `ip talos_mark` and
`inet talos_mark`, so that a ruleset without the mark leaves neither behind. `destroy` needs Linux
6.3 and nft 1.0.8: on an older kernel `nft -f` fails after the daemon has deleted its tables, and
the node is left with none of them.

See talos-installer's
[docs/nftables.md](https://github.com/slipmesh/talos-installer/blob/main/docs/nftables.md) for the
packaging side: why `nft` is a statically linked binary built from source rather than the
dynamically linked package siderolabs/pkgs already ships.

---

## `taloscfg`: the files of one network, every node's patch

`slipmesh-taloscfg` is the only crate here that doesn't run on a node. It reads the files of
`slipmesh.yaml` given with `--in`, which takes several values and may be repeated, in [format
version 2](https://github.com/slipmesh/sliplib/blob/main/docs/slipmesh-yaml.md), laid over each
other as [several files](https://github.com/slipmesh/sliplib/blob/main/docs/slipmesh-yaml.md#several-files)
are: one file, or the same network split into its architecture and its secrets, gives the same
patch files. The format describes the whole mesh and everything else a node of `platform: talos`
carries. It writes `patches/<node>.yaml` for every such node, each holding the node's Talos
documents followed by the `awg`, `router` and `nftables` `ExtensionServiceConfig` documents and the
[routing rules](#routing-rules) it generates, which `talosctl apply-config -p` then ships to that
node. A patch file is output only:
nothing in it is read back, so edit `slipmesh.yaml` and regenerate rather than editing the patch.

It only reads `slipmesh.yaml`. What writes into the file - its keys, its obfuscation,
`mesh.interface_prefix` - is [`slipmesh`](https://github.com/slipmesh/sliplib#slipmesh), and where
the file lacks something `generate` needs, the refusal names the `slipmesh` command that writes it.
A file of format version 1 is refused, naming the document that converts it.

### What it reads of `slipmesh.yaml`

The format is the specification's. Of it, the generator serves the nodes of `talos`, and on them:

- the network, as every tool reads it;
- the `template` documents: of those that reach a node, the last by rank for each daemon,
  `router` and `firewall`;
- the `patch` documents of `talos`, merged for each node.

A node of another platform gets no patch file; `generate --node` with one is refused, naming its
platform.

The bodies of the `talos` `platform` document and of each `template` are the generator's to read,
and it refuses, naming the document and the line: a key the specification's table does not have, or
a missing one; a listener without `port`, a `port` of 0, and one port for both; a `daemon` other
than `router` or `firewall`; and a `base` that is not `sha256:` and 64 hexadecimal digits.

`patch` documents of one Talos identity - `apiVersion`, `kind`, `name` - are merged for each node in
the order of their rank, so the narrower one wins wherever it sits. Mappings merge key by key, an
explicit `null` deletes a key, and a sequence replaces the one before it whole. That last part
differs from Talos' own strategic merge, which appends to a list: appending by key needs the types
Talos has and this tool does not, and appending without a key would leave no way to remove an
element. Every document goes into the patch file serialized; its comments stay in `slipmesh.yaml`.

A file a `patch` document carries in `configFiles[].content` may be written as YAML - a mapping or
a list - rather than as a string. Talos takes only a string there, so the patch file gets that
YAML's text. Written this way, each field of the file is a field of `slipmesh.yaml` like any other:

```yaml
slipmesh:
  kind: patch
  platform: talos
  include: [node-b]
apiVersion: v1alpha1
kind: ExtensionServiceConfig
name: example
configFiles:
  - mountPath: /usr/local/etc/example/example.yaml
    content:
      listen: 198.51.100.2
```

The generator reads of a `patch` document only what it uses: its `apiVersion`, `kind` and `name`,
each a string, a `KubeNodeConfig`'s `annotations`, a mapping, and the keys set on a generated
document. A value of the wrong type there is refused at its key and line; every other key goes to
Talos as written.

A `patch` document may also name a generated `ExtensionServiceConfig`, `awg`, `router` or
`nftables`, to add files to it: the files follow the generated ones in that same document, since
Talos takes one document per name. It may set `configFiles` and nothing else. Of an entry the
generator reads only `mountPath`, a string, and refuses one at a path the generator writes; the
entry goes to Talos as written.

### Templates

The `router` document carries the node's router template as `/etc/talos-extensions/router.conf.j2`,
and the `nftables` document, written after it, the `firewall` template as
`/etc/talos-extensions/nftables.conf.j2`. A node gets the last by rank of the `template` documents
of a daemon that reach it, or, where none does, that daemon's reference template of the
`slipmesh-taloscfg` release that runs `generate`. A daemon on the node takes the file it is given
and has no template of its own. A template from the files is checked as that daemon will check it
and rendered with the node's values, a `router` one with the node's config and a `firewall` one with
each interface name standing in as its variable's name, so one that would fail on a node fails
`generate` instead. A template overridden on every node it reaches is not checked.

The values are the route classes of the network and the `vars` that reach the node, laid by rank.
`router.yaml` carries them as `classes` and `vars`, and the `nftables` document as
`/etc/talos-extensions/firewall.yaml`, beside the template. Neither key is written when it is
empty, so `firewall.yaml` holds `{}` when both are.

The text in the files is the one in force, and a newer reference does not replace it. `template`
prints the `template` document that gives every node of `talos` a daemon's reference template,
`base` included, to add to the file and edit there:

```sh
slipmesh-taloscfg template router    # or: firewall
```

It prints the document alone, without a leading `---`:

```sh
{ echo ---; slipmesh-taloscfg template firewall; } >> slipmesh.yaml
```

A template whose `base` is not the hash of its daemon's current reference is warned about, with
the diff from its text to that reference; the warning stops nothing.

### Mesh MTU

Every mesh interface gets one MTU, the largest at which a full-size packet still crosses every
link unfragmented. A fragmented outer packet takes TCP in the tunnel down to a few Mbit/s.
`sliplib-mesh` computes it, as the specification's "The MTU of the mesh" says, from the underlay
MTU of each node, the family each link is dialed over and the `s4` of each link of type
`amneziawg`; `mesh.mtu` may lower it, and `generate` refuses one above the least link limit.

A change of the mesh MTU has to reach both ends of every link at once.
OSPF compares MTUs in its database description packets and refuses a neighbor whose MTU is larger
than its own, so an adjacency across ends that differ does not form again; BIRD cannot skip the
check. Keep `mesh.mtu` at the current value until every node runs an `awg` that sets the MTU, then
apply every node's patch in one pass. Adjacencies across ends that still differ are down for that
pass.

### Node annotations

Every node publishes what the cluster needs to know about the mesh as annotations on its Node
object: `generate` puts them into the node's `KubeNodeConfig`, merged with the one a `patch`
document gives, since Talos takes one document of that kind. The names are those the
specification lists:

| from | annotation | |
| --- | --- | --- |
| `mesh.interface_prefix` | `slipmesh.net/interface_prefix.mesh` | what every mesh interface's name starts with |
| `routing.classes.<name>.protocol` | `slipmesh.net/route_proto_id.<name>` | one for each route class |
| the node's `endpoint` | `slipmesh.net/endpoint` | as written; none for a node without one |
| the mesh MTU | `slipmesh.net/mesh_mtu` | see [Mesh MTU](#mesh-mtu); none without links |

Talos keeps the annotations it sets in step with the config: a changed value is rewritten on the
Node, and one no longer given is taken off it. A `patch` document may set annotations of its own,
but none under `slipmesh.net/`.

### Routing rules

Each rule of a route class, `routing.classes.<name>.rules`, becomes a `RoutingRuleConfig` document
on every `talos` node, after the generated `ExtensionServiceConfig` documents, in the order the
classes and their rules are written:

```yaml
apiVersion: v1alpha1
kind: RoutingRuleConfig
name: '1000'
fwMark: 1048576
fwMask: 1048576
table: main
```

`name` is the rule's `priority`. `table` is `main` for `lookup: main`, and otherwise the class's
`table`, or `main` for a class without one. A rule with a `mark` gets `fwMark` and `fwMask` both,
in decimal, and `fwMask` is `4294967295` where the mark has no mask: the kernel compares every bit
then and reports that mask, and Talos would replace a document without `fwMask` on every pass. A
rule names no `dst`, so Talos makes it for IPv4 and IPv6 both.

A `patch` that is a `RoutingRuleConfig` named by a generated rule's priority is refused, naming
that rule and its class: Talos takes one document per name, and the two would merge without a word.
A `RoutingRuleConfig` of any other name goes to Talos as written.

### Secrets

Everything derivable is derived: interface names and link-local/loopback addressing fall out of
the network rather than being written by hand, and only the public half of a peer's key ever
appears in the other end's config. Keys aren't derivable: they stand in `slipmesh.yaml`, in
`nodes.<name>.wireguard.private_key` of every node on a link, and the `obfuscation` of every link
of type `amneziawg`. `slipmesh mint` creates the ones the file lacks and writes them there;
`generate` creates none and refuses a node whose config needs one that is missing.

So `slipmesh.yaml` holds private keys in the clear, as the patch files it renders do - keep it
where those are kept.

Each node's configs are rendered and validated by `sliplib-mesh`, on the config types the daemons
read, so the generator and the daemons check one definition.

```sh
slipmesh-taloscfg generate --in mesh.yaml secrets.yaml talos.yaml # every node of talos, into ./patches
slipmesh-taloscfg generate --in cfg/*.yaml --node node-a --diff   # one node, print what would change, write nothing
slipmesh-taloscfg generate --in cfg/*.yaml --check                # validate only
```

Every run renders and validates every node it was asked for before it writes any patch file, and
none writes `slipmesh.yaml`. With `--node`, only the secrets that node's config needs have to be
there: its own key, and for each of its links the peer's key and the link's obfuscation. `--check`
and `--diff` write no patch file either.

`--diff` prints the value of every `private_key`, `header_protection_key` and `password` line, at
any depth, as `<redacted>` when it is the same on both sides and as `<redacted, old>` and
`<redacted, new>` where it changed. A `vars` value under any other key is printed as written.

In every mode a run prints a line that starts with `warning:` on standard error for each way a
link of the nodes it was asked for loses data packets it should deliver, one line each, and for
each template whose `base` is not the current reference, and fails for none of them. A file it
refuses gets no warning.
There are two such cases of loss, both on a link with `random_trailers` on: one of `h1` to `h3` is
a range, which costs up to the share of data packets the line names; and the link has no
`header_protection_key` while one of `s1` to `s3` stands 1 to 15 bytes above `s4`.

### Breaking changes

After v1.15.0-beta.0+sm.5, `generate` takes the files of `slipmesh.yaml` with `--in`, one or
several; `--config` is gone, with no alias and no default file. One file that holds two `network`
or two `groups` documents is laid, where it was refused. A refusal of the network names the key's
line and its file, where it named the document's line and a column after a `reading <file>` line.

After v1.15.0-beta.0+sm.5, `slipmesh-taloscfg` reads a `slipmesh.yaml` of format version 2 alone;
a file of version 1 is converted as sliplib's `docs/slipmesh-yaml-v1-to-v2.md` says, with the
release that reads it before and this one after. `template` prints a `template` document, and
`template nftables` is `template firewall`. A node of another platform gets no patch file any
more: delete the one version 1 wrote for it.

After v1.15.0-beta.0+sm.5, `slipmesh-taloscfg` reads no `$patch`: it merges `$patch: delete` with
the other documents of its identity key by key and writes it as it stands, and Talos applies it. A
narrower patch over a broader `$patch: delete` no longer undoes the deletion, and a `KubeNodeConfig`
with it is no longer refused: the node drops it, the annotations with it.

After v1.15.0-beta.0+sm.5, `awg` reads no `handshake_stale_secs`: a config that has it is read and
the key ignored, and a tracked peer's routes go 180 seconds after its last handshake.

After v1.15.0-beta.0+sm.5, an entry of `ospf_interfaces` or `direct_interfaces`, in `slipmesh.yaml`
or a daemon's config, is refused when it is a CIDR, empty, or holds `?`, a `*` before the end or
another character outside an interface name. `slipmesh-taloscfg` refuses at the check a `patch`
whose `apiVersion`, `kind`, `name` or the `mountPath` of a file it adds to a generated document is
not a string, or whose `KubeNodeConfig` `annotations` are not a mapping.

Since v1.15.0-beta.0+sm.4, a peer's `advanced_security` is gone from the config: a file that still
has it is read and the key ignored. The module reads no per-peer switch; header protection is the
interface's key.

Since v1.15.0-beta.0+sm.4, a file in which one of the six tuning values is above 65535, or one of
them or of `h1`..`h4` is a reversed range or neither a number nor `lo-hi` in decimal digits, cannot
be read: `taloscfg` refuses `slipmesh.yaml`, and `awg` refuses its whole config at start and
touches no interface, so those an earlier run left stay as they are.

Since v1.15.0-beta.0+sm.4, `taloscfg` and `awg` refuse a `rekey_after_time` of 180 or more, a range
of a timing value that starts at 0, and a `reject_after_time` not above `keepalive_timeout` plus
`rekey_timeout`. `awg` leaves such an interface as an earlier run left it, brings up the others and
exits, so route tracking and metrics wait until the config is fixed. Such a value never did what it
said; set it within those bounds or take it out for the module's own value.

Since v1.15.0-beta.0+sm.4, a tuning value taken out of the config is taken off the interface too,
back to the module's own value; it used to stay as the earlier config set it.

Since `slipmesh` 0.17.0, a pool with `header_protection_key`, `s3`, `s4` or `random_trailers` gets
them into its client configs: a client config exported before then, without the key or without
`RandomTrailers`, completes no handshake, without `S4` sends no data the pool takes, and without
`S3` reads no cookie reply. A file of format version 2 holds no pools.

A file of format version 1 is refused, naming the document that converts it. What the entries
before format version 2 said of its keys - the `cluster:` block and the pools refusing a field they
do not know, `cluster.metrics_port` renamed `cluster.awg_metrics_port` in v0.2.0, the ruleset of a
`kind: nftables` document moved into a `kind: patch` one - is the conversion's now, step by step in
sliplib's `docs/slipmesh-yaml-v1-to-v2.md`. A key renamed in a later format keeps no alias either: a
rename lands only with a new Talos line (see [docs/RELEASING.md](docs/RELEASING.md)), and a name
that means one thing in the tool and another in the file is worse than a build that stops.

`generate` no longer writes into `slipmesh.yaml`, and `rw-add`, `rw-del` and `rw-inspect` are gone.
What wrote is now [`slipmesh`](https://github.com/slipmesh/sliplib#slipmesh), installed from the
release assets of its repository or with `cargo install` from a checkout of it:

| was | is |
| --- | --- |
| `generate` creating missing keys and obfuscation, and writing unset network defaults | `slipmesh mint` |
| `generate` writing the reference templates into a file that sets none | `generate` writes the reference into the patch of a node no `template` document reaches, and the file stays as it is |
| `rw-add`, `rw-del`, `rw-inspect` | none: a file of format version 2 holds no pools |

Install it with `cargo install --path taloscfg`.

---

## Development

```sh
cargo test
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
# the build taloscfg uses: features unify across the workspace, so only these packages alone show it
cargo clippy -p common -p router -p nftables -p taloscfg --all-targets --no-default-features -- -D warnings
cargo deny --locked check licenses bans sources
```

The code follows [docs/CODESTYLE.md](docs/CODESTYLE.md).

No mocking framework - pure logic (`config::validate`, `interface::diff_peers`,
`rt::to_remove`, the bypass set arithmetic in `resolver.rs`, `taloscfg`'s patch files)
is unit-tested directly; a node's configs are rendered by `sliplib-mesh` and CIDR parsing and
exclusion come from `sliplib-net`, each tested there;
netlink I/O is a thin, not-unit-tested shim around it (see `common/src/netlink/`).

Exercising a daemon end to end needs a Linux host with `CAP_NET_ADMIN`, and for `awg` the
`amneziawg` kernel module loaded. Each daemon reads its config from the fixed path its
`extension-services/` spec mounts, so a smoke test puts a hand-written config there:

```sh
cargo build -p awg
sudo mkdir -p /etc/talos-extensions
sudo cp awg.yaml /etc/talos-extensions/awg.yaml
sudo ./target/debug/awg
# in another shell:
ip -d link show type amneziawg
ip route show                    # for a tracked peer with a fresh handshake, its route
```

`router` also needs `router.conf.j2` (start from `router/templates/router.conf.j2`) and a `bird`
in its working directory, such as the static one copied out of a built router extension:
`docker create` the image, then `docker cp <id>:/usr/local/lib/containers/router/bird .`.
Restarting a daemon after editing its config exercises the same converge-and-clean-up path a
config change on a node does.

### Releasing

`[workspace.package] version` and the tag are the same number, and the release commit moves both:
every crate here inherits that one version, and it is what an installed `slipmesh-taloscfg`
reports for itself. Bumping only the tag leaves a binary that misnames its own version, which is
how it read `0.1.0` at tag `v0.1.6`. The Release PR workflow (Actions, then Release PR) opens that
commit as a PR with `CHANGELOG.md` regenerated, and merging it tags the release. Release lines,
versions and the steps are in [docs/RELEASING.md](docs/RELEASING.md).

Pull requests and pushes run fmt, clippy, the tests, `cargo audit`, which also runs weekly, and the
`licenses` check, which holds every dependency to the licenses and sources [`deny.toml`](deny.toml)
allows and renders the third-party notices from [`about.toml`](about.toml); only
the push of a merged release PR builds, once every check of that push passes. A pull request also
builds the image from empty placeholders and pushes nothing, so a Dockerfile the release build would
fail on fails there. An advisory with no
fix yet is ignored in `.cargo/audit.toml`, with the reason next to it. It builds every binary for
the musl target on a runner of each arch and packs the four of them, in `/usr/local/bin/`, into
`ghcr.io/slipmesh/talos-extensions`, together with the `extension-services/` specs of the three
daemons in `/usr/local/etc/containers/` and the license notices of what is linked into the binaries
in `/usr/share/licenses/talos-extensions/`: `THIRD-PARTY-NOTICES` for the crates, rendered by
[cargo-about](https://embarkstudios.github.io/cargo-about/) with [`about.hbs`](about.hbs), and
`COPYRIGHT-rust-std.html` and `COPYRIGHT-musl` for the Rust standard library and the musl libc. The
image is pushed as `sha-<commit>`, retagged as the
release once the build succeeds, the commit is tagged, and the GitHub Release gets the same
binaries and notices with a `SHA256SUMS`. Only a released image is one talos-installer can pin, so a daemon
change reaches it through a release.

To reproduce one binary locally, build on a Linux host of that arch with `musl-tools` installed:

```sh
cargo build --release --target x86_64-unknown-linux-musl -p awg
```
