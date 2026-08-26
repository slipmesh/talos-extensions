# talos-extensions

The Rust workspace behind the slipmesh Talos system extensions: three daemons that bring up a
node's mesh networking with no Kubernetes API involved, plus the offline generator that writes
their config.

| crate | binary | runs | what it does |
| --- | --- | --- | --- |
| `awg` | `awg` | on the node, as `ext-awg` | brings up AmneziaWG interfaces and peers over netlink |
| `router` | `router` | on the node, as `ext-router` | renders BIRD config (OSPFv3 + iBGP), supervises `bird` |
| `nftables` | `nftables` | on the node, as `ext-nftables` | applies an nftables ruleset and keeps it applied |
| `patches` | `slipmesh-patches` | on your workstation | renders every node's config from one `mesh.yaml` |
| `common` | — | — | netlink, obfuscation types, shared route tagging |

This repository produces plain binaries and nothing else. Packaging each daemon into a Talos
system extension happens in a repository of its own —
[talos-awg-extension](https://github.com/slipmesh/talos-awg-extension),
[talos-router-extension](https://github.com/slipmesh/talos-router-extension),
[talos-nftables-extension](https://github.com/slipmesh/talos-nftables-extension) — which
cross-compile from here and publish one extension image each.

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
  handshake-tracked at 1Hz: while its handshake stays fresher than `handshake_stale_secs` (default
  180), a kernel route is installed for each CIDR; once it goes stale, the route is removed. This
  is a roaming client - the route's mere presence in the kernel *is* the "this client is currently
  connected" signal (`talosctl get routes`), with no status field anywhere.

One interface can freely mix both kinds of peer.

### Config

Read from a fixed path (`/etc/talos-extensions/awg.yaml` inside the container, matching
`extension-services/awg.yaml`'s `mountPath`) - never an environment variable or CLI flag. The whole
file is rendered into the node's machine config as an `ExtensionServiceConfig` document's
`configFiles[].content`. See `talos-awg-extension`'s `docs/extension-services.md` for the full
machine config example and every field.

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
      random_trailers: true            # 3.1: pad outgoing packets to a varying length
      disable_cookies: true            # 3.1: never send cookie replies
```

**Private keys always come from the config - this binary never generates or persists one.**
Whoever renders the machine config is responsible for giving a node its own per-interface key, or
placing the same key in every node's config when a single shared identity is needed (e.g. so a
roaming client sees one consistent server identity no matter which node it's currently connected
to). This is a config-authoring concern, not something `awg` decides. The same applies to
`header_protection_key`. `patches` (below) is one such config author.

**Every AmneziaWG obfuscation parameter is exposed**, through 3.1, not just the original nine
(jc/jmin/jmax/s1/s2/h1-h4) - confirmed field-by-field against the current kernel module's
`src/netlink.c` and amneziawg-tools' own config parser (`src/config.c`), since the kernel module's
own README only documents the original set. See `common::Obfuscation`'s doc comment for the full
field list and what each one does. `header_protection_key` + a peer's `advanced_security: true` are
a matched pair - the key alone does nothing without the flag, and both ends of a peering need the
same key.

The two 3.1 switches are the exception to that pairing: each end decides for itself.
`random_trailers` appends a random-length trailer to outgoing packets and relaxes the receive-side
length check to "at least", so a peer that doesn't set it still accepts the traffic.
`disable_cookies` suppresses cookie replies, whose own message type is a signature - at the cost
of the load-shedding they exist for.

Both are sent explicitly on every reconcile, set or not: an omitted attribute leaves the
kernel's current value alone. A module older than 3.1 rejects them - generic netlink validates against
the family's own attribute maximum and fails the whole request rather than ignoring what it
does not know - so a refused `SetDevice` is retried once without them, and the interface comes
up without the two switches instead of not at all.

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

A live handshake-polling *watcher* independent of route installation (i.e. something readable via
`talosctl` beyond "does a route exist") was deliberately deferred - if it's ever wanted, the hook
point is `handshake.rs`'s `dump_handshakes`, which already has the parsed per-peer handshake
timestamps.

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

---

## `router`: BIRD-based OSPF/iBGP routing, also driven by a static file

`router` reads one file (`/etc/talos-extensions/router.yaml`) at startup, renders BIRD's config
from it, and spawns `bird` as a supervised child process - staged into the same
`rootfs/usr/local/lib/containers/router/` directory as the `router` binary itself, rather than
running as a separate sidecar container: Talos extension services have no sidecar concept, a
service is always one `container.entrypoint`. It talks to BIRD over BIRD's own control socket
protocol directly, so no `birdc` binary is shipped.

There is no topology to discover, because there is nothing to discover it from. `router.yaml`
declares it all:

- `node.loopback_addresses` - this node's own IPv4+IPv6 loopback identity;
- `bgp_peers` - every other mesh node's name + IPv6 loopback (static by necessity);
- `ospf_interfaces` - exact interface names, shell-glob patterns like `"mesh-*"`, or CIDRs
  matching an interface's address - fed straight into BIRD's own `interface` clause, so nothing
  here needs to know what `awg` actually named its interfaces;
- `direct_interfaces` - interfaces whose own addresses should be announced (`protocol direct`);
- `learn` - IPv4 CIDR *ranges*, not exact per-peer `/32`s: any kernel route falling inside one is
  picked up and re-announced over iBGP, whoever installed it. This is how a node's pod subnet gets
  announced without naming the CNI's interface;
- `announce` - static routes to redistribute;
- `bypass` (optional) - RIPEstat/DNS-resolved blackhole routes, refreshed on an interval. This
  part stays "live", unlike everything else in this workspace, since resolving ASN/geoip/DNS
  sources is the whole point of the feature.

See `router/src/config.rs`'s doc comments for the full schema and `router/src/bird.rs` for how each
field becomes BIRD config.

Whoever authors `router.yaml` is responsible for `bypass.exclude` covering this node's own (and
every peer's) public endpoint - a blackholed endpoint takes the mesh link down with it. There is no
cluster-wide node list a static per-node file could consult, so this is the same
config-authoring-is-a-human-responsibility pattern documented above for `awg`'s private keys.
`patches` handles it for you when the topology comes from `mesh.yaml`.

---

## `nftables`: ruleset loader with a table-loss watchdog

Applies `/etc/talos-extensions/nftables.yaml`'s `ruleset:` once at startup, the same way
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
   survive. The table names live in whoever authors `ruleset:`, not in this binary; the cost of
   that is that renaming a table between two config versions orphans the old one rather than
   cleaning it up.

No rule content is baked into this binary at all - MSS clamping, NAT, or anything else is just
whatever `ruleset:` says. See `talos-nftables-extension`'s README for the packaging side (why `nft`
is a statically-linked binary built from source rather than the dynamically-linked package
`siderolabs/pkgs` already ships) and an example `ruleset:` value.

---

## `patches`: one topology file, every node's config

`slipmesh-patches` is the only crate here that doesn't run on a node. It reads a single
`mesh.yaml` describing the whole mesh - links, ports, obfuscation, BGP AS, road-warrior pools,
bypass lists, nftables ruleset - and writes `patches/<node>.yaml` for every node in it, each
holding the `awg`/`router`/`nftables` `ExtensionServiceConfig` documents that
`talosctl apply-config -p` then ships to that node.

Everything derivable is derived: interface names and link-local/loopback addressing fall out of
the topology rather than being written by hand. Keypairs aren't derivable, so they're generated
once and then read back out of the existing `patches/<node>.yaml` on every later run - a
regeneration never rotates a key it has already issued, and only the public half of a peer's key
ever appears in the other end's config. Each rendered config is validated through the real
daemon's own `validate()` - the daemons are depended on as libraries here, so there is no second
implementation to drift.

```sh
slipmesh-patches generate                      # every node, into ./patches
slipmesh-patches generate --node node-a --diff # one node, print what would change, write nothing
slipmesh-patches generate --check              # validate only
```

Two properties worth knowing before you point it at a directory:

- **It preserves what it doesn't own.** Only `awg`, `router` and `nftables` documents are
  regenerated (`segments.rs`); any other document in `patches/<node>.yaml` - a hand-written
  `machine.install.disk`, device credentials, anything - survives byte-for-byte. Editing a
  generated document by hand, on the other hand, is pointless: the next `generate` overwrites it.
- **It edits `mesh.yaml` in place for road warriors, comments intact.** `rw-add`/`rw-del` add or
  remove one client entry through a format-preserving YAML patch rather than a rewrite, so a
  hand-maintained topology file stays hand-readable:

```sh
slipmesh-patches rw-add --if plain --name laptop --allowed-ips 10.62.253.5/32 --export --qr
slipmesh-patches rw-inspect --if plain --name laptop --qr   # re-render, change nothing
slipmesh-patches rw-del --if plain --name laptop
```

`rw-add` generates the client's keypair and prints a ready-to-import config (optionally as a
terminal QR code), keeping only the public half. Client private keys are never persisted -
`rw-inspect` re-renders the rest and leaves a placeholder unless you pass the key back in.

The same generated `<node>.yaml` also drives [routeros](https://github.com/slipmesh/routeros),
which converges a MikroTik device into the mesh from it - a mesh member need not be a Talos node.

Install it with `cargo install --path patches`.

---

## Development

```sh
cargo test
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
```

No mocking framework - pure logic (`config::validate`, `interface::diff_peers`,
`rt::{to_remove,parse_cidr}`, all of `patches`' rendering) is unit-tested directly; netlink I/O is
a thin, not-unit-tested shim around it (see `common/src/netlink/`). Exercising `awg` end-to-end
needs a real Linux host with the `amneziawg` kernel module loaded and `CAP_NET_ADMIN` - see
`talos-awg-extension`'s `docs/extension-services.md` for a local smoke-test recipe.

Building a release artifact (cross-compiling a daemon and baking it into a Talos system extension)
happens in the packaging repositories, not here - this repo only needs to produce a plain binary:

```sh
cargo zigbuild --release --target x86_64-unknown-linux-musl -p awg
cargo zigbuild --release --target aarch64-unknown-linux-musl -p awg
```
