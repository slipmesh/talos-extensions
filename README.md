# talos-extensions

The Rust workspace behind the slipmesh Talos system extensions: three daemons that bring up a
node's mesh networking with no Kubernetes API involved, plus the offline generator that writes
their config.

| crate | binary | runs | what it does |
| --- | --- | --- | --- |
| `awg` | `awg` | on the node, as `ext-awg` | brings up AmneziaWG interfaces and peers over netlink |
| `router` | `router` | on the node, as `ext-router` | renders BIRD config (OSPFv3 + iBGP), supervises `bird` |
| `nftables` | `nftables` | on the node, as `ext-nftables` | applies an nftables ruleset and keeps it applied |
| `taloscfg` | `slipmesh-taloscfg` | on your workstation | renders every node's patch from one `slipmesh.yaml` |
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
  connected" signal, with no status field anywhere. `slipmesh_awg_peer_connected` (below) reports
  that same verdict without reading the FIB by hand.

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
metrics:
  listen: "10.62.0.4:9586"             # omit the whole section to serve nothing
```

**Private keys always come from the config - this binary never generates or persists one.**
Whoever renders the machine config is responsible for giving a node its own per-interface key, or
placing the same key in every node's config when a single shared identity is needed (e.g. so a
roaming client sees one consistent server identity no matter which node it's currently connected
to). This is a config-authoring concern, not something `awg` decides. The same applies to
`header_protection_key`. `taloscfg` (below) is one such config author.

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

### Metrics

With a `metrics` section in the config, `awg` serves `GET /metrics` on that address; without one it
opens nothing, because a node not set up for scraping should not open a port on a default. `taloscfg`
(below) renders the section from `cluster.awg_metrics_port`, binding it to the node's own v4 mesh
loopback - the address kubelet reports as `InternalIP`, so Prometheus reaches it through node
discovery plus a port relabel, exactly the way node-exporter is reached. That address belongs to
`ext-router`, and Talos does not order extension startup, so the socket is bound with `IP_FREEBIND`
and starts answering once the address appears; until then the scrape fails, which is the honest
reading rather than a fault to paper over.

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
`taloscfg` handles it for you when the topology comes from `slipmesh.yaml`.

---

### BIRD metrics

`cluster.router_metrics_port` makes `ext-router` run [`bird_exporter`] beside BIRD, reading the
same control socket for protocol state - session up/down, uptime, prefix counts, BFD sessions.
The address is derived the same way `awg`'s is, from the node's own v4 loopback, so the two
cannot drift; unset means no node runs it. It needs no `IP_FREEBIND` counterpart, because
`ext-router` brings that address up itself before it starts either child.

Unlike `bird` exiting, the exporter exiting is not fatal: it is restarted in place, since a
failed scrape is not a reason to restart the container and tear down every adjacency.

[`bird_exporter`]: https://github.com/czerwonk/bird_exporter

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

## `taloscfg`: one file, every node's patch

`slipmesh-taloscfg` is the only crate here that doesn't run on a node. It reads `slipmesh.yaml`,
which describes the whole mesh and everything else a node's patch file carries, and writes
`patches/<node>.yaml` for every node in it, each holding that node's Talos documents followed by the
`awg`/`router`/`nftables` `ExtensionServiceConfig` documents that `talosctl apply-config -p` then
ships to that node. A patch file is output only: nothing in it is read back, so edit
`slipmesh.yaml` and regenerate rather than editing the patch.

### `slipmesh.yaml`

A multi-document YAML file. Every document opens with a `slipmesh:` block saying what it is; the
block is addressed to this tool and never reaches a patch file.

```yaml
slipmesh:
  kind: network
cluster:
  bgp_as: 64512
  loopback_networks: {ipv4: "10.62.0.0/24", ipv6: "fd00:62::/120"}
nodes:
  - {name: node-a, node_id: "10.62.0.1", endpoint: "192.0.2.1"}
  - {name: node-b, node_id: "10.62.0.2", endpoint: "192.0.2.2"}
  - {name: router-1, node_id: "10.62.0.3", endpoint: "192.0.2.3"}
mesh:
  links:
    - {pair: [node-a, node-b], port: 52801}
    - {pair: [router-1, node-a], port: 52891, plain: true}
---
slipmesh:
  kind: roadwarriors
name: plain
node_hostnames: [node-a]
address: "198.51.100.1/24"
listen_port: 51820
plain: true
clients: []
---
slipmesh:
  kind: nftables
  exclude: [router-1]
ruleset: |
  table inet talos_filter { ... }
---
slipmesh:
  kind: patch
  include: [node-b]
apiVersion: v1alpha1
kind: UnattendedInstallConfig
installer:
    disk: /dev/nvme0n1
```

| kind | how many | aimed by | holds |
| --- | --- | --- | --- |
| `network` | exactly one | — | the topology: `cluster`, `bfd`, `obfuscation`, `nodes`, `mesh`, `bypass` |
| `roadwarriors` | one per pool | — | one pool: its address, port, nodes and clients |
| `nftables` | any | `include`/`exclude` | a `ruleset` |
| `patch` | any | `include`/`exclude` | a Talos document, carried into the patch of every node it reaches |

`include` lists the nodes a document reaches; leave it out to reach every node. `exclude` takes
nodes back out. Both name nodes of the `network` document, and a key the `slipmesh:` block does
not know is an error, so a misspelled `include` cannot quietly aim a document at every node. A node
reached by no `nftables` document gets no nftables document at all; one reached by two is an error,
since a ruleset is one text and two cannot be merged.

`patch` documents of one Talos identity - `apiVersion`, `kind`, `name` - are merged for each node:
those without `include` first, then those naming the node, each in file order, so the specific one
wins wherever it sits. Mappings merge key by key, an explicit `null` deletes a key, and a sequence
replaces the one before it whole. That last part differs from Talos' own strategic merge, which
appends to a list: appending by key needs the types Talos has and this tool does not, and appending
without a key would leave no way to remove an element. A document that comes from one source goes
into the patch file as written; a merged one is re-serialized, which loses its comments, and
`generate` names it when that happens.

A file a `patch` document carries in `configFiles[].content` may be written as YAML - a mapping or
a list - rather than as a string. Talos takes only a string there, so the patch file gets that
YAML's text; comments inside it do not carry over. Written this way, each field of the file is a
field of `slipmesh.yaml`, which is what lets a password be encrypted without the host beside it:

```yaml
slipmesh:
  kind: patch
  include: [router-1]
apiVersion: v1alpha1
kind: ExtensionServiceConfig
name: mikrotik
configFiles:
  - mountPath: /etc/talos-extensions/mikrotik.yaml
    content:
      host: router1.example.com
      port: 8729
      username: admin
      password: hunter2
```

### Secrets

Everything derivable is derived: interface names and link-local/loopback addressing fall out of
the topology rather than being written by hand, and only the public half of a peer's key ever
appears in the other end's config. Keys aren't derivable, so the tool generates them once and
writes them into `slipmesh.yaml` itself, into the fields an operator would otherwise fill in by
hand: `nodes[].mesh_private_key`, a pool document's `private_key`, and whichever `obfuscation`
fields a link or pool leaves unset.

Written, a value is the operator's like any other. A regeneration never rotates a key that is
written down; deleting one does, for that node, link or pool and every peer of it. Only what the
tool generated is written: a field set on the entry or in the global `obfuscation` is never copied
down, and neither are `random_trailers` and `disable_cookies`, which are never generated. Taking a
node out of the `network` document takes its key with it, so putting it back mints a new one.

What the tool adds goes in as block entries laid out the way sops lays out YAML - nested four
columns deeper, a mapping in a list two columns past the dash - so that encrypting the file moves
nothing the tool wrote. An entry written in flow style, `{...}`, takes an addition in flow style.

Each rendered config is validated through the real daemon's own `validate()` - the daemons are
depended on as libraries here, so there is no second implementation to drift.

```sh
slipmesh-taloscfg generate                      # every node, into ./patches
slipmesh-taloscfg generate --node node-a --diff # one node, print what would change, write nothing
slipmesh-taloscfg generate --check              # validate only
```

Every run mints for the whole topology, whichever nodes it renders, and renders and validates every
node before it writes any patch file. `--check` and `--diff` never write: when a secret would have
to be minted they stop and name it, because a key minted and not kept would differ on the next run.

### Encrypting `slipmesh.yaml`

The tool reads and writes plain YAML and knows nothing of encryption. To keep the secrets in
`slipmesh.yaml` out of the clear, have sops encrypt just those fields; everything else stays
readable, and so do diffs:

```yaml
# .sops.yaml
creation_rules:
  - path_regex: (^|/)slipmesh\.yaml$
    encrypted_regex: ^(mesh_private_key|private_key|obfuscation|password)$
    mac_only_encrypted: true
    age: age1...
```

`mac_only_encrypted` lets the unencrypted part be edited in any editor: changing a value, adding a
node. Removing or reordering anything that holds an encrypted value goes through `sops edit`, since
sops checks those against its MAC. A field the regex matches is written through sops or by the
tool, never typed in by hand - plaintext in it fails decryption. A secret under a name the regex
does not list stays in the clear, so a new one needs adding to it.

The tool then runs through sops. Reading, sops decrypts to a temporary file and passes its path;
writing, sops runs the tool in place of an editor, with the temporary file's path appended, and
encrypts the result back only if it changed:

```sh
sops exec-file --no-fifo slipmesh.yaml 'slipmesh-taloscfg generate --diff --config {}'
EDITOR='slipmesh-taloscfg generate --config' sops edit slipmesh.yaml
EDITOR='slipmesh-taloscfg rw-add --if plain --name laptop --allowed-ips 10.62.253.5/32 --export --config' \
  sops edit slipmesh.yaml
```

`sops edit` exits with 200 when nothing changed, and writes nothing back when the tool fails.
`--no-fifo` is for systems without named pipes, Windows among them. sops writes the whole file in
its own layout, so the first encryption reformats it once; after that, a change shows in the file
as the lines of that change and sops' `mac`.

For diffs in the clear, mark the file for a diff driver in `.gitattributes`
(`slipmesh.yaml diff=sops`) and name the driver per command -
`git -c diff.sops.textconv="sops decrypt" diff`. Configuring it for good would also show the
decrypted text to gitleaks, which reads history through `git log -p` and reports every key in it.

### Road warriors

`rw-add`/`rw-del` add or remove one client in the pool's own document through a format-preserving
YAML patch rather than a rewrite, so the rest of `slipmesh.yaml` stays exactly as written:

```sh
slipmesh-taloscfg rw-add --if plain --name laptop --allowed-ips 10.62.253.5/32 --export --qr
slipmesh-taloscfg rw-inspect --if plain --name laptop --qr   # re-render, change nothing
slipmesh-taloscfg rw-del --if plain --name laptop
```

`rw-add` generates the client's keypair and prints a ready-to-import config (optionally as a
terminal QR code), keeping only the public half. Client private keys are never persisted -
`rw-inspect` re-renders the rest and leaves a placeholder unless you pass the key back in. The
pool's own key, which the config is built with, is written into the pool's document, so `generate`
puts the same key on the wire; `rw-inspect` writes nothing and asks for `generate` first when that
key is not written down yet.

The same generated `<node>.yaml` also drives [routeros](https://github.com/slipmesh/routeros),
which converges a MikroTik device into the mesh from it - a mesh member need not be a Talos node.

### Migrating from `mesh.yaml`

Before `slipmesh.yaml`, the topology lived in `mesh.yaml`, and the keys and hand-written documents
lived inside the patch files. `slipmesh-migrate` moves both, once:

```sh
slipmesh-migrate --mesh mesh.yaml --patches-dir patches --out slipmesh.yaml
slipmesh-taloscfg generate --diff
```

It writes the new file and nothing else, and refuses to overwrite it. Each hand-written document
in a patch file becomes a `patch` document for that node, the keys and obfuscation the patch files
carry are written into the fields of `slipmesh.yaml` they belong to, and the ruleset reaches every
node as it did. It changes no behaviour, so
the diff after it shows only the header `generate` now writes at the top of each patch file. A
warning that something was minted means a key was in neither `mesh.yaml` nor the patch files - for
a node that already had one, that is a new identity. Until `generate` has run, the patch files hold
the only copy of anything the migration missed, so keep them until then.

### Breaking changes

The top of the `network` document, its `cluster:` block and every pool refuse a field they do not
know, so a name that changed fails where it is written rather than being ignored into a listener
that silently stops being rendered:

```text
the `kind: network` document at line 1: cluster: unknown field `metrics_port`, expected one of
`bgp_as`, `loopback_networks`, `bypass_refresh_interval_secs`, `awg_metrics_port`, ... at line 6
column 3
```

Renamed so far, each needing the same edit in `slipmesh.yaml` and nothing else:

| was | is | since |
| --- | --- | --- |
| `cluster.metrics_port` | `cluster.awg_metrics_port` | v0.2.0 |

No aliases are kept. This is a 0.x generator versioned with the file it reads, and a name that
means one thing in the tool and another in the file is worse than a build that stops.

Install both binaries with `cargo install --path taloscfg`.

---

## Development

```sh
cargo test
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
```

No mocking framework - pure logic (`config::validate`, `interface::diff_peers`,
`rt::to_remove`, `cidr::parse_cidr`, all of `taloscfg`'s rendering) is unit-tested directly;
netlink I/O is a thin, not-unit-tested shim around it (see `common/src/netlink/`). Exercising `awg` end-to-end
needs a real Linux host with the `amneziawg` kernel module loaded and `CAP_NET_ADMIN` - see
`talos-awg-extension`'s `docs/extension-services.md` for a local smoke-test recipe.

### Releasing

`[workspace.package] version` and the tag are the same number, and the release commit moves both:
every crate here inherits that one version, and it is what an installed `slipmesh-taloscfg`
reports for itself. Bumping only the tag leaves a binary that misnames its own version, which is
how it read `0.1.0` at tag `v0.1.6`.

Building a release artifact (cross-compiling a daemon and baking it into a Talos system extension)
happens in the packaging repositories, not here - this repo only needs to produce a plain binary:

```sh
cargo zigbuild --release --target x86_64-unknown-linux-musl -p awg
cargo zigbuild --release --target aarch64-unknown-linux-musl -p awg
```
