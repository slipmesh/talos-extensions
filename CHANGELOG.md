# Changelog

All notable changes to this project will be documented in this file.

This project adheres to [Keep a Changelog](https://keepachangelog.com/en/1.0.0/)
and follows [Semantic Versioning](https://semver.org/).

## [0.2.0] - 2026-09-07

### Added ✨

- Detect a dead mesh link with BFD instead of OSPF's dead timer
- Put BFD behind a mesh.yaml switch
- Let the mesh set the BFD intervals
- Run bird_exporter beside bird, on the node's own loopback

### Changed 🔧

- Build the generator without netlink, and name it taloscfg
- Cut markers by their node range, not by rules about text
- Ask the tree which marker terminates a directive
- Name a metrics port by whose it is, not by what serves it

### Documentation 📚

- Finish the rename in the manifests
- Say what the cut guarantees, not what it does not
- Say what the rename breaks, and put the BIRD metrics with the router

### Fixed 🐛

- Import parse_cidr where it is still called
- Import parse_cidr in the last place that took it from rt
- Validate mesh.yaml once, not twice
- Split patch files by the YAML grammar, not by a text scan
- Read existing keys eagerly, and strip only a real end marker
- Keep a file the grammar finds no document in
- Strip only a line that is a document marker
- Take the marker's span from the tree, and read the crate's contract
- Read the patch files of nodes, not of the directory
- Keep the marker that terminates a directive
- Keep BFD off the loopback, which has no neighbour to check
- Validate the metrics listener, and log through the daemon's own logger

### Miscellaneous 🧹

- Raise the workspace version to 0.2.0

### Tests ✅

- Drop the three that only exercised the parser
- Drop the one no mutation could kill
- Cover the read failing loudly, and stop reusing a dirty temp dir

## [0.1.6] - 2026-09-04

### Documentation 📚

- Name the BIRD the extension actually ships
- Say what the fixtures were captured on, and how 3.3.2 failed

## [0.1.5] - 2026-09-04

### Documentation 📚

- State what BIRD 3.3.2 changes for this daemon, which is nothing

## [0.1.4] - 2026-09-03

### Added ✨

- Read full peer stats and publish the reconcile verdict
- Render an awg metrics listener from cluster.metrics_port
- Serve per-peer metrics over HTTP
- Label peer metrics with the name from the config

### Fixed 🐛

- Refuse a wildcard or portless metrics address, connect once per scrape

## [0.1.3] - 2026-08-27

### Added ✨

- Expose AmneziaWG 3.1's random trailers and cookie suppression

### CI/CD ⚙️

- Check this workspace on its own, not only through the repositories that ship it

### Fixed 🐛

- Let a dropped 3.1 switch turn off, and survive an older module

### Miscellaneous 🧹

- Move markdownlint config to the cli2 file

## [0.1.2] - 2026-08-26

### Added ✨

- Router: learn kernel-proto routes, drop the implicit direct_interfaces defaults

### Documentation 📚

- Drop deployment-specific names from comments and metadata
- Describe the whole workspace, not just awg
- State the facts instead of pointing at an unpublished file
- State the facts, drop how they were found
- Keep the provenance, drop links to repositories that no longer exist
- Document each field where it is, not in one block above the struct

### Fixed 🐛

- Router: export every OSPF route source to the kernel, not just RTS_OSPF

### Miscellaneous 🧹

- Add the standard markdownlint and clippy config

### Reverts ⏪

- Router: export every OSPF route source to the kernel, not just RTS_OSPF

### Style 🎨

- Satisfy rustfmt and clippy as of Rust 1.98

## [0.1.1] - 2026-08-19

### Added ✨

- Patches: rw-add/rw-inspect: --invert for QR polarity

## [0.1.0] - 2026-08-19

### Added ✨

- Initial commit: awg daemon converging AmneziaWG interfaces from a static config
- Expose the full AmneziaWG 3.0 obfuscation/security parameter set
- Add router: BIRD-based OSPF/iBGP daemon, ported from operators/router
- Add nftables: ruleset loader with a table-loss watchdog
- Add patches: offline generator for awg/router/nftables machine-config patches
- Router: add generic direct_interfaces for exporting any connected route over iBGP
- Patches: wire mesh.yaml's cluster.direct_interfaces into router.yaml
- Patches: add plain: true for mesh links that can't speak AmneziaWG
- Patches: announce the k8s service CIDR over iBGP (cluster.service_subnet)
- Patches: give mesh-* tunnel interfaces real addresses via cluster.tunnel_networks
- Patches: add plain roadwarrior pools, derive iface name from pool name
- Patches: add rw-add/rw-del/rw-inspect for roadwarrior clients
- Patches: rw-add/rw-inspect: --endpoint override, --private-key for rw-inspect

### Changed 🔧

- Regroup Obfuscation fields by function, not by AmneziaWG version history
- Add lib targets to awg/router/nftables for cross-crate config reuse
- Router: bind-mount the Talos host's own CA store instead of vendoring one

### Fixed 🐛

- Fix H1-H4/PersistentKeepalive wire format bugs, drop in-process keep_addr_on_down write
- Awg: fix 3 code-review findings (peer sync isolation, route leak, validation)
- Router: fix 3 code-review findings (birdc timeout, bypass retry, watchdog cap)
- Awg: fix 2 more code-review findings (DNS timeout, advanced_security check)
- Router: reject bgp_as == 0 (RFC 7607 reserved AS)
- Router: make RIPEstat client construction fallible, not panic-on-init
- Router: embed a CA bundle instead of trusting the rootfs to have one
- Awg: always send explicit obfuscation values, never omit-to-preserve-stale
- Router: install ANNOUNCE routes into the local kernel table, not just export them
- Rename patches binary to slipmesh-patches
- Awg: run GC before converging interfaces, not after

### Miscellaneous 🧹

- Add dual MIT/Apache-2.0 license files
- Add cliff.toml for changelog generation
