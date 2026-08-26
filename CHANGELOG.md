# Changelog

All notable changes to this project will be documented in this file.

This project adheres to [Keep a Changelog](https://keepachangelog.com/en/1.0.0/)
and follows [Semantic Versioning](https://semver.org/).

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
