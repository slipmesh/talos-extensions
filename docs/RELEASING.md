# Releasing

## Lines and versions

A release is named after the Talos line it is cut for: the Talos patch current when it comes out,
plus a revision, such as `v1.14.5+sm.1`. The daemons run in userspace and depend on no Talos
patch, so a new Talos patch needs no release here; the patch in the name only records when the
release came out. The revision starts at 1 for every Talos patch and counts releases against it.
The image carries the same tag with `+` as `-`, since OCI tags cannot hold a `+`. Releases up to
`v0.4.0` were plain semver from `main`.

Stable releases come only from `release-1.X` branches, one per Talos minor; `main` follows the next
minor. A change that breaks a daemon's behaviour or the `slipmesh.yaml` that `slipmesh-taloscfg`
reads lands only on `main`, with the next minor. Any other change lands on `main` first and is
cherry-picked to the release branches it applies to (`git cherry-pick -x`, then a pull request
into `release-1.X`). A line is supported while upstream ships patches for it.

| Talos line | branch | status |
| --- | --- | --- |
| 1.14 | `release-1.14` | supported |

## Cutting a release

1. Run Actions, then Release PR, on the release branch with the version, such as `v1.14.5+sm.1`.
   Without one it computes a semver bump, which names no Talos patch.
2. The pull request it opens moves `[workspace.package] version` to the same number without the
   `v` and regenerates `CHANGELOG.md`. A bot opened it, so its checks wait for Approve workflows
   to run; the merge does not need them. Merge it.
3. Only this push builds, once fmt, clippy, the tests and `cargo audit` of that push pass: the
   binaries for both arches and the daemons image, pushed as `talos-extensions:sha-<commit>`. Once
   the build succeeds, the commit is tagged, that image is retagged as
   `talos-extensions:<version>` by digest, and the GitHub Release gets the binaries with a
   `SHA256SUMS`, not marked latest, and marked pre-release for an alpha or beta. A failed build
   leaves no tag, so the same version can be released again after the fix.

Every other pull request and push runs the checks and builds nothing.

A release that changes a daemon reaches nodes once talos-installer's branch for the same line pins
its image. A release that changes only `slipmesh-taloscfg` needs no such pin.

## Branching a new line

Before the first release for a new Talos minor, branch `release-1.X` from `main` and add it to the
table above.
