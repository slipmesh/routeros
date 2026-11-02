# Releasing

## Lines and versions

This tool converges a RouterOS device to the same per-node config the daemons of talos-extensions
read, through their own config types, so it follows talos-extensions' release lines. A release is
named after the Talos line it is cut for: the Talos patch current when it comes out, plus a
revision, such as `v1.14.5+sm.1`. Nothing here depends on a Talos patch, so a new Talos patch needs
no release here; the patch in the name only records when the release came out. The revision starts
at 1 for every Talos patch and counts releases against it. Releases up to `v0.2.4` were plain
semver from `main`.

Each branch takes `awg` and `router` from a talos-extensions release of its own line, by tag in
`Cargo.toml`. Renovate moves that tag within the branch's line, to a later Talos patch or `+sm.N`,
together with `Cargo.lock`, and never to another line: `main` moves to the next line by hand
(`cargo update -p awg -p router`), as a pull request like any other.

Stable releases come only from `release-1.X` branches, one per Talos minor; `main` follows the next
minor. A change that breaks how a `slipmesh.yaml` is applied to a device lands only on `main`, with
the next minor. Any other change lands on `main` first and is cherry-picked to the release branches
it applies to (`git cherry-pick -x`, then a pull request into `release-1.X`). Renovate's patch
updates are the exception: it opens them against each branch on its own. A line is supported
while upstream ships patches for it.

| Talos line | branch | status |
| --- | --- | --- |
| 1.14 | `release-1.14` | supported |

## Cutting a release

1. Run Actions, then Release PR, on the release branch with the version, such as `v1.14.5+sm.1`.
   It is required: a bump computed from the commits would move the Talos patch, not the revision.
2. The pull request it opens moves `Cargo.toml`'s `version` to the same number without the `v` and
   regenerates `CHANGELOG.md`. The push of the merge runs the checks again, so it does not wait on
   this pull request's. Merge it.
3. Only this push builds, once fmt, clippy, the tests and `cargo audit` of that push pass:
   `slipmesh-routeros-linux-{amd64,arm64}`. Once the build succeeds, the commit is tagged and the
   GitHub Release gets the binaries with a `SHA256SUMS`, marked latest when it is the newest stable
   release, and pre-release for an alpha or beta. A failed build leaves no tag, so the same version
   can be released again after the fix.
   If a later step fails, Re-run failed jobs finishes the release while the run's artifacts last,
   14 days; a push whose release commit is already tagged builds nothing.

Every other pull request and push runs the checks and builds nothing.

## Branching a new line

Before the first release for a new Talos minor, branch `release-1.X` from `main` and add it to the
table above.

Before the first release from `main` after that, tag the branch point as the next minor's `alpha.0`,
for `release-1.15`:

```sh
git tag -a v1.16.0-alpha.0 -m v1.16.0-alpha.0 <branch point>
git push origin v1.16.0-alpha.0
```

The `release-1.X` tags are not reachable from `main`, so without it git-cliff would list everything
that line released again in `main`'s next section. Until `main` releases, nothing reads it. The tag
releases nothing: CI runs on branch pushes, not tags.

## Withdrawing a broken release

A published release stays: a deleted tag would be reused by the next run of the same version.

1. Put a warning at the top of its GitHub Release notes naming the release that replaces it.
2. Fix forward: the fix lands like any other change and is released as the next `+sm.N`.
3. A replacement that `sort -V` ranks below the broken release, such as a return to an older Talos
   patch, does not become latest by itself. Mark it latest with `gh release edit <tag> --latest`.
