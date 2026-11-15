# routeros

One-shot CLI tool that converges a MikroTik RouterOS device into the mesh's desired state:
WireGuard tunnels plus OSPF/iBGP dynamic routing, computed from the device's node in
`slipmesh.yaml` by [`sliplib-mesh`](https://github.com/slipmesh/sliplib) - the same `awg` and
`router` configs every platform's tool computes for its nodes.

It applies that state over RouterOS's native binary API
([`mikrotik-rs`](https://github.com/ferrohd/mikrotik-rs)), never SSH/ansible. It is **not** a
Kubernetes client and has no dependency on Kubernetes anywhere: it runs like `ansible-playbook` -
invoke it manually, from cron, or a systemd timer - reads one file, connects to the router once,
converges, and exits.

## Usage

```sh
slipmesh-routeros --node=router1 [--check] [--diff] [--config slipmesh.yaml]
```

- `--node` - the device's node in `slipmesh.yaml`.
- `--config` - `slipmesh.yaml` as plain text, `slipmesh.yaml` in the current directory by default.
  The tool knows nothing of encryption: a SOPS-encrypted file is decrypted by a wrapper that passes
  the plaintext path:

  ```sh
  sops exec-file slipmesh.yaml 'slipmesh-routeros --node router1 --check --config {}'
  ```

- `--check` - compute the diff but don't apply it to the device.
- `--diff` - print the computed add/update/remove plan to stdout (works with or without `--check`).

Requires:

- `slipmesh.yaml` with the node and every secret its configs need: the mesh private keys of the
  node and its peers, the obfuscation of each of its links that is not `plain`, and the private key
  of each roadwarriors pool on it, with its obfuscation unless the pool is `plain`. A file that is
  missing, malformed or lacks one of them is a fatal error before the device is touched;
  `slipmesh-taloscfg generate` writes the secrets a file lacks. This tool checks only what its own
  node's configs need: a file the Talos generator refuses for a Talos-only reason - a template, a
  patch document, an annotation - is still accepted here.
- The device's API credentials in the environment:

  | variable | |
  | --- | --- |
  | `SLIPMESH_ROUTEROS_HOST` | required |
  | `SLIPMESH_ROUTEROS_PORT` | optional, `8729` (API-SSL) when unset |
  | `SLIPMESH_ROUTEROS_USERNAME` | required |
  | `SLIPMESH_ROUTEROS_PASSWORD` | optional; unset logs in without one, set and empty with an empty one |

  An unset or empty host or username, or a port that is not a port number, is a fatal error
  before the device is touched. They are never command-line flags, so they do not show up in a
  process listing.
- Network access to the device's RouterOS API-SSL port (8729), with a TLS certificate the host's
  own trust store already validates.

## Upgrading from the patch file

- `--patches-dir` is gone: pass `--config` with the path of `slipmesh.yaml` instead.
- The tool now reads the whole decrypted `slipmesh.yaml`, which holds every node's and every
  pool's private key; the patch file held only this router's key and its peers' public keys.
  Keep the plaintext where the encrypted file is kept, or let the wrapper above decrypt it for one
  run.
- The file must already hold the secrets: run `slipmesh-taloscfg generate` once first, so that
  every key and obfuscation is written into it.

## What it converges

WireGuard interfaces and their peers, a loopback bridge and its IPv4/IPv6 addresses,
interface-list membership, the OSPFv3 instance/area/interface-templates, the BFD
configuration behind them, the `bgp-networks` firewall address-list, and the iBGP connections -
fourteen tables in a fixed, dependency-correct
order (`converge.rs`'s module doc comment is the authoritative list). Each is read live from the
device and diffed against the desired state before anything is written.

Tables this tool owns exclusively (`interface wireguard[/peers]`, `routing bfd configuration`,
`routing ospf interface-template`, `routing bgp connection`) are converged remove-before-add, so a rename or a
moved listen port can't collide with the row it replaces. Tables shared with whatever else the
device is doing are only ever touched row by row.

`--check` gives you the whole plan without writing, and `--diff` prints it either way.

## License

AGPL-3.0-only - see [`LICENSE`](./LICENSE). This follows from depending on
[`mikrotik-rs`](https://github.com/ferrohd/mikrotik-rs), whose entire workspace is AGPL-3.0-only.
It is the only repository in this organization that isn't MIT/Apache-2.0.

Each release carries the licenses and notices of what is linked into the binary:
`THIRD-PARTY-NOTICES` for the crates, rendered by [cargo-about](https://embarkstudios.github.io/cargo-about/)
from [`about.toml`](about.toml) and [`about.hbs`](about.hbs), and `COPYRIGHT-rust-std.html` and
`COPYRIGHT-musl` for the Rust standard library and the musl libc. The `licenses` check holds every
dependency to the licenses and sources [`deny.toml`](deny.toml) allows, and renders the notices on
every pull request.

## Development

The code follows [docs/CODESTYLE.md](docs/CODESTYLE.md).

```sh
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test
cargo deny --locked check licenses bans sources
```

`Cargo.toml`'s `version` and the release tag are the same number, and the release commit moves both:
it is what an installed `slipmesh-routeros` reports for itself, and bumping only the tag leaves a
binary that misnames its own version - which is how it read `0.1.0` at tag `v0.1.2`. The Release PR
workflow (Actions, then Release PR) opens that commit as a PR with `CHANGELOG.md` regenerated.
Merging it releases it: that push alone builds `slipmesh-routeros-linux-{amd64,arm64}`, tags the
commit once the build succeeds, and attaches them with a `SHA256SUMS` to the GitHub Release. Every
other push and pull request runs only the checks, and `cargo audit` also runs weekly. The release
build waits for every check of its own push, `cargo audit` included; an advisory with no fix yet is
ignored in a `.cargo/audit.toml`, with the reason next to it - there is none today. Release lines,
versions and the steps are in [docs/RELEASING.md](docs/RELEASING.md).
