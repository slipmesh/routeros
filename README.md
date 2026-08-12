# routeros

One-shot CLI tool that converges a MikroTik RouterOS device into the mesh's desired state:
WireGuard tunnels plus OSPF/iBGP dynamic routing, computed from a
[`talos-extensions/patches`](../talos-extensions)-generated patch file (`<node>.yaml`) - the same
per-node config Talos mounts onto real Talos nodes for the `awg`/`router` daemons, even though the
RouterOS device itself isn't a Talos node.

It applies that state over RouterOS's native binary API
([`mikrotik-rs`](https://github.com/ferrohd/mikrotik-rs)), never SSH/ansible. It is **not** a
Kubernetes client and has no dependency on Kubernetes anywhere: it runs like `ansible-playbook` -
invoke it manually, from cron, or a systemd timer - reads one file, connects to the router once,
converges, and exits.

## Usage

```sh
routeros --node=hq --patches-dir=/path/to/IaC/talos/patches [--check] [--diff]
```

- `--node` + `--patches-dir` - together resolve to `<patches-dir>/<node>.yaml`; missing or
  malformed is a fatal error.
- `--check` - compute the diff but don't apply it to the device.
- `--diff` - print the computed add/update/remove plan to stdout (works with or without `--check`).

Requires:

- The patch file to contain three `ExtensionServiceConfig` documents: `awg`, `router` (both
  produced by `talos-extensions/patches generate` from `mesh.yaml`), and `mikrotik` (hand-authored
  separately - RouterOS API credentials, preserved untouched across regeneration since it isn't one
  of `patches`'s own owned document names). See [`AGENTS.md`](./AGENTS.md) for the exact format.
- Network access to the router's RouterOS API-SSL port (8729), with a TLS certificate the host's
  own trust store already validates.

See [`AGENTS.md`](./AGENTS.md) for the full architecture and design decisions.

## License

AGPL-3.0-only - see [`LICENSE`](./LICENSE). This follows from depending on `mikrotik-rs`, whose
entire workspace is AGPL-3.0-only; see `AGENTS.md`/`Cargo.toml` for details.

## Development

```sh
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test
```
