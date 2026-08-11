# routeros

One-shot CLI tool that converges a MikroTik RouterOS device into the [slipmesh](https://github.com/slipmesh)
mesh's desired state: WireGuard mesh tunnels plus OSPF/iBGP dynamic routing, computed from the same
`slipmesh.net` Kubernetes CRDs the [`slipmesh-operators`](https://github.com/ffaxl/slipmesh-operators)
`mesh`/`router` operators use for Linux nodes.

RouterOS is treated as a full mesh/router node (uniqueness checks, finalizers - the same lifecycle
a Linux node's operator pod goes through), just applied by this tool over RouterOS's
native binary API ([`mikrotik-rs`](https://github.com/ferrohd/mikrotik-rs)) instead of a live
in-cluster reconcile loop. It is **not** a Kubernetes operator: it runs like `ansible-playbook` -
invoke it manually, from cron, or a systemd timer - reads what it needs from the cluster once,
connects to the router once, converges, and exits.

## Usage

```sh
routeros --node=hq [--check] [--diff]
```

- `--node` - name of the `NodeConfig` identifying this physical router. It must already exist (a
  human/GitOps creates it ahead of time); missing it is a fatal error.
- `--check` - compute the diff but don't apply it to the device.
- `--diff` - print the computed add/update/remove plan to stdout (works with or without `--check`).

Requires:

- A standard kubeconfig (`KUBECONFIG`/`~/.kube/config`) with read/write access to `slipmesh.net`
  CRDs in the `slipmesh` namespace - the same resolution `kubectl` uses.
- Network access to the router's RouterOS API-SSL port (8729), with a TLS certificate the host's
  own trust store already validates, and credentials in a `Secret` labeled
  `slipmesh.net/node=<--node>` in the `slipmesh` namespace (fields: `host`, `port`, `username`,
  `password`, `tls`).

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
