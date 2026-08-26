# routeros

One-shot CLI tool that converges a MikroTik RouterOS device into the mesh's desired state:
WireGuard tunnels plus OSPF/iBGP dynamic routing, computed from a
[`talos-extensions/patches`](https://github.com/slipmesh/talos-extensions)-generated patch file (`<node>.yaml`) - the same
per-node config Talos mounts onto real Talos nodes for the `awg`/`router` daemons, even though the
RouterOS device itself isn't a Talos node.

It applies that state over RouterOS's native binary API
([`mikrotik-rs`](https://github.com/ferrohd/mikrotik-rs)), never SSH/ansible. It is **not** a
Kubernetes client and has no dependency on Kubernetes anywhere: it runs like `ansible-playbook` -
invoke it manually, from cron, or a systemd timer - reads one file, connects to the router once,
converges, and exits.

## Usage

```sh
slipmesh-routeros --node=router1 --patches-dir=./patches [--check] [--diff]
```

- `--node` + `--patches-dir` - together resolve to `<patches-dir>/<node>.yaml`; missing or
  malformed is a fatal error.
- `--check` - compute the diff but don't apply it to the device.
- `--diff` - print the computed add/update/remove plan to stdout (works with or without `--check`).

Requires:

- The patch file to contain three `ExtensionServiceConfig` documents: `awg` and `router` (both
  produced by `patches generate` from `mesh.yaml`) plus `mikrotik` - the device's API
  credentials, which you write by hand. `patches` doesn't own that document name, so it survives
  every regeneration byte-for-byte:

  ```yaml
  ---
  apiVersion: v1alpha1
  kind: ExtensionServiceConfig
  name: mikrotik
  configFiles:
    - mountPath: /etc/talos-extensions/mikrotik.yaml
      content: |
        host: router1.example.com
        port: 8729
        username: automation
        password: ...
  ```

  Any of the three being absent or malformed is a fatal error before the device is touched.
- Network access to the device's RouterOS API-SSL port (8729), with a TLS certificate the host's
  own trust store already validates.

## What it converges

WireGuard interfaces and their peers, a loopback bridge and its IPv4/IPv6 addresses,
interface-list membership, the OSPFv3 instance/area/interface-templates, the `bgp-networks`
firewall address-list, and the iBGP connections - thirteen tables in a fixed, dependency-correct
order (`converge.rs`'s module doc comment is the authoritative list). Each is read live from the
device and diffed against the desired state before anything is written.

Tables this tool owns exclusively (`interface wireguard[/peers]`, `routing ospf
interface-template`, `routing bgp connection`) are converged remove-before-add, so a rename or a
moved listen port can't collide with the row it replaces. Tables shared with whatever else the
device is doing are only ever touched row by row.

`--check` gives you the whole plan without writing, and `--diff` prints it either way.

## License

AGPL-3.0-only - see [`LICENSE`](./LICENSE). This follows from depending on
[`mikrotik-rs`](https://github.com/ferrohd/mikrotik-rs), whose entire workspace is AGPL-3.0-only.
It is the only repository in this organization that isn't MIT/Apache-2.0.

## Development

```sh
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test
```
