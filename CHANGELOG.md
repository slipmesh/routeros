# Changelog

All notable changes to this project will be documented in this file.

This project adheres to [Keep a Changelog](https://keepachangelog.com/en/1.0.0/)
and follows [Semantic Versioning](https://semver.org/).

## [0.1.1] - 2026-08-26

### Documentation 📚

- Make the usage documentation work outside its home cluster
- State the facts instead of pointing at an unpublished file
- State the facts, drop how they were found

### Fixed 🐛

- Rename binary to slipmesh-routeros
- Link-local on the loopback bridge, and compare WireGuard keys clamped

### Miscellaneous 🧹

- Record the one gitleaks false positive
- Exclude build/ from markdownlint too
- Repoint the gitleaks fingerprint at the rewritten commit

## [0.1.0] - 2026-08-18

### Added ✨

- Parse router credentials and validate CRD-sourced strings
- Pure diff computation for all 8 RouterOS tables
- Compute desired RouterOS state from CRD state
- Loopback/link allocation and finalizer protocol
- Thin RouterOS device shim for all 12 tables
- Orchestrate the 13-step RouterOS convergence order
- Wire the one-shot pipeline together (cli/run/main)

### CI/CD ⚙️

- Add release CI, cross-compiled binaries attached to GitHub Releases

### Changed 🔧

- Migrate to NodeConfig/ClusterConfig, OSPFv3/RFC 8950 underlay
- Read desired state from a talos-extensions patch file, not Kubernetes

### Fixed 🐛

- Parse persistent-keepalive's time-unit suffix
- Show full row content on --diff removals, not a bare id
- Two real bugs found via live-device diff on real hardware
- Presence-style RouterOS flags need contains_key, not get()
- Apply mesh IPv4/link-local addresses, redistribute connected into OSPF, remove-before-add ordering
- Stop excluding mesh-* interfaces from the BGP announce candidate set
- Replace real node names in test/doc examples with placeholders

### Miscellaneous 🧹

- Scaffold repository
- Bump slipmesh-core pin, follow router_types rename
