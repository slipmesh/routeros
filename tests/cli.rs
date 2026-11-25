//! The binary as a caller sees it: its exit status and what it logs.

use std::path::Path;
use std::process::Command;

#[test]
fn a_failed_run_exits_nonzero_and_logs_the_whole_error_chain() {
    let config = Path::new(env!("CARGO_TARGET_TMPDIR"))
        .join("no-such-dir")
        .join("slipmesh.yaml");
    let output = Command::new(env!("CARGO_BIN_EXE_slipmesh-routeros"))
        .args(["--node", "node-a", "--in"])
        .arg(&config)
        .env_remove("RUST_LOG")
        .output()
        .unwrap();

    assert!(!output.status.success(), "{:?}", output.status);
    let log = String::from_utf8(output.stdout).unwrap();
    assert!(log.contains("routeros failed"), "{log}");
    assert_eq!(
        log.matches("failed to read the node's configs").count(),
        1,
        "{log}"
    );
    assert_eq!(log.matches(&*config.to_string_lossy()).count(), 1, "{log}");
    assert!(log.contains("No such file or directory"), "{log}");
}

/// A file of format version 2 in which `router1`, of `routeros`, dials `node-a`, of `talos`. Every
/// key is generated here.
fn network() -> String {
    let key = || {
        sliplib_secrets::wireguard::PrivateKey::generate()
            .expose()
            .to_owned()
    };
    format!(
        r#"slipmesh: {{kind: network, version: 2, revision: 1}}
addressing: {{loopback: {{ipv4: 198.51.100.0/25, ipv6: "3fff::/64"}}}}
routing: {{bgp: {{as: 64512}}}}
mesh:
  interface_prefix: mesh-
  links:
    a-r1: {{type: wireguard, ends: {{node-a: {{}}, router1: {{}}}}, wireguard: {{port: 51820}}}}
nodes:
  node-a: {{platform: talos, node_id: 0.0.0.1, underlay: {{wan: {{endpoint: {{ipv4: 192.0.2.10}}}}}}, wireguard: {{private_key: "{a}"}}}}
  router1: {{platform: routeros, node_id: 0.0.0.2, underlay: {{wan: {{}}}}, wireguard: {{private_key: "{r}"}}}}
"#,
        a = key(),
        r = key(),
    )
}

/// A run for `node` on `network()`, with no device to reach.
fn run_for(name: &str, node: &str) -> (bool, String) {
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join(name);
    std::fs::create_dir_all(&dir).unwrap();
    let config = dir.join("slipmesh.yaml");
    std::fs::write(&config, network()).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_slipmesh-routeros"))
        .args(["--node", node, "--in"])
        .arg(&config)
        .env_remove("RUST_LOG")
        .env_remove("SLIPMESH_ROUTEROS_HOST")
        .env_remove("SLIPMESH_ROUTEROS_USERNAME")
        .output()
        .unwrap();
    (
        output.status.success(),
        String::from_utf8(output.stdout).unwrap(),
    )
}

#[test]
fn a_valid_file_is_read_and_the_run_stops_at_the_device_it_has_no_credentials_for() {
    let (success, log) = run_for("valid", "router1");
    assert!(!success, "{log}");
    assert!(log.contains("SLIPMESH_ROUTEROS_HOST is not set"), "{log}");
    assert!(!log.contains("failed to read the node's configs"), "{log}");
}

#[test]
fn a_node_of_talos_is_refused_naming_its_platform_before_the_device() {
    let (success, log) = run_for("talos-node", "node-a");
    assert!(!success, "{log}");
    assert!(log.contains("node-a") && log.contains("talos"), "{log}");
    assert!(!log.contains("SLIPMESH_ROUTEROS_HOST"), "{log}");
}
