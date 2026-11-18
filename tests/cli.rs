//! The binary as a caller sees it: its exit status and what it logs.

use std::path::Path;
use std::process::Command;

#[test]
fn a_failed_run_exits_nonzero_and_logs_the_whole_error_chain() {
    let config = Path::new(env!("CARGO_TARGET_TMPDIR"))
        .join("no-such-dir")
        .join("slipmesh.yaml");
    let output = Command::new(env!("CARGO_BIN_EXE_slipmesh-routeros"))
        .args(["--node", "node-a", "--config"])
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

/// A file in which `router1` dials `node-a` over a link that loses data packets: `random_trailers`
/// with a range in `h1`. Every key is generated here.
fn losing_link() -> String {
    let key = || {
        sliplib_secrets::wireguard::PrivateKey::generate()
            .expose()
            .to_owned()
    };
    format!(
        r#"slipmesh:
  kind: network
cluster:
  bgp_as: 64512
  loopback_networks: {{ipv4: "198.51.100.0/25", ipv6: "3fff::/32"}}
nodes:
  - {{name: node-a, node_id: "198.51.100.1", endpoint: "192.0.2.10", mesh_private_key: "{a}"}}
  - {{name: router1, node_id: "198.51.100.2", mesh_private_key: "{r}"}}
mesh:
  links:
    - pair: [node-a, router1]
      port: 51820
      obfuscation: {{jc: 4, jmin: 10, jmax: 50, s1: 40, s2: 41, h1: 100-199, h2: 6, h3: 7, h4: 8, random_trailers: true}}
"#,
        a = key(),
        r = key(),
    )
}

#[test]
fn a_losing_link_is_logged_as_a_warning_and_the_run_goes_on() {
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join("losing-link");
    std::fs::create_dir_all(&dir).unwrap();
    let config = dir.join("slipmesh.yaml");
    std::fs::write(&config, losing_link()).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_slipmesh-routeros"))
        .args(["--node", "router1", "--config"])
        .arg(&config)
        .env_remove("RUST_LOG")
        .env_remove("SLIPMESH_ROUTEROS_HOST")
        .env_remove("SLIPMESH_ROUTEROS_USERNAME")
        .output()
        .unwrap();

    // It goes on past the warning, and stops at the next step: no device to reach.
    assert!(!output.status.success(), "{:?}", output.status);
    let log = String::from_utf8(output.stdout).unwrap();
    let warning = log
        .find("WARN")
        .unwrap_or_else(|| panic!("no warning: {log}"));
    let refusal = log
        .find("SLIPMESH_ROUTEROS_HOST is not set")
        .unwrap_or_else(|| panic!("no refusal: {log}"));
    assert!(warning < refusal, "{log}");
    assert!(log.contains("mesh link node-a-router1: "), "{log}");
}
