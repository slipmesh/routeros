//! The node's desired state from `slipmesh.yaml`: its `awg` and `router` configs, computed and
//! checked by `sliplib-mesh`. The file is read as plain text; decrypting it is the caller's.

use anyhow::Context;
use sliplib_config::v2::{File, Platform};
use sliplib_mesh::render::{self, NodeConfigs, node_configs};
use sliplib_yaml::MultiDoc;
use std::path::Path;

/// `refusal`, with the command that creates the secret when a missing one is what it is about.
fn with_its_cure(refusal: render::Error) -> anyhow::Error {
    let lacks_a_secret = refusal.missing_secret().is_some();
    let refusal = anyhow::Error::new(refusal);
    if lacks_a_secret {
        anyhow::anyhow!("{refusal:#} - `slipmesh mint` creates it")
    } else {
        refusal
    }
}

/// What `slipmesh.yaml` gives one node: its configs, and what the name of every interface of a
/// link starts with.
#[derive(Debug)]
pub struct Node {
    pub configs: NodeConfigs,
    pub interface_prefix: String,
}

/// The configs of `node`, a node of `routeros`: this tool configures no other. An error reading or
/// parsing the file names the file; one about the node or a secret its configs need names the
/// node or link.
pub fn read_node(path: &Path, node: &str) -> anyhow::Result<Node> {
    let reading = || format!("reading {}", path.display());
    let files = File::read(&MultiDoc::read(path)?).with_context(reading)?;
    // `routeros` has no settings: a key in its `platform` document is one nothing reads.
    files.routeros_settings().with_context(reading)?;
    let network = sliplib_mesh::v2::lower(&files).with_context(reading)?;
    let platform = network.node(node)?.platform;
    anyhow::ensure!(
        platform == Platform::Routeros,
        "node {node:?} is a `{platform}` node, which this tool does not configure"
    );
    let resolved = sliplib_mesh::secrets::read(&network);
    let configs = node_configs(&network, node, &resolved).map_err(with_its_cure)?;
    Ok(Node {
        configs,
        interface_prefix: network.interface_prefix,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::wg_key;
    use sliplib_secrets::wireguard::PrivateKey;

    /// A network of `node-a`, of `talos`, and `router1`, of `routeros`, on one link of type
    /// `wireguard`, every secret written.
    fn fixture() -> String {
        format!(
            r#"slipmesh:
  kind: network
  version: 2
  revision: 1
addressing:
  loopback: {{ipv4: 198.51.100.0/25, ipv6: "3fff::/64"}}
routing:
  bgp: {{as: 64512}}
mesh:
  interface_prefix: mesh-
  links:
    a-r1:
      type: wireguard
      ends: {{node-a: {{}}, router1: {{}}}}
      wireguard: {{port: 51820}}
nodes:
  node-a:
    platform: talos
    node_id: 0.0.0.1
    underlay: {{wan: {{endpoint: {{ipv4: 192.0.2.10}}}}}}
    wireguard: {{private_key: "{a}"}}
  router1:
    platform: routeros
    node_id: 0.0.0.2
    underlay: {{wan: {{}}}}
    wireguard: {{private_key: "{r}"}}
    routing: {{direct_interfaces: [bridge-lan], learn: [], announce: []}}
"#,
            a = wg_key("node-a"),
            r = wg_key("router1"),
        )
    }

    /// A `slipmesh.yaml` in a directory of its own, removed with it when the test is done.
    struct Written(std::path::PathBuf);

    impl Written {
        fn path(&self) -> std::path::PathBuf {
            self.0.join("slipmesh.yaml")
        }
    }

    impl Drop for Written {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn written(name: &str, text: &str) -> Written {
        let dir =
            std::env::temp_dir().join(format!("routeros-slipmesh-{}-{name}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let file = Written(dir);
        std::fs::write(file.path(), text).unwrap();
        file
    }

    #[test]
    fn a_nodes_configs_come_from_slipmesh_yaml() {
        let file = written("configs", &fixture());
        let path = file.path();
        let Node { configs, .. } = read_node(&path, "router1").unwrap();
        assert_eq!(configs.router.bgp_as, 64512);
        assert_eq!(configs.router.direct_interfaces, ["bridge-lan"]);
        let [iface] = configs.awg.interfaces.as_slice() else {
            panic!("{:?}", configs.awg.interfaces);
        };
        assert_eq!(iface.name, "mesh-node-a");
        let [peer] = iface.peers.as_slice() else {
            panic!("{:?}", iface.peers);
        };
        assert_eq!(peer.endpoint.as_deref(), Some("192.0.2.10:51820"));
        let a = PrivateKey::from(wg_key("node-a").as_str());
        assert_eq!(peer.public_key, a.public_key().unwrap());
    }

    #[test]
    fn a_node_the_file_does_not_have_is_refused_naming_it() {
        let file = written("unknown", &fixture());
        let path = file.path();
        let err = format!("{:#}", read_node(&path, "router2").err().unwrap());
        assert!(err.contains("router2"), "{err}");
    }

    #[test]
    fn a_file_that_is_not_there_is_refused_naming_it() {
        let path = std::env::temp_dir()
            .join("routeros-no-such-dir")
            .join("slipmesh.yaml");
        let err = format!("{:#}", read_node(&path, "router1").err().unwrap());
        assert!(err.contains(&*path.to_string_lossy()), "{err}");
    }

    #[test]
    fn a_file_that_does_not_read_as_slipmesh_yaml_is_refused_naming_it() {
        let file = written("malformed", &fixture().replace("  kind: network\n", ""));
        let path = file.path();
        let err = format!("{:#}", read_node(&path, "router1").err().unwrap());
        assert!(
            err.contains(&format!("reading {}", path.display())),
            "{err}"
        );
    }

    #[test]
    fn a_file_without_a_peers_key_is_refused_naming_the_peer_and_the_key() {
        let fixture = fixture().replace(
            &format!("    wireguard: {{private_key: \"{}\"}}\n", wg_key("node-a")),
            "",
        );
        let file = written("no-peer-key", &fixture);
        let path = file.path();
        let err = format!("{:#}", read_node(&path, "router1").err().unwrap());
        assert!(
            err.contains("node \"node-a\": wireguard.private_key is not set")
                && err.ends_with(" - `slipmesh mint` creates it"),
            "{err}"
        );
    }

    #[test]
    fn a_file_that_is_not_yaml_is_refused_naming_it() {
        let file = written("not-yaml", "slipmesh: [unterminated\n");
        let path = file.path();
        let err = format!("{:#}", read_node(&path, "router1").err().unwrap());
        assert!(err.contains(&*path.to_string_lossy()), "{err}");
    }

    #[test]
    fn a_node_of_another_platform_is_refused_naming_its_platform() {
        let file = written("other-platform", &fixture());
        let err = format!("{:#}", read_node(&file.path(), "node-a").err().unwrap());
        assert!(err.contains("node-a") && err.contains("talos"), "{err}");
    }

    #[test]
    fn a_key_in_the_platform_document_of_routeros_is_refused() {
        let with_settings = format!(
            "{}---\nslipmesh: {{kind: platform, platform: routeros}}\nmetrics: {{}}\n",
            fixture()
        );
        let file = written("routeros-settings", &with_settings);
        let path = file.path();
        let err = format!("{:#}", read_node(&path, "router1").err().unwrap());
        assert!(err.contains("metrics"), "{err}");
        assert!(
            err.contains(&format!("reading {}", path.display())),
            "{err}"
        );
        // Without the key, the document stands.
        let without = with_settings.replace("metrics: {}\n", "");
        let file = written("routeros-settings-empty", &without);
        read_node(&file.path(), "router1").unwrap();
    }

    #[test]
    fn the_prefix_of_the_links_interfaces_is_the_one_the_file_sets() {
        let file = written(
            "prefix",
            &fixture().replace("interface_prefix: mesh-", "interface_prefix: wg-"),
        );
        let node = read_node(&file.path(), "router1").unwrap();
        assert_eq!(node.interface_prefix, "wg-");
        assert_eq!(node.configs.awg.interfaces[0].name, "wg-node-a");
    }

    #[test]
    fn a_refusal_no_secret_cures_names_no_command() {
        let fixture = fixture().replace(
            &format!("    wireguard: {{private_key: \"{}\"}}\n", wg_key("node-a")),
            "    wireguard: {private_key: not a key}\n",
        );
        let file = written("not-a-key", &fixture);
        let err = format!("{:#}", read_node(&file.path(), "router1").err().unwrap());
        assert!(err.contains("node-a"), "{err}");
        assert!(!err.contains("slipmesh mint"), "{err}");
    }
}
