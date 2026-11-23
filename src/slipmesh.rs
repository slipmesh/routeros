//! The node's desired state from `slipmesh.yaml`: its `awg` and `router` configs, computed and
//! checked by `sliplib-mesh`. The file is read as plain text; decrypting it is the caller's.

use anyhow::Context;
use sliplib_config::v2::{File, Platform};
use sliplib_mesh::Mesh;
use sliplib_mesh::render::{NodeConfigs, node_configs};
use sliplib_yaml::{Mapping, MultiDoc};
use std::path::Path;

/// `routeros` has no settings.
fn no_settings(files: &File) -> anyhow::Result<()> {
    let Some(document) = files.platform(Platform::Routeros) else {
        return Ok(());
    };
    let body: Mapping = document.read()?;
    if let Some((key, _)) = body.into_iter().next() {
        let key = sliplib_yaml::to_string(&key)?;
        anyhow::bail!(
            "{}: `routeros` has no settings, and this one holds `{}` - take it out",
            document.place(),
            key.trim_end()
        );
    }
    Ok(())
}

/// The configs of `node`, a node of `routeros`: this tool configures no other. An error reading or
/// parsing the file names the file; one about the node or a secret its configs need names the
/// node or link.
pub fn read_node(path: &Path, node: &str) -> anyhow::Result<NodeConfigs> {
    let reading = || format!("reading {}", path.display());
    let files = File::read(&MultiDoc::read(path)?).with_context(reading)?;
    no_settings(&files).with_context(reading)?;
    let network = Mesh::of(&files).with_context(reading)?;
    let platform = network.node(node)?.platform;
    anyhow::ensure!(
        platform == Platform::Routeros,
        "node {node:?} is a `{platform}` node, which this tool does not configure"
    );
    Ok(node_configs(&network, node)?)
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
    routing: {{direct_interfaces: [bridge-lan]}}
"#,
            a = wg_key("node-a"),
            r = wg_key("router1"),
        )
    }

    /// In a directory of its own, gone with the value.
    struct Written(tempfile::TempDir);

    impl Written {
        fn path(&self) -> std::path::PathBuf {
            self.0.path().join("slipmesh.yaml")
        }
    }

    fn written(text: &str) -> Written {
        let file = Written(tempfile::tempdir().unwrap());
        std::fs::write(file.path(), text).unwrap();
        file
    }

    #[test]
    fn a_nodes_configs_come_from_slipmesh_yaml() {
        let file = written(&fixture());
        let path = file.path();
        let configs = read_node(&path, "router1").unwrap();
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
        let file = written(&fixture());
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
        let file = written(&fixture().replace("  kind: network\n", ""));
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
        let file = written(&fixture);
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
        let file = written("slipmesh: [unterminated\n");
        let path = file.path();
        let err = format!("{:#}", read_node(&path, "router1").err().unwrap());
        assert!(err.contains(&*path.to_string_lossy()), "{err}");
    }

    #[test]
    fn a_node_of_another_platform_is_refused_naming_its_platform() {
        let file = written(&fixture());
        let err = format!("{:#}", read_node(&file.path(), "node-a").err().unwrap());
        assert!(err.contains("node-a") && err.contains("talos"), "{err}");
    }

    #[test]
    fn a_key_in_the_platform_document_of_routeros_is_refused() {
        let with_settings = format!(
            "{}---\nslipmesh: {{kind: platform, platform: routeros}}\nmetrics: {{}}\n",
            fixture()
        );
        let file = written(&with_settings);
        let path = file.path();
        let err = format!("{:#}", read_node(&path, "router1").err().unwrap());
        let line = fixture().lines().count() + 2;
        assert_eq!(
            err,
            format!(
                "reading {}: the `kind: platform` document at line {line}: `routeros` has no \
                 settings, and this one holds `metrics` - take it out",
                path.display()
            )
        );
        // Without the key, the document stands.
        let without = with_settings.replace("metrics: {}\n", "");
        let file = written(&without);
        read_node(&file.path(), "router1").unwrap();
    }

    #[test]
    fn a_refusal_no_secret_cures_names_no_command() {
        let fixture = fixture().replace(
            &format!("    wireguard: {{private_key: \"{}\"}}\n", wg_key("node-a")),
            "    wireguard: {private_key: not a key}\n",
        );
        let file = written(&fixture);
        let err = format!("{:#}", read_node(&file.path(), "router1").err().unwrap());
        assert!(err.contains("node-a"), "{err}");
        assert!(!err.contains("slipmesh mint"), "{err}");
    }

    #[test]
    fn a_keepalive_the_link_sets_reaches_the_peer_the_device_dials() {
        let fixture = fixture().replace(
            "wireguard: {port: 51820}",
            "wireguard: {port: 51820, persistent_keepalive: 10}",
        );
        let file = written(&fixture);
        let configs = read_node(&file.path(), "router1").unwrap();
        let desired = crate::config::desired_state(&configs.awg, &configs.router, &[]).unwrap();
        let [peer] = desired.wireguard_peers.as_slice() else {
            panic!("{:?}", desired.wireguard_peers);
        };
        assert_eq!(peer.persistent_keepalive, Some(10));
    }
}
