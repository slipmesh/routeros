//! The node's desired state from `slipmesh.yaml`: its `awg` and `router` configs, computed and
//! checked by `sliplib-mesh`. The file is read as plain text; decrypting it is the caller's.

use anyhow::Context;
use sliplib_config::v2::{File, Platform};
use sliplib_mesh::Mesh;
use sliplib_mesh::render::{NodeConfigs, node_configs};
use sliplib_yaml::Mapping;
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
    let files = File::open(path)?;
    no_settings(&files).with_context(reading)?;
    let network = Mesh::of(&files).with_context(reading)?;
    network.node_on(node, Platform::Routeros)?;
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
        let direct: Vec<&str> = configs
            .router
            .direct_interfaces
            .iter()
            .map(|pattern| pattern.as_str())
            .collect();
        assert_eq!(direct, ["bridge-lan"]);
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
}
