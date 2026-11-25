//! The node's desired state from the files of `slipmesh.yaml`: its `awg` and `router` configs,
//! computed and checked by `sliplib-mesh`. The files are read as plain text; decrypting them is the
//! caller's.

use anyhow::Context;
use sliplib_config::v2::{File, Platform};
use sliplib_mesh::Mesh;
use sliplib_mesh::render::{NodeConfigs, node_configs};
use sliplib_yaml::Mapping;
use std::path::PathBuf;

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

/// The configs of `node`, a node of `routeros`: this tool configures no other. A refusal names its
/// file once; one about the node or a secret its configs need names the node or link.
pub fn read_node(inputs: &[PathBuf], node: &str) -> anyhow::Result<NodeConfigs> {
    let files = File::open(inputs)?;
    // A refusal of the document names its file.
    no_settings(&files)?;
    // About the network as a whole, naming no document.
    let network = Mesh::of(&files).with_context(|| {
        let shown: Vec<String> = inputs
            .iter()
            .map(|path| path.display().to_string())
            .collect();
        format!("reading {}", shown.join(", "))
    })?;
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
        let configs = read_node(&[path], "router1").unwrap();
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
    fn one_file_and_its_split_into_architecture_and_secrets_give_the_same_desired_state() {
        let one = fixture();
        let keys: Vec<&str> = one
            .lines()
            .filter(|line| line.trim_start().starts_with("wireguard: {private_key"))
            .collect();
        assert_eq!(keys.len(), 2);
        let architecture: String = one
            .lines()
            .filter(|line| !keys.contains(line))
            .map(|line| format!("{line}\n"))
            .collect();
        let secrets = format!(
            "slipmesh: {{kind: network, version: 2, revision: 1}}\nnodes:\n  node-a:\n{}\n  \
             router1:\n{}\n",
            keys[0], keys[1]
        );
        let dir = tempfile::tempdir().unwrap();
        let paths =
            ["slipmesh.yaml", "mesh.yaml", "secrets.yaml"].map(|name| dir.path().join(name));
        for (path, text) in paths.iter().zip([&one, &architecture, &secrets]) {
            std::fs::write(path, text).unwrap();
        }
        let desired = |inputs: &[std::path::PathBuf]| {
            let configs = read_node(inputs, "router1").unwrap();
            crate::config::desired_state(&configs.awg, &configs.router, &[]).unwrap()
        };
        assert_eq!(desired(&paths[..1]), desired(&paths[1..]));
    }

    #[test]
    fn a_key_in_the_platform_document_of_routeros_is_refused() {
        let with_settings = format!(
            "{}---\nslipmesh: {{kind: platform, platform: routeros}}\nmetrics: {{}}\n",
            fixture()
        );
        let file = written(&with_settings);
        let path = file.path();
        let err = format!(
            "{:#}",
            read_node(std::slice::from_ref(&path), "router1")
                .err()
                .unwrap()
        );
        let line = fixture().lines().count() + 2;
        assert_eq!(
            err,
            format!(
                "the `kind: platform` document at line {line} of {}: `routeros` has no settings, \
                 and this one holds `metrics` - take it out",
                path.display()
            )
        );
        // Without the key, the document stands.
        let without = with_settings.replace("metrics: {}\n", "");
        let file = written(&without);
        read_node(&[file.path()], "router1").unwrap();
    }
}
