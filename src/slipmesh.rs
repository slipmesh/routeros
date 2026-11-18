//! The node's desired state from `slipmesh.yaml`: its `awg` and `router` configs, computed and
//! checked by `sliplib-mesh`. The file is read as plain text; decrypting it is the caller's.

use anyhow::Context;
use sliplib_config::slipmesh_file::SlipmeshFile;
use sliplib_mesh::render::{NodeConfigs, node_configs};
use sliplib_yaml::MultiDoc;
use std::path::Path;

/// An error reading or parsing the file names the file; one about the node or a secret its configs
/// need names the node, link or pool.
pub fn read_node_configs(path: &Path, node: &str) -> anyhow::Result<NodeConfigs> {
    let file = SlipmeshFile::read(&MultiDoc::read(path)?)
        .with_context(|| format!("reading {}", path.display()))?;
    let resolved = sliplib_mesh::secrets::read(file.topology());
    let model = file.effective_for(node)?;
    Ok(node_configs(&model, node, &resolved)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::wg_key;
    use sliplib_secrets::wireguard::PrivateKey;

    fn fixture() -> String {
        format!(
            r#"slipmesh:
  kind: network
cluster:
  bgp_as: 64512
  loopback_networks: {{ipv4: "198.51.100.0/25", ipv6: "3fff::/32"}}
nodes:
  - name: node-a
    node_id: "198.51.100.1"
    endpoint: "192.0.2.10"
    mesh_private_key: "{a}"
  - name: router1
    node_id: "198.51.100.2"
    mesh_private_key: "{r}"
    direct_interfaces: [bridge-lan]
mesh:
  links:
    - {{pair: [node-a, router1], port: 51820, plain: true}}
---
slipmesh:
  kind: patch
  include: [router1]
apiVersion: v1alpha1
kind: ExtensionServiceConfig
name: mikrotik
configFiles:
  - mountPath: /etc/talos-extensions/mikrotik.yaml
    content:
      host: router1.example.com
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
        let configs = read_node_configs(&path, "router1").unwrap();
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
        let err = format!("{:#}", read_node_configs(&path, "router2").err().unwrap());
        assert!(err.contains("router2"), "{err}");
    }

    #[test]
    fn a_file_that_is_not_there_is_refused_naming_it() {
        let path = std::env::temp_dir()
            .join("routeros-no-such-dir")
            .join("slipmesh.yaml");
        let err = format!("{:#}", read_node_configs(&path, "router1").err().unwrap());
        assert!(err.contains(&*path.to_string_lossy()), "{err}");
    }

    #[test]
    fn a_file_that_does_not_read_as_slipmesh_yaml_is_refused_naming_it() {
        let file = written("malformed", &fixture().replace("  kind: network\n", ""));
        let path = file.path();
        let err = format!("{:#}", read_node_configs(&path, "router1").err().unwrap());
        assert!(
            err.contains(&format!("reading {}", path.display())),
            "{err}"
        );
    }

    #[test]
    fn a_file_without_a_peers_key_is_refused_naming_the_peer_and_the_key() {
        let fixture = fixture().replace(
            &format!("    mesh_private_key: \"{}\"\n", wg_key("node-a")),
            "",
        );
        let file = written("no-peer-key", &fixture);
        let path = file.path();
        let err = format!("{:#}", read_node_configs(&path, "router1").err().unwrap());
        assert!(
            err.contains("node \"node-a\": mesh_private_key is not set"),
            "{err}"
        );
    }

    #[test]
    fn a_file_that_is_not_yaml_is_refused_naming_it() {
        let file = written("not-yaml", "slipmesh: [unterminated\n");
        let path = file.path();
        let err = format!("{:#}", read_node_configs(&path, "router1").err().unwrap());
        assert!(err.contains(&*path.to_string_lossy()), "{err}");
    }
}
