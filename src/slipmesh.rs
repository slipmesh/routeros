//! The node's desired state from `slipmesh.yaml`: its `awg` and `router` configs, computed and
//! checked by `sliplib-mesh` the way every platform's tool computes them. The file is read as
//! plain text; decrypting it is the caller's.

use anyhow::Context;
use sliplib_config::slipmesh_file::SlipmeshFile;
use sliplib_mesh::render::{NodeConfigs, node_configs};
use sliplib_yaml::MultiDoc;
use std::path::Path;

/// The error names the file.
pub fn read_node_configs(path: &Path, node: &str) -> anyhow::Result<NodeConfigs> {
    let file = SlipmeshFile::read(&MultiDoc::read(path)?)
        .with_context(|| format!("reading {}", path.display()))?;
    let resolved = sliplib_mesh::secrets::read(file.topology());
    let model = file.effective_for(node)?;
    node_configs(&model, node, &resolved)
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

    fn written(name: &str, text: &str) -> std::path::PathBuf {
        let dir =
            std::env::temp_dir().join(format!("routeros-slipmesh-{}-{name}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("slipmesh.yaml");
        std::fs::write(&path, text).unwrap();
        path
    }

    #[test]
    fn a_nodes_configs_come_from_slipmesh_yaml() {
        let path = written("configs", &fixture());
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
        let path = written("unknown", &fixture());
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
}
