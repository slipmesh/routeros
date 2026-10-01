//! Reads the patch file `slipmesh-taloscfg generate` writes for a node (`<patches-dir>/<node>.yaml`)
//! and extracts the `awg`/`router`/`mikrotik` `ExtensionServiceConfig` documents this tool needs.
//! `mikrotik` comes from a `kind: patch` document of `slipmesh.yaml`, which the generator passes
//! through to this node's patch file - see `credentials.rs`.

use crate::credentials::{self, RouterCredentials};
use anyhow::Context;
use awg::config::AwgConfig;
use router::config::RouterConfig;
use serde::Deserialize;
use std::path::Path;
use yaml_serde::Value;

pub struct PatchFile {
    pub awg: AwgConfig,
    pub router: RouterConfig,
    pub credentials: RouterCredentials,
}

#[derive(Deserialize)]
struct Envelope {
    #[serde(rename = "configFiles", default)]
    config_files: Vec<ConfigFile>,
}

#[derive(Deserialize)]
struct ConfigFile {
    content: String,
}

fn documents(raw: &str) -> anyhow::Result<Vec<Value>> {
    yaml_serde::Deserializer::from_str(raw)
        .map(Value::deserialize)
        .collect::<Result<_, _>>()
        .context("patch file is not valid YAML")
}

fn segment_content(documents: &[Value], name: &str) -> anyhow::Result<String> {
    let document = documents
        .iter()
        .find(|doc| doc["kind"] == "ExtensionServiceConfig" && doc["name"] == name)
        .with_context(|| {
            format!("patch file has no ExtensionServiceConfig document named {name:?}")
        })?;
    let envelope: Envelope = yaml_serde::from_value(document.clone())
        .with_context(|| format!("malformed {name:?} document"))?;
    envelope
        .config_files
        .into_iter()
        .next()
        .map(|file| file.content)
        .with_context(|| format!("{name:?} document has no configFiles entries"))
}

pub fn read_patch_file(path: &Path) -> anyhow::Result<PatchFile> {
    let raw = std::fs::read_to_string(path)
        .map_err(|e| anyhow::anyhow!("failed to read patch file {}: {e}", path.display()))?;
    let docs = documents(&raw)?;

    let awg_content = segment_content(&docs, "awg")?;
    let awg: AwgConfig = yaml_serde::from_str(&awg_content)
        .map_err(|e| anyhow::anyhow!("malformed \"awg\" document content: {e}"))?;
    awg::config::validate(&awg).map_err(|e| anyhow::anyhow!("invalid \"awg\" config: {e}"))?;

    let router_content = segment_content(&docs, "router")?;
    let router: RouterConfig = yaml_serde::from_str(&router_content)
        .map_err(|e| anyhow::anyhow!("malformed \"router\" document content: {e}"))?;
    router::config::validate(&router)
        .map_err(|e| anyhow::anyhow!("invalid \"router\" config: {e}"))?;

    let credentials_content = segment_content(&docs, "mikrotik")?;
    let credentials = credentials::parse_from_yaml(&credentials_content)?;

    Ok(PatchFile {
        awg,
        router,
        credentials,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const AWG_DOC: &str = "apiVersion: v1alpha1\nkind: ExtensionServiceConfig\nname: awg\nconfigFiles:\n  - mountPath: /etc/talos-extensions/awg.yaml\n    content: |\n      interfaces: []\n";
    const ROUTER_DOC: &str = "apiVersion: v1alpha1\nkind: ExtensionServiceConfig\nname: router\nconfigFiles:\n  - mountPath: /etc/talos-extensions/router.yaml\n    content: |\n      node:\n        loopback_addresses: [\"10.0.0.1/32\", \"fd00::1/128\"]\n      bgp_as: 64512\n      ospf_interfaces: []\n      direct_interfaces: []\n      learn: []\n      announce: []\n";
    const MIKROTIK_DOC: &str = "apiVersion: v1alpha1\nkind: ExtensionServiceConfig\nname: mikrotik\nconfigFiles:\n  - mountPath: /etc/talos-extensions/mikrotik.yaml\n    content: |\n      host: router1.example.com\n      port: 8729\n      username: ansible\n      password: hunter2\n";
    const FOREIGN_DOC: &str = "machine:\n  install:\n    disk: /dev/vda\n";

    fn full_file() -> String {
        [AWG_DOC, ROUTER_DOC, MIKROTIK_DOC].join("---\n")
    }

    #[test]
    fn parses_a_full_patch_file() {
        let dir = std::env::temp_dir().join(format!("routeros-patch-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("router1.yaml");
        std::fs::write(&path, full_file()).unwrap();

        let patch = read_patch_file(&path).unwrap();
        assert_eq!(patch.router.bgp_as, 64512);
        assert_eq!(patch.credentials.host, "router1.example.com");
        assert!(patch.awg.interfaces.is_empty());

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn foreign_documents_are_ignored_when_extracting_owned_segments() {
        let docs = documents(&[FOREIGN_DOC, AWG_DOC, ROUTER_DOC, MIKROTIK_DOC].join(
            "---
",
        ))
        .unwrap();
        assert_eq!(
            segment_content(&docs, "awg").unwrap().trim(),
            "interfaces: []"
        );
    }

    #[test]
    fn each_of_the_three_documents_is_required() {
        for (name, others) in [
            ("awg", [ROUTER_DOC, MIKROTIK_DOC]),
            ("router", [AWG_DOC, MIKROTIK_DOC]),
            ("mikrotik", [AWG_DOC, ROUTER_DOC]),
        ] {
            let docs = documents(&others.join(
                "---
",
            ))
            .unwrap();
            assert!(segment_content(&docs, name).is_err(), "{name}");
        }
    }

    #[test]
    fn a_malformed_document_is_reported_as_such_not_as_missing() {
        let dir = std::env::temp_dir().join(format!("routeros-malformed-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("router1.yaml");
        let broken = ROUTER_DOC.replace("name: router", "name: [router");
        std::fs::write(&path, [AWG_DOC, &broken, MIKROTIK_DOC].join("---\n")).unwrap();

        let err = read_patch_file(&path).err().unwrap().to_string();
        std::fs::remove_dir_all(&dir).unwrap();
        assert!(!err.contains("no ExtensionServiceConfig document"), "{err}");
    }

    #[test]
    fn nonexistent_file_is_an_error() {
        assert!(read_patch_file(Path::new("/nonexistent/router1.yaml")).is_err());
    }
}
