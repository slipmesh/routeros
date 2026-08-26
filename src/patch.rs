//! Reads a `talos-extensions/patches`-generated patch file (`<patches-dir>/<node>.yaml`) and
//! extracts the `awg`/`router`/`mikrotik` `ExtensionServiceConfig` documents this tool needs.
//! Independent, minimal reimplementation of the document-splitting logic in
//! `talos-extensions/patches/src/segments.rs` (that crate has no `lib.rs` to depend on) - same
//! trivial format: `---`-separated YAML documents, each identified by `kind`/`name`. `mikrotik` is
//! a foreign document as far as `patches generate` is concerned (outside its own
//! `OWNED_NAMES = ["awg", "router", "nftables"]`), so it's preserved byte-for-byte across
//! regeneration - see `credentials.rs`.

use crate::credentials::{self, RouterCredentials};
use awg::config::AwgConfig;
use router::config::RouterConfig;
use serde::Deserialize;
use std::path::Path;

pub struct PatchFile {
    pub awg: AwgConfig,
    pub router: RouterConfig,
    pub credentials: RouterCredentials,
}

#[derive(Deserialize, Default)]
struct Envelope {
    kind: Option<String>,
    name: Option<String>,
    #[serde(rename = "configFiles", default)]
    config_files: Vec<ConfigFile>,
}

#[derive(Deserialize)]
struct ConfigFile {
    content: String,
}

fn split_segments(raw: &str) -> Vec<&str> {
    let raw = raw.strip_prefix("---\n").unwrap_or(raw);
    raw.split("\n---\n")
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .collect()
}

fn segment_content(segments: &[&str], name: &str) -> anyhow::Result<String> {
    for segment in segments {
        let envelope: Envelope = serde_yaml::from_str(segment).unwrap_or_default();
        if envelope.kind.as_deref() == Some("ExtensionServiceConfig")
            && envelope.name.as_deref() == Some(name)
        {
            let content = envelope
                .config_files
                .into_iter()
                .next()
                .ok_or_else(|| anyhow::anyhow!("{name:?} document has no configFiles entries"))?
                .content;
            return Ok(content);
        }
    }
    anyhow::bail!("patch file has no ExtensionServiceConfig document named {name:?}")
}

pub fn read_patch_file(path: &Path) -> anyhow::Result<PatchFile> {
    let raw = std::fs::read_to_string(path)
        .map_err(|e| anyhow::anyhow!("failed to read patch file {}: {e}", path.display()))?;
    let segments = split_segments(&raw);

    let awg_content = segment_content(&segments, "awg")?;
    let awg: AwgConfig = serde_yaml::from_str(&awg_content)
        .map_err(|e| anyhow::anyhow!("malformed \"awg\" document content: {e}"))?;
    awg::config::validate(&awg).map_err(|e| anyhow::anyhow!("invalid \"awg\" config: {e}"))?;

    let router_content = segment_content(&segments, "router")?;
    let router: RouterConfig = serde_yaml::from_str(&router_content)
        .map_err(|e| anyhow::anyhow!("malformed \"router\" document content: {e}"))?;
    router::config::validate(&router)
        .map_err(|e| anyhow::anyhow!("invalid \"router\" config: {e}"))?;

    let credentials_content = segment_content(&segments, "mikrotik")?;
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
        let raw = [FOREIGN_DOC, AWG_DOC, ROUTER_DOC, MIKROTIK_DOC].join("---\n");
        let segments = split_segments(&raw);
        assert_eq!(
            segment_content(&segments, "awg").unwrap().trim(),
            "interfaces: []"
        );
    }

    #[test]
    fn missing_awg_segment_is_an_error() {
        let raw = [ROUTER_DOC, MIKROTIK_DOC].join("---\n");
        let segments = split_segments(&raw);
        assert!(segment_content(&segments, "awg").is_err());
    }

    #[test]
    fn missing_router_segment_is_an_error() {
        let raw = [AWG_DOC, MIKROTIK_DOC].join("---\n");
        let segments = split_segments(&raw);
        assert!(segment_content(&segments, "router").is_err());
    }

    #[test]
    fn missing_mikrotik_segment_is_an_error() {
        let raw = [AWG_DOC, ROUTER_DOC].join("---\n");
        let segments = split_segments(&raw);
        assert!(segment_content(&segments, "mikrotik").is_err());
    }

    #[test]
    fn nonexistent_file_is_an_error() {
        assert!(read_patch_file(Path::new("/nonexistent/router1.yaml")).is_err());
    }

    #[test]
    fn split_of_empty_file_is_empty() {
        assert!(split_segments("").is_empty());
    }
}
