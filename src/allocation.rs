//! The `MeshLink` interface-cleanup finalizer lifecycle `hq` must participate in as a full
//! mesh-fleet node, plus node_id/public_key collision guards - mirroring
//! `mesh::reconcile::reconcile`'s own finalizer handling and uniqueness checks in
//! `slipmesh-operators`, just performed once per run instead of in a live reconcile loop. See
//! AGENTS.md.
//!
//! Before the NodeConfig/ClusterConfig migration this module also drove `RouterPool`/`MeshPool`
//! CAS allocation for a node's loopback and a link's `/31`+port. Neither exists any more:
//! `slipmesh_core::pool` and `slipmesh_core::mesh_math` were removed along with `RouterPool`/
//! `MeshPool` - a node's loopback/link-local are pure functions of a manually-assigned
//! `NodeConfig.spec.node_id` (see `slipmesh_core::ipv6`), and a link's UDP port is a manual
//! `MeshLink.spec.port` field, like `obfuscation`. That CAS used to make a `node_id`/public_key
//! collision structurally impossible; a manually-assigned `node_id` with no CAS makes it a real,
//! human-typo-shaped risk, so this module now also carries the pure collision-detection helpers
//! `run.rs` fails the whole run on - mirroring `router::reconcile::render`'s own-node_id check and
//! `mesh::reconcile::reconcile`'s public-key check, adapted to scan the whole `node_configs` slice
//! at once since this tool has no per-reconcile "the other object" framing.
//!
//! Pure predicates/helpers here are unit-tested directly; the actual `Api::patch` calls are a
//! thin, deliberately-untested I/O layer (see AGENTS.md's "no mocking framework" convention) -
//! verified against a real cluster/device in the manual pass instead.

use kube::api::{Patch, PatchParams};
use kube::{Resource, ResourceExt};
use slipmesh_core::mesh_types::MeshLink;
use slipmesh_core::node_config_types::NodeConfig;
use std::net::Ipv4Addr;
use std::sync::Arc;

/// Per-node finalizer on a `MeshLink` `hq` is a party to - mirrors `mesh::reconcile::
/// finalizer_for` exactly. Per-node, not per-object: a shared finalizer string couldn't express
/// "both parties are done" independently.
pub fn mesh_link_finalizer(node_name: &str) -> String {
    format!("slipmesh.net/interface-cleanup-{node_name}")
}

pub fn has_finalizer(finalizers: &[String], finalizer: &str) -> bool {
    finalizers.iter().any(|f| f == finalizer)
}

pub fn with_finalizer(finalizers: &[String], finalizer: &str) -> Vec<String> {
    if has_finalizer(finalizers, finalizer) {
        finalizers.to_vec()
    } else {
        let mut v = finalizers.to_vec();
        v.push(finalizer.to_string());
        v
    }
}

pub fn without_finalizer(finalizers: &[String], finalizer: &str) -> Vec<String> {
    finalizers
        .iter()
        .filter(|f| f.as_str() != finalizer)
        .cloned()
        .collect()
}

/// Every `MeshLink` `hq` is a party to, already marked for deletion, that still carries `hq`'s own
/// finalizer - these must be torn down (device config removed, finalizer released) before the
/// normal convergence pass runs, exactly mirroring `mesh::reconcile`'s deletion-handling branch.
pub fn links_pending_teardown<'a>(
    links: &'a [Arc<MeshLink>],
    own_node_name: &str,
) -> Vec<&'a Arc<MeshLink>> {
    let finalizer = mesh_link_finalizer(own_node_name);
    links
        .iter()
        .filter(|l| {
            l.meta().deletion_timestamp.is_some()
                && (l.spec.node_a == own_node_name || l.spec.node_b == own_node_name)
                && has_finalizer(l.finalizers(), &finalizer)
        })
        .collect()
}

/// Every `MeshLink` `hq` is a party to, not being deleted, that doesn't yet carry `hq`'s own
/// finalizer - mirrors `mesh::reconcile`'s "add our finalizer if involved and not already
/// present" step, run before convergence so a freshly-created link is protected from this
/// device's very first reconcile pass onward, same as a Linux node's operator pod would do.
pub fn links_needing_finalizer<'a>(
    links: &'a [Arc<MeshLink>],
    own_node_name: &str,
) -> Vec<&'a Arc<MeshLink>> {
    let finalizer = mesh_link_finalizer(own_node_name);
    links
        .iter()
        .filter(|l| {
            l.meta().deletion_timestamp.is_none()
                && (l.spec.node_a == own_node_name || l.spec.node_b == own_node_name)
                && !has_finalizer(l.finalizers(), &finalizer)
        })
        .collect()
}

/// Adds `finalizer` to `name`'s `metadata.finalizers` if not already present. A no-op patch is
/// avoided by the caller only ever invoking this via [`links_needing_finalizer`]'s result.
pub async fn add_finalizer<K>(
    api: &kube::Api<K>,
    name: &str,
    current: &[String],
    finalizer: &str,
) -> anyhow::Result<()>
where
    K: Clone
        + std::fmt::Debug
        + for<'de> serde::Deserialize<'de>
        + kube::Resource<DynamicType = ()>
        + serde::Serialize,
{
    let patch =
        serde_json::json!({ "metadata": { "finalizers": with_finalizer(current, finalizer) } });
    api.patch(name, &PatchParams::default(), &Patch::Merge(&patch))
        .await?;
    Ok(())
}

pub async fn remove_finalizer<K>(
    api: &kube::Api<K>,
    name: &str,
    current: &[String],
    finalizer: &str,
) -> anyhow::Result<()>
where
    K: Clone
        + std::fmt::Debug
        + for<'de> serde::Deserialize<'de>
        + kube::Resource<DynamicType = ()>
        + serde::Serialize,
{
    let patch =
        serde_json::json!({ "metadata": { "finalizers": without_finalizer(current, finalizer) } });
    api.patch(name, &PatchParams::default(), &Patch::Merge(&patch))
        .await?;
    Ok(())
}

/// The first other live `NodeConfig` (if any) that claims the same `node_id` as this device's own.
/// This used to be a collision structurally impossible under `RouterPool`'s CAS, now a real,
/// human-typo-shaped risk since `node_id` is a plain manually-assigned spec field. Mirrors
/// `router::reconcile::render`'s own-node_id check in `slipmesh-operators`.
pub fn find_node_id_collision<'a>(
    node_configs: &'a [Arc<NodeConfig>],
    own_name: &str,
    own_node_id: Ipv4Addr,
) -> Option<&'a Arc<NodeConfig>> {
    node_configs
        .iter()
        .find(|n| n.name_any() != own_name && n.spec.node_id == own_node_id)
}

/// The first other live `NodeConfig` (if any) that claims the same public key as this device's own.
/// Two nodes sharing a public key would bind every `mesh-*` interface peering with either one to
/// the same kernel identity. Mirrors `mesh::reconcile::reconcile`'s public-key collision check in
/// `slipmesh-operators`.
pub fn find_public_key_collision<'a>(
    node_configs: &'a [Arc<NodeConfig>],
    own_name: &str,
    own_public_key: &str,
) -> Option<&'a Arc<NodeConfig>> {
    node_configs.iter().find(|n| {
        n.name_any() != own_name
            && n.status.as_ref().and_then(|s| s.public_key.as_deref()) == Some(own_public_key)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use slipmesh_core::mesh_types::{MeshLinkSpec, Obfuscation};
    use slipmesh_core::node_config_types::{NodeConfig, NodeConfigSpec, NodeConfigStatus};

    fn link(node_a: &str, node_b: &str) -> MeshLink {
        MeshLink::new(
            &format!("{node_a}-{node_b}"),
            MeshLinkSpec {
                node_a: node_a.to_string(),
                node_b: node_b.to_string(),
                obfuscation: Obfuscation::default(),
                port: 51820,
            },
        )
    }

    fn node_config(name: &str, node_id: Ipv4Addr, public_key: Option<&str>) -> Arc<NodeConfig> {
        let mut n = NodeConfig::new(
            name,
            NodeConfigSpec {
                node_id,
                endpoint: None,
            },
        );
        n.status = Some(NodeConfigStatus {
            conditions: vec![],
            public_key: public_key.map(str::to_string),
        });
        Arc::new(n)
    }

    #[test]
    fn finalizer_helpers_are_idempotent() {
        let none: Vec<String> = vec![];
        let one = with_finalizer(&none, "f1");
        assert_eq!(one, vec!["f1".to_string()]);
        // Adding again must not duplicate.
        assert_eq!(with_finalizer(&one, "f1"), one);
        assert_eq!(without_finalizer(&one, "f1"), Vec::<String>::new());
        // Removing an absent finalizer is a no-op, not an error.
        assert_eq!(without_finalizer(&none, "f1"), none);
    }

    #[test]
    fn links_pending_teardown_requires_deletion_timestamp_and_our_finalizer() {
        let mut deleting = link("hq", "fra");
        deleting.meta_mut().deletion_timestamp =
            Some(k8s_openapi::apimachinery::pkg::apis::meta::v1::Time(
                k8s_openapi::jiff::Timestamp::now(),
            ));
        deleting.meta_mut().finalizers = Some(vec![mesh_link_finalizer("hq")]);

        let not_deleting = link("hq", "lon");
        let links = vec![Arc::new(deleting), Arc::new(not_deleting)];
        let pending = links_pending_teardown(&links, "hq");
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].spec.node_b, "fra");
    }

    #[test]
    fn links_needing_finalizer_skips_uninvolved_and_already_finalized() {
        let plain = link("hq", "fra"); // involved, no finalizer yet
        let mut already = link("hq", "lon");
        already.meta_mut().finalizers = Some(vec![mesh_link_finalizer("hq")]);
        let uninvolved = link("fra", "lon");

        let links = vec![Arc::new(plain), Arc::new(already), Arc::new(uninvolved)];
        let needing = links_needing_finalizer(&links, "hq");
        assert_eq!(needing.len(), 1);
        assert_eq!(needing[0].spec.node_b, "fra");
    }

    #[test]
    fn node_id_collision_finds_the_other_node_sharing_our_id() {
        let nodes = vec![
            node_config("hq", Ipv4Addr::new(0, 0, 0, 1), None),
            node_config("fra", Ipv4Addr::new(0, 0, 0, 2), None),
        ];
        assert!(find_node_id_collision(&nodes, "hq", Ipv4Addr::new(0, 0, 0, 1)).is_none());

        let colliding = vec![
            node_config("hq", Ipv4Addr::new(0, 0, 0, 5), None),
            node_config("fra", Ipv4Addr::new(0, 0, 0, 5), None),
        ];
        let hit = find_node_id_collision(&colliding, "hq", Ipv4Addr::new(0, 0, 0, 5));
        assert_eq!(hit.map(|n| n.name_any()), Some("fra".to_string()));
    }

    #[test]
    fn node_id_collision_ignores_self() {
        let nodes = vec![node_config("hq", Ipv4Addr::new(0, 0, 0, 1), None)];
        assert!(find_node_id_collision(&nodes, "hq", Ipv4Addr::new(0, 0, 0, 1)).is_none());
    }

    #[test]
    fn public_key_collision_finds_the_other_node_sharing_our_key() {
        let nodes = vec![
            node_config("hq", Ipv4Addr::new(0, 0, 0, 1), Some("same-key")),
            node_config("fra", Ipv4Addr::new(0, 0, 0, 2), Some("same-key")),
        ];
        let hit = find_public_key_collision(&nodes, "hq", "same-key");
        assert_eq!(hit.map(|n| n.name_any()), Some("fra".to_string()));
    }

    #[test]
    fn public_key_collision_none_when_keys_differ_or_unset() {
        let nodes = vec![
            node_config("hq", Ipv4Addr::new(0, 0, 0, 1), Some("key-a")),
            node_config("fra", Ipv4Addr::new(0, 0, 0, 2), Some("key-b")),
            node_config("lon", Ipv4Addr::new(0, 0, 0, 3), None),
        ];
        assert!(find_public_key_collision(&nodes, "hq", "key-a").is_none());
    }
}
