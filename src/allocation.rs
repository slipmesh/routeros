//! Loopback (`RouterPool`) and `/31`+port (`MeshPool`) allocation, plus the finalizer protocol
//! `hq` must participate in as a full mesh-fleet node - mirroring `router::reconcile::
//! allocate_router_loopback`/`mesh::reconcile::allocate_link_addressing` and their respective
//! finalizer handling in `slipmesh-operators`, just performed once per run instead of in a live
//! reconcile loop. See AGENTS.md.
//!
//! Pure predicates/helpers here are unit-tested directly; the actual `Api::replace_status`/
//! `Api::patch` calls are a thin, deliberately-untested I/O layer (see AGENTS.md's "no mocking
//! framework" convention) - verified against a real cluster/device in the manual pass instead.

use kube::api::{Patch, PatchParams};
use kube::{Api, Resource, ResourceExt};
use serde_json::json;
use slipmesh_core::mesh_types::{MeshLink, MeshNode};
use slipmesh_core::router_types::{RouterNode, RouterPool};
use std::net::Ipv4Addr;
use std::sync::Arc;

/// Single-party finalizer on `hq`'s own `RouterNode` - releases its `RouterPool` slot on delete.
/// Mirrors `router::reconcile::ROUTER_POOL_FINALIZER` exactly (same string, same one-finalizer-
/// per-object shape, since a `RouterNode` has exactly one owning party unlike `MeshLink`).
pub const ROUTER_POOL_FINALIZER: &str = "slipmesh.net/router-pool-release";

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
    finalizers.iter().filter(|f| f.as_str() != finalizer).cloned().collect()
}

/// Loopback allocation is only needed once - after that, `status.loopback` is always populated
/// (whether it came from a pin or a pool draw), exactly mirroring the gate
/// `router::reconcile::render` itself uses before ever calling `allocate_router_loopback`.
pub fn needs_loopback_allocation(node: &RouterNode) -> bool {
    node.status.as_ref().and_then(|s| s.loopback).is_none()
}

/// A `/31`+port only needs allocating when `hq` is the link's authoritative side (`node_a` - see
/// `MeshLinkSpec::is_lower`) *and* nothing has been allocated yet. When `hq` is `node_b`, the
/// peer's `mesh` operator already drove this allocation - `hq` only ever reads `status.network`/
/// `status.port`, never allocates on that link's behalf.
pub fn needs_link_allocation(link: &MeshLink, own_node_name: &str) -> bool {
    link.spec.is_lower(own_node_name) && link.status.as_ref().and_then(|s| s.network.as_ref()).is_none()
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
/// present" step, run before allocation/convergence so a freshly-created link is protected from
/// this device's very first reconcile pass onward, same as a Linux node's operator pod would do.
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

/// Successive loopback candidates within `network/prefix_len`, in address order - skips `.0` (not
/// a usable host address). Paired with `None` (no port concept) to match `slipmesh_core::pool::
/// allocate`'s generic candidate shape. Ported verbatim from `router::reconcile::
/// router_pool_candidates`.
pub fn router_pool_candidates(
    network: Ipv4Addr,
    prefix_len: u8,
) -> impl Iterator<Item = (String, Option<u16>)> {
    let network_u32 = u32::from(network);
    let host_bits = 32 - u32::from(prefix_len);
    let network_size: u64 = 1u64 << host_bits;
    (1u32..).map_while(move |offset| {
        let addr = network_u32.checked_add(offset)?;
        let in_range = (u64::from(offset)) < network_size;
        in_range.then(|| (Ipv4Addr::from(addr).to_string(), None))
    })
}

struct RouterPoolInfo {
    network: Ipv4Addr,
    prefix_len: u8,
}

async fn valid_router_pools(
    pools_api: &Api<RouterPool>,
) -> anyhow::Result<Vec<slipmesh_core::pool::ParsedPool<RouterPoolInfo>>> {
    slipmesh_core::pool::valid_pools(pools_api, |p| {
        let (network, prefix_len) = slipmesh_core::cidr::parse_network_cidr(&p.spec.network)?;
        Ok(RouterPoolInfo {
            network,
            prefix_len,
        })
    })
    .await
}

/// Allocates (or, for a pinned `spec.loopback`, registers) this device's loopback address and
/// patches `RouterNode.status`. Mirrors `router::reconcile::allocate_router_loopback` - notably,
/// even a pinned loopback still goes through `slipmesh_core::pool::allocate` with a single-
/// candidate iterator, so the pool's own `status.allocated` tracks it (preventing a collision with
/// another node claiming the same address), rather than bypassing the pool entirely.
pub async fn allocate_loopback(
    router_pools: &Api<RouterPool>,
    router_nodes: &Api<RouterNode>,
    node_name: &str,
    node: &RouterNode,
) -> anyhow::Result<Ipv4Addr> {
    let pools = valid_router_pools(router_pools).await?;

    if let Some(pinned) = node.spec.loopback {
        let pool = pools
            .iter()
            .find(|p| slipmesh_core::cidr::cidr_contains(p.value.network, p.value.prefix_len, pinned))
            .ok_or_else(|| {
                anyhow::anyhow!("no RouterPool configured contains pinned loopback {pinned}")
            })?;
        let allocated = slipmesh_core::pool::allocate(
            router_pools,
            &pool.name,
            node_name,
            std::iter::once((pinned.to_string(), None)),
        )
        .await?
        .ok_or_else(|| {
            anyhow::anyhow!("pinned loopback {pinned} is already allocated to another RouterNode")
        })?;
        let _ = allocated;
        patch_router_node_loopback(router_nodes, node_name, &pool.name, pinned).await?;
        return Ok(pinned);
    }

    for pool in &pools {
        let candidates = router_pool_candidates(pool.value.network, pool.value.prefix_len);
        if let Some((value, _)) =
            slipmesh_core::pool::allocate(router_pools, &pool.name, node_name, candidates).await?
        {
            let addr: Ipv4Addr = value
                .parse()
                .expect("value came from this same pool's own router_pool_candidates");
            patch_router_node_loopback(router_nodes, node_name, &pool.name, addr).await?;
            return Ok(addr);
        }
    }
    anyhow::bail!("no RouterPool has room for a new node")
}

async fn patch_router_node_loopback(
    api: &Api<RouterNode>,
    name: &str,
    pool: &str,
    loopback: Ipv4Addr,
) -> anyhow::Result<()> {
    let patch = json!({ "status": { "pool": pool, "loopback": loopback.to_string() } });
    api.patch_status(name, &PatchParams::apply("routeros"), &Patch::Merge(&patch))
        .await?;
    Ok(())
}

/// Adds `finalizer` to `name`'s `metadata.finalizers` if not already present. A no-op patch is
/// avoided by the caller only ever invoking this via [`links_needing_finalizer`]'s result.
pub async fn add_finalizer(
    links: &Api<MeshLink>,
    name: &str,
    current: &[String],
    finalizer: &str,
) -> anyhow::Result<()> {
    let patch = json!({ "metadata": { "finalizers": with_finalizer(current, finalizer) } });
    links
        .patch(name, &PatchParams::default(), &Patch::Merge(&patch))
        .await?;
    Ok(())
}

pub async fn remove_finalizer(
    links: &Api<MeshLink>,
    name: &str,
    current: &[String],
    finalizer: &str,
) -> anyhow::Result<()> {
    let patch = json!({ "metadata": { "finalizers": without_finalizer(current, finalizer) } });
    links
        .patch(name, &PatchParams::default(), &Patch::Merge(&patch))
        .await?;
    Ok(())
}

/// Releases this link's `MeshPool` slot (only ever held by the `node_a` side - see
/// `MeshLinkSpec::is_lower`) - idempotent, a missing entry is not an error.
pub async fn release_link_pool_slot(
    mesh_pools: &Api<slipmesh_core::mesh_types::MeshPool>,
    pool_name: &str,
    link_name: &str,
) -> anyhow::Result<()> {
    slipmesh_core::pool::release(mesh_pools, pool_name, link_name).await
}

pub async fn release_router_pool_slot(
    router_pools: &Api<RouterPool>,
    pool_name: &str,
    node_name: &str,
) -> anyhow::Result<()> {
    slipmesh_core::pool::release(router_pools, pool_name, node_name).await
}

/// Finds the peer `MeshNode` for `link` from `hq`'s perspective - used by the teardown path to
/// know which `mesh-<label>` interface to remove from the device (best-effort: if the peer
/// `MeshNode` is already gone too, the caller can't know the interface name and must fall back to
/// leaving it for a later full-state comparison, same as `mesh::reconcile`'s own comment on this).
pub fn peer_mesh_node_for_link<'a>(
    link: &MeshLink,
    mesh_nodes: &'a [Arc<MeshNode>],
    own_node_name: &str,
) -> Option<&'a Arc<MeshNode>> {
    let peer = link.spec.peer_label(own_node_name)?;
    mesh_nodes.iter().find(|n| n.name_any() == peer)
}

#[cfg(test)]
mod tests {
    use super::*;
    use slipmesh_core::mesh_types::{MeshLinkSpec, MeshLinkStatus, Obfuscation};
    use slipmesh_core::router_types::{RouterNodeSpec, RouterNodeStatus};

    fn link(node_a: &str, node_b: &str) -> MeshLink {
        MeshLink::new(
            &format!("{node_a}-{node_b}"),
            MeshLinkSpec {
                node_a: node_a.to_string(),
                node_b: node_b.to_string(),
                obfuscation: Obfuscation::default(),
                network: None,
            },
        )
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
    fn needs_loopback_allocation_true_until_status_is_populated() {
        let mut node = RouterNode::new(
            "hq",
            RouterNodeSpec {
                loopback: None,
                router_label: "hq".to_string(),
            },
        );
        assert!(needs_loopback_allocation(&node));
        node.status = Some(RouterNodeStatus {
            conditions: vec![],
            pool: Some("pool1".to_string()),
            loopback: Some(Ipv4Addr::new(10, 62, 0, 1)),
        });
        assert!(!needs_loopback_allocation(&node));
    }

    #[test]
    fn needs_loopback_allocation_true_even_with_a_pin_until_registered() {
        // A pin alone doesn't satisfy the gate - allocate_loopback must still run once to
        // register it in the pool (see the doc comment on allocate_loopback).
        let node = RouterNode::new(
            "hq",
            RouterNodeSpec {
                loopback: Some(Ipv4Addr::new(10, 62, 0, 1)),
                router_label: "hq".to_string(),
            },
        );
        assert!(needs_loopback_allocation(&node));
    }

    #[test]
    fn needs_link_allocation_only_when_node_a_and_unallocated() {
        let l = link("hq", "fra");
        assert!(needs_link_allocation(&l, "hq")); // node_a, no status at all
        assert!(!needs_link_allocation(&l, "fra")); // node_b never allocates

        let mut allocated = link("hq", "fra");
        allocated.status = Some(MeshLinkStatus {
            conditions: vec![],
            pool: Some("pool".to_string()),
            network: Some("10.0.0.0/31".to_string()),
            port: Some(51820),
        });
        assert!(!needs_link_allocation(&allocated, "hq"));
    }

    #[test]
    fn router_pool_candidates_skips_dot_zero() {
        let mut c = router_pool_candidates(Ipv4Addr::new(172, 21, 0, 0), 24);
        assert_eq!(c.next(), Some(("172.21.0.1".to_string(), None)));
        assert_eq!(c.next(), Some(("172.21.0.2".to_string(), None)));
    }

    #[test]
    fn links_pending_teardown_requires_deletion_timestamp_and_our_finalizer() {
        let mut deleting = link("hq", "fra");
        deleting.meta_mut().deletion_timestamp = Some(k8s_openapi::apimachinery::pkg::apis::meta::v1::Time(
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
}
