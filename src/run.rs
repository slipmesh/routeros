//! The one-shot pipeline: fetch CRD state once, handle finalizers/allocation, connect to the
//! device once, converge, exit. No `kube::runtime::Controller`, no reflectors/watch, no state
//! carried between invocations - see AGENTS.md.

use crate::allocation;
use crate::cli::Cli;
use crate::config::{self, DesiredState, OwnIdentity};
use crate::converge::{self, ConvergeReport};
use crate::credentials;
use anyhow::Context;
use k8s_openapi::api::core::v1::Secret;
use kube::api::{ListParams, Patch, PatchParams};
use kube::{Api, Client, Resource, ResourceExt};
use serde_json::json;
use slipmesh_core::mesh_types::{MeshLink, MeshNode, MeshPool};
use slipmesh_core::router_types::{RouterConfig, RouterNode, RouterPool};
use std::sync::Arc;

/// Hardcoded, not read from `POD_NAMESPACE` - this process runs directly on a host, not as a pod.
/// See AGENTS.md.
pub const NAMESPACE: &str = "slipmesh";

const OWN_KEYS_SECRET: &str = "routeros-keys";

async fn list_arc<K>(api: &Api<K>) -> anyhow::Result<Vec<Arc<K>>>
where
    K: Clone + std::fmt::Debug + for<'de> serde::Deserialize<'de> + kube::Resource,
{
    Ok(api
        .list(&ListParams::default())
        .await?
        .items
        .into_iter()
        .map(Arc::new)
        .collect())
}

/// Finds the single `Secret` labeled `slipmesh.net/node=<node>` in `namespace` - never a fixed
/// name (see AGENTS.md). Exactly one is expected, same "fail loud, don't guess" contract as
/// `RouterConfig`.
async fn find_credentials_secret(secrets: &Api<Secret>, node: &str) -> anyhow::Result<Secret> {
    let selector = format!("slipmesh.net/node={node}");
    let mut items = secrets
        .list(&ListParams::default().labels(&selector))
        .await?
        .items;
    match items.len() {
        0 => anyhow::bail!("no Secret labeled {selector:?} found in namespace {NAMESPACE:?}"),
        1 => Ok(items.remove(0)),
        n => {
            anyhow::bail!("expected exactly one Secret labeled {selector:?}, found {n} - ambiguous")
        }
    }
}

/// Tears down every `MeshLink` `--node` is party to that's already marked for deletion and still
/// carries our finalizer: releases the `MeshPool` slot (only if we were `node_a`) and removes the
/// finalizer. No explicit device-side interface removal is needed here - excluding these links
/// from the slice passed to `config::desired_state` this same run means the normal exclusive-
/// table convergence (`converge::run`, step 2) prunes the now-undesired interface/peer on its own.
async fn teardown_pending_links(
    mesh_links_api: &Api<MeshLink>,
    mesh_pools_api: &Api<MeshPool>,
    links: &[Arc<MeshLink>],
    node: &str,
) -> anyhow::Result<Vec<String>> {
    let mut torn_down = Vec::new();
    for link in allocation::links_pending_teardown(links, node) {
        let name = link.name_any();
        if link.spec.is_lower(node)
            && let Some(pool_name) = link.status.as_ref().and_then(|s| s.pool.as_deref())
            && let Err(e) =
                allocation::release_link_pool_slot(mesh_pools_api, pool_name, &name).await
        {
            tracing::warn!(link = %name, pool = pool_name, error = %e, "failed to release MeshPool slot on delete");
        }
        allocation::remove_finalizer(
            mesh_links_api,
            &name,
            link.finalizers(),
            &allocation::mesh_link_finalizer(node),
        )
        .await?;
        torn_down.push(name);
    }
    Ok(torn_down)
}

async fn ensure_link_finalizers(
    mesh_links_api: &Api<MeshLink>,
    links: &[Arc<MeshLink>],
    node: &str,
) -> anyhow::Result<()> {
    let finalizer = allocation::mesh_link_finalizer(node);
    for link in allocation::links_needing_finalizer(links, node) {
        allocation::add_finalizer(
            mesh_links_api,
            &link.name_any(),
            link.finalizers(),
            &finalizer,
        )
        .await?;
    }
    Ok(())
}

/// Ensures this device's own loopback is allocated (adding `ROUTER_POOL_FINALIZER` first, exactly
/// mirroring `router::reconcile::render`'s ordering) and returns it.
async fn ensure_loopback(
    router_pools_api: &Api<RouterPool>,
    router_nodes_api: &Api<RouterNode>,
    node: &str,
    router_node: &RouterNode,
) -> anyhow::Result<std::net::Ipv4Addr> {
    if !allocation::has_finalizer(router_node.finalizers(), allocation::ROUTER_POOL_FINALIZER) {
        allocation::add_finalizer(
            router_nodes_api,
            node,
            router_node.finalizers(),
            allocation::ROUTER_POOL_FINALIZER,
        )
        .await?;
    }
    if allocation::needs_loopback_allocation(router_node) {
        allocation::allocate_loopback(router_pools_api, router_nodes_api, node, router_node).await
    } else {
        Ok(router_node
            .status
            .as_ref()
            .and_then(|s| s.loopback)
            .expect("needs_loopback_allocation confirmed status.loopback is populated"))
    }
}

/// If `hq`'s own `RouterNode` is itself being decommissioned, release its `RouterPool` slot and
/// remove `ROUTER_POOL_FINALIZER` - mirrors `router::reconcile::render`'s own deletion-handling
/// branch. Returns `true` if deletion was handled (caller should stop here, nothing left to
/// converge this run).
async fn handle_router_node_deletion(
    router_pools_api: &Api<RouterPool>,
    router_nodes_api: &Api<RouterNode>,
    node: &str,
    router_node: &RouterNode,
) -> anyhow::Result<bool> {
    if router_node.meta().deletion_timestamp.is_none() {
        return Ok(false);
    }
    if allocation::has_finalizer(router_node.finalizers(), allocation::ROUTER_POOL_FINALIZER) {
        if let Some(pool_name) = router_node.status.as_ref().and_then(|s| s.pool.as_deref())
            && let Err(e) =
                allocation::release_router_pool_slot(router_pools_api, pool_name, node).await
        {
            tracing::warn!(node, pool = pool_name, error = %e, "failed to release RouterPool slot on delete");
        }
        allocation::remove_finalizer(
            router_nodes_api,
            node,
            router_node.finalizers(),
            allocation::ROUTER_POOL_FINALIZER,
        )
        .await?;
    }
    tracing::info!(
        node,
        "RouterNode is being deleted - nothing to converge this run"
    );
    Ok(true)
}

pub async fn run(cli: &Cli) -> anyhow::Result<ConvergeReport> {
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .map_err(|_| anyhow::anyhow!("failed to install default rustls crypto provider"))?;

    let client = Client::try_default()
        .await
        .context("failed to build a Kubernetes client from the default kubeconfig")?;

    let mesh_nodes_api: Api<MeshNode> = Api::namespaced(client.clone(), NAMESPACE);
    let router_nodes_api: Api<RouterNode> = Api::namespaced(client.clone(), NAMESPACE);
    let mesh_links_api: Api<MeshLink> = Api::namespaced(client.clone(), NAMESPACE);
    let mesh_pools_api: Api<MeshPool> = Api::namespaced(client.clone(), NAMESPACE);
    let router_pools_api: Api<RouterPool> = Api::namespaced(client.clone(), NAMESPACE);
    let router_configs_api: Api<RouterConfig> = Api::namespaced(client.clone(), NAMESPACE);
    let secrets_api: Api<Secret> = Api::namespaced(client.clone(), NAMESPACE);

    let mesh_node = mesh_nodes_api
        .get(&cli.node)
        .await
        .with_context(|| format!("MeshNode {:?} not found in namespace {NAMESPACE:?} - create it before running routeros", cli.node))?;
    let router_node = router_nodes_api
        .get(&cli.node)
        .await
        .with_context(|| format!("RouterNode {:?} not found in namespace {NAMESPACE:?} - create it before running routeros", cli.node))?;

    if handle_router_node_deletion(
        &router_pools_api,
        &router_nodes_api,
        &cli.node,
        &router_node,
    )
    .await?
    {
        return Ok(ConvergeReport::default());
    }

    let mesh_links = list_arc(&mesh_links_api)
        .await
        .context("failed to list MeshLink")?;
    let router_nodes = list_arc(&router_nodes_api)
        .await
        .context("failed to list RouterNode")?;
    let mesh_nodes = list_arc(&mesh_nodes_api)
        .await
        .context("failed to list MeshNode")?;
    let router_configs = router_configs_api
        .list(&ListParams::default())
        .await
        .context("failed to list RouterConfig")?
        .items;
    let bgp_as = slipmesh_core::router_types::router_config_from_configs(&router_configs)?.bgp_as;

    let torn_down =
        teardown_pending_links(&mesh_links_api, &mesh_pools_api, &mesh_links, &cli.node).await?;
    let mesh_links: Vec<Arc<MeshLink>> = mesh_links
        .into_iter()
        .filter(|l| !torn_down.contains(&l.name_any()))
        .collect();

    ensure_link_finalizers(&mesh_links_api, &mesh_links, &cli.node).await?;

    for link in &mesh_links {
        if allocation::needs_link_allocation(link, &cli.node) {
            let name = link.name_any();
            allocation::allocate_link(&mesh_pools_api, &mesh_links_api, link, &name).await?;
        }
    }
    // Re-fetch: allocate_link/ensure_loopback patched status server-side, invisible to the
    // in-memory Vec<Arc<MeshLink>> fetched above.
    let mesh_links = list_arc(&mesh_links_api)
        .await
        .context("failed to re-list MeshLink after allocation")?;

    let own_loopback = ensure_loopback(
        &router_pools_api,
        &router_nodes_api,
        &cli.node,
        &router_node,
    )
    .await?;

    let creds_secret = find_credentials_secret(&secrets_api, &cli.node).await?;
    let creds = credentials::parse_from_secret(&creds_secret)?;

    let private_key = slipmesh_core::keys::get_or_create_secret_key(
        &secrets_api,
        NAMESPACE,
        OWN_KEYS_SECRET,
        &cli.node,
    )
    .await
    .context("failed to get-or-create this device's own WireGuard key")?;
    let private_key_b64 = {
        use base64::Engine;
        base64::engine::general_purpose::STANDARD.encode(private_key)
    };
    let public_key_b64 = slipmesh_core::keys::derive_public_key(private_key);
    if mesh_node
        .status
        .as_ref()
        .and_then(|s| s.public_key.as_deref())
        != Some(public_key_b64.as_str())
    {
        mesh_nodes_api
            .patch_status(
                &cli.node,
                &PatchParams::apply("routeros"),
                &Patch::Merge(&json!({ "status": { "publicKey": public_key_b64 } })),
            )
            .await
            .context("failed to publish this device's public key to its own MeshNode")?;
    }

    let device = crate::mikrotik::connect(&creds)
        .await
        .context("failed to connect to the RouterOS device")?;

    let physically_connected_prefixes =
        crate::mikrotik::read_physically_connected_prefixes(&device, config::LOOPBACK_BRIDGE)
            .await
            .context("failed to read physically-connected prefixes from the device")?;

    let own = OwnIdentity {
        node_name: &cli.node,
        mesh_label: &mesh_node.spec.mesh_label,
        router_label: &router_node.spec.router_label,
        loopback: own_loopback,
        private_key_b64: &private_key_b64,
    };
    let desired: DesiredState = config::desired_state(
        &own,
        bgp_as,
        &mesh_nodes,
        &mesh_links,
        &router_nodes,
        &physically_connected_prefixes,
    )?;

    converge::run(&device, &desired, !cli.check).await
}
