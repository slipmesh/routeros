//! The one-shot pipeline: fetch CRD state once, handle finalizers/collision checks, connect to
//! the device once, converge, exit. No `kube::runtime::Controller`, no reflectors/watch, no state
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
use slipmesh_core::cluster_config_types::{ClusterConfig, cluster_config_from_configs};
use slipmesh_core::mesh_types::MeshLink;
use slipmesh_core::node_config_types::NodeConfig;
use std::net::Ipv6Addr;
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
/// `ClusterConfig`.
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
/// carries our finalizer: removes the finalizer. No explicit device-side interface removal is
/// needed here - excluding these links from the slice passed to `config::desired_state` this same
/// run means the normal exclusive-table convergence (`converge::run`, step 2) prunes the now-
/// undesired interface/peer on its own. Unlike before the NodeConfig/ClusterConfig migration,
/// there's no `MeshPool` slot to release - a link's port is a manual `spec.port` field, not
/// allocated.
async fn teardown_pending_links(
    mesh_links_api: &Api<MeshLink>,
    links: &[Arc<MeshLink>],
    node: &str,
) -> anyhow::Result<Vec<String>> {
    let mut torn_down = Vec::new();
    for link in allocation::links_pending_teardown(links, node) {
        let name = link.name_any();
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

/// Best-effort `Ready=False` condition on the offending `NodeConfig` - mirrors
/// `router::reconcile::set_node_config_condition`'s/`mesh::reconcile::set_condition`'s exact
/// type/reason shape in `slipmesh-operators`, for `kubectl` visibility parity. The caller always
/// follows this with `anyhow::bail!`: this tool has no requeue loop, so failing the whole run
/// (non-zero exit, cron retries later) is the correct one-shot mirror of operators' "block render,
/// requeue in 30s" behavior.
async fn set_node_config_condition(
    api: &Api<NodeConfig>,
    node: &NodeConfig,
    reason: &str,
    message: &str,
) -> anyhow::Result<()> {
    let existing = node
        .status
        .as_ref()
        .map_or(&[][..], |s| s.conditions.as_slice());
    let cond = slipmesh_core::condition(
        existing,
        "Ready",
        "False",
        reason,
        message,
        node.meta().generation,
    );
    api.patch_status(
        &node.name_any(),
        &PatchParams::apply("routeros"),
        &Patch::Merge(&json!({ "status": { "conditions": [cond] } })),
    )
    .await?;
    Ok(())
}

pub async fn run(cli: &Cli) -> anyhow::Result<ConvergeReport> {
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .map_err(|_| anyhow::anyhow!("failed to install default rustls crypto provider"))?;

    let client = Client::try_default()
        .await
        .context("failed to build a Kubernetes client from the default kubeconfig")?;

    let nodeconfigs_api: Api<NodeConfig> = Api::namespaced(client.clone(), NAMESPACE);
    let mesh_links_api: Api<MeshLink> = Api::namespaced(client.clone(), NAMESPACE);
    let clusterconfigs_api: Api<ClusterConfig> = Api::namespaced(client.clone(), NAMESPACE);
    let secrets_api: Api<Secret> = Api::namespaced(client.clone(), NAMESPACE);

    let own_node_config = nodeconfigs_api
        .get(&cli.node)
        .await
        .with_context(|| format!("NodeConfig {:?} not found in namespace {NAMESPACE:?} - create it before running routeros", cli.node))?;

    let cluster_configs = clusterconfigs_api
        .list(&ListParams::default())
        .await
        .context("failed to list ClusterConfig")?
        .items;
    let cluster_config = cluster_config_from_configs(&cluster_configs)?;
    let bgp_as = cluster_config.bgp_as;
    let ipv4_loopback_network =
        slipmesh_core::cidr::parse_network_cidr(&cluster_config.loopback_networks.ipv4)
            .context("ClusterConfig.loopbackNetworks.ipv4 is not a valid network CIDR")?;
    let ipv6_loopback_network: (Ipv6Addr, u8) = {
        let (addr, prefix) = cluster_config
            .loopback_networks
            .ipv6
            .split_once('/')
            .context("ClusterConfig.loopbackNetworks.ipv6 is not a CIDR (missing '/')")?;
        let addr = addr
            .parse()
            .context("ClusterConfig.loopbackNetworks.ipv6 has an invalid address")?;
        let prefix: u8 = prefix
            .parse()
            .context("ClusterConfig.loopbackNetworks.ipv6 has an invalid prefix length")?;
        anyhow::ensure!(
            prefix <= 128,
            "ClusterConfig.loopbackNetworks.ipv6 prefix length {prefix} exceeds 128"
        );
        (addr, prefix)
    };

    let mesh_links = list_arc(&mesh_links_api)
        .await
        .context("failed to list MeshLink")?;
    let node_configs = list_arc(&nodeconfigs_api)
        .await
        .context("failed to list NodeConfig")?;

    // node_id collision guard - mirrors router::reconcile::render's own-node_id check in
    // slipmesh-operators (see AGENTS.md: node_id used to be CAS-protected via RouterPool
    // allocation, which no longer exists).
    if let Some(other) =
        allocation::find_node_id_collision(&node_configs, &cli.node, own_node_config.spec.node_id)
    {
        let msg = format!(
            "node_id {} collides with NodeConfig {}",
            own_node_config.spec.node_id,
            other.name_any()
        );
        set_node_config_condition(&nodeconfigs_api, &own_node_config, "NodeIdConflict", &msg)
            .await?;
        anyhow::bail!(msg);
    }

    let own_loopback = slipmesh_core::ipv6::ipv4_loopback(
        ipv4_loopback_network.0,
        ipv4_loopback_network.1,
        own_node_config.spec.node_id,
    );
    let own_ipv6_loopback = slipmesh_core::ipv6::ipv6_loopback(
        ipv6_loopback_network.0,
        ipv6_loopback_network.1,
        own_node_config.spec.node_id,
    );

    let torn_down = teardown_pending_links(&mesh_links_api, &mesh_links, &cli.node).await?;
    let mesh_links: Vec<Arc<MeshLink>> = mesh_links
        .into_iter()
        .filter(|l| !torn_down.contains(&l.name_any()))
        .collect();

    ensure_link_finalizers(&mesh_links_api, &mesh_links, &cli.node).await?;

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

    // public_key collision guard - mirrors mesh::reconcile::reconcile's public-key check in
    // slipmesh-operators: two nodes sharing a public key would bind every mesh-* interface peering
    // with either one to the same kernel identity.
    if let Some(other) =
        allocation::find_public_key_collision(&node_configs, &cli.node, &public_key_b64)
    {
        let msg = format!("public key collides with NodeConfig {}", other.name_any());
        set_node_config_condition(
            &nodeconfigs_api,
            &own_node_config,
            "PublicKeyConflict",
            &msg,
        )
        .await?;
        anyhow::bail!(msg);
    }

    if own_node_config
        .status
        .as_ref()
        .and_then(|s| s.public_key.as_deref())
        != Some(public_key_b64.as_str())
    {
        nodeconfigs_api
            .patch_status(
                &cli.node,
                &PatchParams::apply("routeros"),
                &Patch::Merge(&json!({ "status": { "publicKey": public_key_b64 } })),
            )
            .await
            .context("failed to publish this device's public key to its own NodeConfig")?;
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
        loopback: own_loopback,
        ipv6_loopback: own_ipv6_loopback,
        private_key_b64: &private_key_b64,
    };
    let desired: DesiredState = config::desired_state(
        &own,
        bgp_as,
        ipv4_loopback_network,
        ipv6_loopback_network,
        &node_configs,
        &mesh_links,
        &physically_connected_prefixes,
    )?;

    converge::run(&device, &desired, !cli.check).await
}
