//! Pure "compute what this RouterOS device should look like" logic - the mesh/routing analogue of
//! `router::bird::render` in `slipmesh-operators`, just targeting RouterOS's own tables instead of
//! a BIRD config file. Takes plain CRD slices (already fetched by `run.rs`), returns a
//! [`DesiredState`]; touches neither `kube::Api` nor `mikrotik_rs` - see AGENTS.md's "keep I/O in
//! thin shims" convention.

use crate::diff::{
    DesiredAddressListEntry, DesiredBgpConnection, DesiredBgpInstance, DesiredBridge,
    DesiredFilterRule, DesiredIpAddress, DesiredListMember, DesiredOspfArea, DesiredOspfInstance,
    DesiredOspfInterfaceTemplate, DesiredWireguardInterface, DesiredWireguardPeer,
};
use crate::sanitize::{validate_endpoint, validate_label};
use slipmesh_core::mesh_types::{MeshLink, MeshNode};
use slipmesh_core::router_types::RouterNode;
use std::net::Ipv4Addr;
use std::sync::Arc;

pub const LOOPBACK_BRIDGE: &str = "router-lo";
pub const LAN_LIST: &str = "LAN";
pub const OSPF_INSTANCE: &str = "default-v2";
pub const OSPF_AREA: &str = "backbone";
pub const OSPF_FILTER_CHAIN: &str = "ospf-in";
pub const BGP_INSTANCE: &str = "default";
pub const BGP_NETWORKS_LIST: &str = "bgp-networks";
const MESH_PERSISTENT_KEEPALIVE: u16 = 25;
const OSPF_PEER_COST: u16 = 10;
const OSPF_HELLO_INTERVAL: &str = "10s";
const OSPF_DEAD_INTERVAL: &str = "40s";

/// This device's own identity - grouped into one struct purely to keep `desired_state`'s
/// parameter count sane (`node_name` is `--node`/`metadata.name`; `mesh_label`/`router_label` are
/// the separate, short fields inside `MeshNode.spec`/`RouterNode.spec` - see AGENTS.md, they don't
/// necessarily equal `node_name` or each other).
pub struct OwnIdentity<'a> {
    pub node_name: &'a str,
    pub mesh_label: &'a str,
    pub router_label: &'a str,
    pub loopback: Ipv4Addr,
    /// Base64 X25519 private key for this device's own WireGuard identity - never the public key;
    /// nothing in `desired_state` needs our own public key (only the peer's, from
    /// `MeshNode.status.publicKey` - publishing *our* public key back to our own `MeshNode` is a
    /// `run.rs`-level concern, not part of computing desired device state).
    pub private_key_b64: &'a str,
}

#[derive(Debug, Clone, PartialEq)]
pub struct DesiredState {
    pub wireguard_interfaces: Vec<DesiredWireguardInterface>,
    pub ip_addresses: Vec<DesiredIpAddress>,
    pub wireguard_peers: Vec<DesiredWireguardPeer>,
    pub list_members: Vec<DesiredListMember>,
    pub loopback_bridge: DesiredBridge,
    pub ospf_filter_rule: DesiredFilterRule,
    pub ospf_instance: DesiredOspfInstance,
    pub ospf_area: DesiredOspfArea,
    pub ospf_interface_templates: Vec<DesiredOspfInterfaceTemplate>,
    pub bgp_networks: Vec<DesiredAddressListEntry>,
    pub bgp_instance: DesiredBgpInstance,
    pub bgp_connections: Vec<DesiredBgpConnection>,
}

/// RFC1918-matching OSPF import filter that also sets `pref-src` to this device's own loopback -
/// anycast/mesh traffic must stay one-hop both ways. Ported verbatim from the ansible `router`
/// role's RouterOS filter rule (see the plan/commit history).
fn ospf_filter_rule_text(loopback: Ipv4Addr) -> String {
    format!(
        "if ((dst in 10.0.0.0/8 && dst-len >= 8 && dst-len <= 32) || \
         (dst in 172.16.0.0/12 && dst-len >= 12 && dst-len <= 32) || \
         (dst in 192.168.0.0/16 && dst-len >= 16 && dst-len <= 32)) \
         {{ set pref-src {loopback}; accept }} else {{ reject }}"
    )
}

struct AcceptedLink {
    iface: String,
    listen_port: u16,
    local_addr: Ipv4Addr,
    peer_public_key_b64: String,
    endpoint_address: Option<String>,
    endpoint_port: Option<u16>,
    persistent_keepalive: Option<u16>,
}

/// Everything needed to configure this device's side of one `MeshLink` - `None` (with a
/// `tracing::warn!`) for any link that isn't yet ready from this device's perspective: peer
/// `MeshNode` missing, peer's public key not yet computed, or `/31`+port not yet allocated for
/// this link. None of these are hard errors - a future run converges once the missing piece
/// appears (mirroring how `mesh::reconcile` itself treats the exact same conditions as "await
/// change", not a failure).
fn accept_link(
    link: &MeshLink,
    mesh_nodes: &[Arc<MeshNode>],
    own_node_name: &str,
) -> Option<AcceptedLink> {
    let link_name = link.metadata.name.as_deref().unwrap_or("<unnamed>");
    let peer_name = link.spec.peer_label(own_node_name)?;

    let Some(peer_node) = mesh_nodes
        .iter()
        .find(|n| n.metadata.name.as_deref() == Some(peer_name))
    else {
        tracing::warn!(
            link = link_name,
            peer = peer_name,
            "MeshNode not found, skipping link"
        );
        return None;
    };

    let Some(peer_public_key_b64) = peer_node.status.as_ref().and_then(|s| s.public_key.clone())
    else {
        tracing::warn!(
            link = link_name,
            peer = peer_name,
            "peer's public key not computed yet, skipping link"
        );
        return None;
    };

    let Some(link_network) = link.status.as_ref().and_then(|s| s.network.as_deref()) else {
        tracing::warn!(link = link_name, "no /31 allocated yet, skipping link");
        return None;
    };
    let Ok((network_addr, prefix_len)) = slipmesh_core::cidr::parse_cidr(link_network) else {
        tracing::warn!(
            link = link_name,
            network = link_network,
            "status.network is not a valid CIDR, skipping link"
        );
        return None;
    };
    if prefix_len != 31 {
        tracing::warn!(
            link = link_name,
            network = link_network,
            "status.network is not a /31, skipping link"
        );
        return None;
    }
    let Some(listen_port) = link.status.as_ref().and_then(|s| s.port) else {
        tracing::warn!(link = link_name, "no port allocated yet, skipping link");
        return None;
    };

    // peer_label being Some already proves own_node_name is node_a or node_b - this can only fail
    // on a genuine invariant violation, worth surfacing loudly rather than silently skipping.
    let local_addr = slipmesh_core::mesh_math::local_addr(
        network_addr,
        &link.spec.node_a,
        &link.spec.node_b,
        own_node_name,
    )
    .expect("own_node_name already confirmed to be a party to this link via peer_label");

    if let Err(e) = validate_label(&peer_node.spec.mesh_label) {
        tracing::warn!(link = link_name, peer = peer_name, error = %e, "peer mesh_label failed validation, skipping link");
        return None;
    }
    let iface = format!("mesh-{}", peer_node.spec.mesh_label);

    let (endpoint_address, endpoint_port, persistent_keepalive) = match peer_node
        .spec
        .endpoint
        .as_deref()
    {
        Some(endpoint) => match validate_endpoint(endpoint) {
            Ok(()) => (
                Some(endpoint.to_string()),
                Some(listen_port),
                Some(MESH_PERSISTENT_KEEPALIVE),
            ),
            Err(e) => {
                tracing::warn!(link = link_name, peer = peer_name, error = %e, "peer endpoint failed validation, skipping link");
                return None;
            }
        },
        // NAT'd peer with no reachable endpoint: no Endpoint/PersistentKeepalive, wait for it to
        // initiate the handshake and roam in - mirrors the Linux side's own NAT'd-peer handling.
        None => (None, None, None),
    };

    Some(AcceptedLink {
        iface,
        listen_port,
        local_addr,
        peer_public_key_b64,
        endpoint_address,
        endpoint_port,
        persistent_keepalive,
    })
}

pub fn desired_state(
    own: &OwnIdentity<'_>,
    bgp_as: u32,
    mesh_nodes: &[Arc<MeshNode>],
    mesh_links: &[Arc<MeshLink>],
    router_nodes: &[Arc<RouterNode>],
    physically_connected_prefixes: &[String],
) -> anyhow::Result<DesiredState> {
    // Our own labels get referenced by every peer that links to us (interface/connection naming
    // on *their* side) - validated here for the same reason peer labels are validated in
    // accept_link: defense in depth on top of the CRD schema's own regex.
    validate_label(own.mesh_label)
        .map_err(|e| anyhow::anyhow!("this device's own mesh_label failed validation: {e}"))?;
    validate_label(own.router_label)
        .map_err(|e| anyhow::anyhow!("this device's own router_label failed validation: {e}"))?;

    let mut wireguard_interfaces = Vec::new();
    let mut ip_addresses = vec![DesiredIpAddress {
        address: format!("{}/32", own.loopback),
        interface: LOOPBACK_BRIDGE.to_string(),
        disabled: false,
    }];
    let mut wireguard_peers = Vec::new();
    let mut list_members = Vec::new();

    for link in mesh_links {
        let Some(accepted) = accept_link(link, mesh_nodes, own.node_name) else {
            continue;
        };

        wireguard_interfaces.push(DesiredWireguardInterface {
            name: accepted.iface.clone(),
            listen_port: accepted.listen_port,
            private_key_b64: own.private_key_b64.to_string(),
            disabled: false,
        });
        ip_addresses.push(DesiredIpAddress {
            address: format!("{}/31", accepted.local_addr),
            interface: accepted.iface.clone(),
            disabled: false,
        });
        wireguard_peers.push(DesiredWireguardPeer {
            interface: accepted.iface.clone(),
            name: accepted.iface.trim_start_matches("mesh-").to_string(),
            public_key_b64: accepted.peer_public_key_b64,
            allowed_address: "0.0.0.0/0,::/0".to_string(),
            endpoint_address: accepted.endpoint_address,
            endpoint_port: accepted.endpoint_port,
            persistent_keepalive: accepted.persistent_keepalive,
            disabled: false,
        });
        list_members.push(DesiredListMember {
            list: LAN_LIST.to_string(),
            interface: accepted.iface,
            disabled: false,
        });
    }

    let mut ospf_interface_templates = vec![DesiredOspfInterfaceTemplate {
        interfaces: LOOPBACK_BRIDGE.to_string(),
        area: OSPF_AREA.to_string(),
        type_: None,
        cost: None,
        hello_interval: None,
        dead_interval: None,
        passive: true,
        disabled: false,
    }];
    // Reuses slipmesh-core's own peer-interface-list computation verbatim (see AGENTS.md) -
    // gated on MeshLinkStatus::is_ready(), which this device itself only sets *after*
    // successfully configuring its own side (run.rs, post-apply) - so a brand-new link's OSPF
    // template appears one run after its wireguard interface does, matching the same eventual
    // consistency the mesh/router operators already exhibit across separate reconcile passes.
    for iface in
        slipmesh_core::desired_state::ospf_ifaces_from(mesh_links, mesh_nodes, own.node_name)
    {
        ospf_interface_templates.push(DesiredOspfInterfaceTemplate {
            interfaces: iface,
            area: OSPF_AREA.to_string(),
            type_: Some("ptp".to_string()),
            cost: Some(OSPF_PEER_COST),
            hello_interval: Some(OSPF_HELLO_INTERVAL.to_string()),
            dead_interval: Some(OSPF_DEAD_INTERVAL.to_string()),
            passive: false,
            disabled: false,
        });
    }

    let bgp_networks = physically_connected_prefixes
        .iter()
        .filter(|prefix| {
            let ok = slipmesh_core::cidr::parse_cidr(prefix).is_ok();
            if !ok {
                tracing::warn!(prefix = %prefix, "physically-connected prefix is not a valid CIDR, skipping");
            }
            ok
        })
        .map(|prefix| DesiredAddressListEntry {
            list: BGP_NETWORKS_LIST.to_string(),
            address: prefix.clone(),
            disabled: false,
        })
        .collect();

    let mut bgp_connections = Vec::new();
    for peer in slipmesh_core::desired_state::bgp_peers_from(router_nodes, own.node_name) {
        if let Err(e) = validate_label(&peer.router_label) {
            tracing::warn!(peer = %peer.router_label, error = %e, "peer router_label failed validation, skipping BGP connection");
            continue;
        }
        bgp_connections.push(DesiredBgpConnection {
            name: format!("bgp-{}", peer.router_label),
            instance: BGP_INSTANCE.to_string(),
            local_address: own.loopback,
            local_role: "ibgp".to_string(),
            remote_address: peer.loopback,
            output_network: BGP_NETWORKS_LIST.to_string(),
            disabled: false,
        });
    }

    Ok(DesiredState {
        wireguard_interfaces,
        ip_addresses,
        wireguard_peers,
        list_members,
        loopback_bridge: DesiredBridge {
            name: LOOPBACK_BRIDGE.to_string(),
            disabled: false,
        },
        ospf_filter_rule: DesiredFilterRule {
            chain: OSPF_FILTER_CHAIN.to_string(),
            rule: ospf_filter_rule_text(own.loopback),
            disabled: false,
        },
        ospf_instance: DesiredOspfInstance {
            name: OSPF_INSTANCE.to_string(),
            version: 2,
            router_id: own.loopback,
            in_filter_chain: OSPF_FILTER_CHAIN.to_string(),
            disabled: false,
        },
        ospf_area: DesiredOspfArea {
            name: OSPF_AREA.to_string(),
            area_id: "0.0.0.0".to_string(),
            instance: OSPF_INSTANCE.to_string(),
            disabled: false,
        },
        ospf_interface_templates,
        bgp_networks,
        bgp_instance: DesiredBgpInstance {
            name: BGP_INSTANCE.to_string(),
            as_number: bgp_as,
            router_id: own.loopback,
            routing_table: "main".to_string(),
            disabled: false,
        },
        bgp_connections,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use k8s_openapi::apimachinery::pkg::apis::meta::v1::Condition;
    use slipmesh_core::mesh_types::{
        MeshLinkSpec, MeshLinkStatus, MeshNodeSpec, MeshNodeStatus, Obfuscation,
    };
    use slipmesh_core::router_types::{RouterNodeSpec, RouterNodeStatus};

    fn own() -> OwnIdentity<'static> {
        OwnIdentity {
            node_name: "hq",
            mesh_label: "hq",
            router_label: "hq",
            loopback: Ipv4Addr::new(10, 62, 0, 1),
            private_key_b64: "own-private-key",
        }
    }

    fn mesh_node(
        name: &str,
        mesh_label: &str,
        endpoint: Option<&str>,
        public_key: Option<&str>,
    ) -> Arc<MeshNode> {
        let mut n = MeshNode::new(
            name,
            MeshNodeSpec {
                endpoint: endpoint.map(str::to_string),
                mesh_label: mesh_label.to_string(),
            },
        );
        n.status = Some(MeshNodeStatus {
            conditions: vec![],
            public_key: public_key.map(str::to_string),
        });
        Arc::new(n)
    }

    fn ready_link(node_a: &str, node_b: &str, network: &str, port: u16) -> Arc<MeshLink> {
        let mut l = MeshLink::new(
            &format!("{node_a}-{node_b}"),
            MeshLinkSpec {
                node_a: node_a.to_string(),
                node_b: node_b.to_string(),
                obfuscation: Obfuscation::default(),
                network: None,
            },
        );
        l.status = Some(MeshLinkStatus {
            conditions: vec![Condition {
                type_: "Ready".to_string(),
                status: "True".to_string(),
                reason: "Configured".to_string(),
                message: "ok".to_string(),
                observed_generation: None,
                last_transition_time: k8s_openapi::apimachinery::pkg::apis::meta::v1::Time(
                    k8s_openapi::jiff::Timestamp::now(),
                ),
            }],
            pool: Some("pool".to_string()),
            network: Some(network.to_string()),
            port: Some(port),
        });
        Arc::new(l)
    }

    fn router_node(name: &str, label: &str, loopback: Ipv4Addr) -> Arc<RouterNode> {
        let mut n = RouterNode::new(
            name,
            RouterNodeSpec {
                loopback: None,
                router_label: label.to_string(),
            },
        );
        n.status = Some(RouterNodeStatus {
            conditions: vec![],
            pool: None,
            loopback: Some(loopback),
        });
        Arc::new(n)
    }

    #[test]
    fn always_includes_the_loopback_address_and_singletons() {
        let state = desired_state(&own(), 65062, &[], &[], &[], &[]).unwrap();
        assert_eq!(state.ip_addresses.len(), 1);
        assert_eq!(state.ip_addresses[0].address, "10.62.0.1/32");
        assert_eq!(state.ip_addresses[0].interface, LOOPBACK_BRIDGE);
        assert_eq!(state.loopback_bridge.name, LOOPBACK_BRIDGE);
        assert_eq!(state.ospf_instance.router_id, Ipv4Addr::new(10, 62, 0, 1));
        assert_eq!(state.bgp_instance.as_number, 65062);
        // Loopback OSPF interface-template is always present, even with zero mesh links.
        assert_eq!(state.ospf_interface_templates.len(), 1);
        assert!(state.ospf_interface_templates[0].passive);
    }

    #[test]
    fn accepts_a_fully_ready_link_with_an_endpoint() {
        let mesh_nodes = vec![
            mesh_node("hq", "hq", None, Some("hq-pub")),
            mesh_node("fra", "fra1", Some("fra.example.com"), Some("fra-pub")),
        ];
        let links = vec![ready_link("hq", "fra", "10.0.0.0/31", 51820)];
        let state = desired_state(&own(), 65062, &mesh_nodes, &links, &[], &[]).unwrap();

        assert_eq!(state.wireguard_interfaces.len(), 1);
        assert_eq!(state.wireguard_interfaces[0].name, "mesh-fra1");
        assert_eq!(state.wireguard_interfaces[0].listen_port, 51820);
        assert_eq!(
            state.wireguard_interfaces[0].private_key_b64,
            "own-private-key"
        );

        assert_eq!(state.wireguard_peers.len(), 1);
        let peer = &state.wireguard_peers[0];
        assert_eq!(peer.public_key_b64, "fra-pub");
        assert_eq!(peer.endpoint_address, Some("fra.example.com".to_string()));
        assert_eq!(peer.endpoint_port, Some(51820));
        assert_eq!(peer.persistent_keepalive, Some(25));

        // hq is node_a -> gets the low address of the /31.
        assert!(
            state
                .ip_addresses
                .iter()
                .any(|a| a.address == "10.0.0.0/31" && a.interface == "mesh-fra1")
        );
        assert!(
            state
                .list_members
                .iter()
                .any(|m| m.interface == "mesh-fra1" && m.list == "LAN")
        );
    }

    #[test]
    fn nat_peer_with_no_endpoint_gets_no_endpoint_or_keepalive() {
        let mesh_nodes = vec![
            mesh_node("hq", "hq", None, Some("hq-pub")),
            mesh_node("lon", "lon1", None, Some("lon-pub")), // no endpoint - NAT'd
        ];
        let links = vec![ready_link("lon", "hq", "10.0.0.2/31", 51821)];
        let state = desired_state(&own(), 65062, &mesh_nodes, &links, &[], &[]).unwrap();

        assert_eq!(state.wireguard_peers.len(), 1);
        assert_eq!(state.wireguard_peers[0].endpoint_address, None);
        assert_eq!(state.wireguard_peers[0].endpoint_port, None);
        assert_eq!(state.wireguard_peers[0].persistent_keepalive, None);
        // hq is node_b here -> gets the high address of the /31.
        assert!(
            state
                .ip_addresses
                .iter()
                .any(|a| a.address == "10.0.0.3/31")
        );
    }

    #[test]
    fn skips_a_link_whose_peer_meshnode_is_missing() {
        let links = vec![ready_link("hq", "ghost", "10.0.0.0/31", 51820)];
        let state = desired_state(&own(), 65062, &[], &links, &[], &[]).unwrap();
        assert!(state.wireguard_interfaces.is_empty());
        assert!(state.wireguard_peers.is_empty());
    }

    #[test]
    fn skips_a_link_whose_peer_has_no_public_key_yet() {
        let mesh_nodes = vec![
            mesh_node("hq", "hq", None, Some("hq-pub")),
            mesh_node("fra", "fra1", None, None), // public_key not computed yet
        ];
        let links = vec![ready_link("hq", "fra", "10.0.0.0/31", 51820)];
        let state = desired_state(&own(), 65062, &mesh_nodes, &links, &[], &[]).unwrap();
        assert!(state.wireguard_interfaces.is_empty());
    }

    #[test]
    fn skips_a_link_with_no_allocation_yet() {
        let mesh_nodes = vec![
            mesh_node("hq", "hq", None, Some("hq-pub")),
            mesh_node("fra", "fra1", None, Some("fra-pub")),
        ];
        let mut l = MeshLink::new(
            "hq-fra",
            MeshLinkSpec {
                node_a: "hq".to_string(),
                node_b: "fra".to_string(),
                obfuscation: Obfuscation::default(),
                network: None,
            },
        );
        l.status = None; // never allocated
        let state = desired_state(&own(), 65062, &mesh_nodes, &[Arc::new(l)], &[], &[]).unwrap();
        assert!(state.wireguard_interfaces.is_empty());
    }

    #[test]
    fn ignores_a_link_this_node_is_not_a_party_to() {
        let mesh_nodes = vec![
            mesh_node("fra", "fra1", None, Some("fra-pub")),
            mesh_node("lon", "lon1", None, Some("lon-pub")),
        ];
        let links = vec![ready_link("fra", "lon", "10.0.0.0/31", 51820)];
        let state = desired_state(&own(), 65062, &mesh_nodes, &links, &[], &[]).unwrap();
        assert!(state.wireguard_interfaces.is_empty());
    }

    #[test]
    fn physically_connected_prefixes_become_bgp_networks() {
        let prefixes = vec!["192.168.252.0/24".to_string(), "not-a-cidr".to_string()];
        let state = desired_state(&own(), 65062, &[], &[], &[], &prefixes).unwrap();
        assert_eq!(state.bgp_networks.len(), 1);
        assert_eq!(state.bgp_networks[0].address, "192.168.252.0/24");
        assert_eq!(state.bgp_networks[0].list, BGP_NETWORKS_LIST);
    }

    #[test]
    fn bgp_connections_exclude_self_and_include_every_other_router_node() {
        let router_nodes = vec![
            router_node("hq", "hq", Ipv4Addr::new(10, 62, 0, 1)),
            router_node("fra", "fra", Ipv4Addr::new(10, 62, 0, 2)),
            router_node("lon", "lon", Ipv4Addr::new(10, 62, 0, 3)),
        ];
        let state = desired_state(&own(), 65062, &[], &[], &router_nodes, &[]).unwrap();
        assert_eq!(state.bgp_connections.len(), 2);
        assert!(state.bgp_connections.iter().any(|c| c.name == "bgp-fra"
            && c.remote_address == Ipv4Addr::new(10, 62, 0, 2)
            && c.local_address == Ipv4Addr::new(10, 62, 0, 1)));
        assert!(state.bgp_connections.iter().any(|c| c.name == "bgp-lon"));
        assert!(!state.bgp_connections.iter().any(|c| c.name == "bgp-hq"));
    }

    #[test]
    fn ospf_filter_rule_embeds_the_loopback_and_all_three_rfc1918_ranges() {
        let rule = ospf_filter_rule_text(Ipv4Addr::new(10, 62, 0, 1));
        assert!(rule.contains("10.62.0.1"));
        assert!(rule.contains("10.0.0.0/8"));
        assert!(rule.contains("172.16.0.0/12"));
        assert!(rule.contains("192.168.0.0/16"));
        assert!(rule.contains("accept"));
        assert!(rule.contains("reject"));
    }
}
