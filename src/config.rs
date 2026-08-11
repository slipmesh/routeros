//! Pure "compute what this RouterOS device should look like" logic - the mesh/routing analogue of
//! `router::bird::render` in `slipmesh-operators`, just targeting RouterOS's own tables instead of
//! a BIRD config file. Takes plain CRD slices (already fetched by `run.rs`), returns a
//! [`DesiredState`]; touches neither `kube::Api` nor `mikrotik_rs` - see AGENTS.md's "keep I/O in
//! thin shims" convention.

use crate::diff::{
    DesiredAddressListEntry, DesiredBgpConnection, DesiredBgpInstance, DesiredBridge,
    DesiredIpAddress, DesiredIpv6Address, DesiredListMember, DesiredOspfArea, DesiredOspfInstance,
    DesiredOspfInterfaceTemplate, DesiredWireguardInterface, DesiredWireguardPeer,
};
use crate::sanitize::validate_endpoint;
use slipmesh_core::mesh_types::MeshLink;
use slipmesh_core::node_config_types::NodeConfig;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::Arc;

pub const LOOPBACK_BRIDGE: &str = "router-lo";
pub const LAN_LIST: &str = "LAN";
/// Version-neutral name (was `"default-v2"` under OSPFv2) - the `version` field alone now
/// distinguishes the instance; see `mikrotik.rs::apply_ospf_instance`'s doc comment on the
/// in-place `2 -> 3` transition this rename anticipates.
pub const OSPF_INSTANCE: &str = "default";
pub const OSPF_AREA: &str = "backbone";
pub const BGP_INSTANCE: &str = "default";
pub const BGP_NETWORKS_LIST: &str = "bgp-networks";
const MESH_PERSISTENT_KEEPALIVE: u16 = 25;
const OSPF_PEER_COST: u16 = 10;
const OSPF_HELLO_INTERVAL: &str = "10s";
const OSPF_DEAD_INTERVAL: &str = "40s";
/// RouterOS 7.20+'s explicit AFI selector for a BGP connection - without it, a session negotiates
/// `afi=ipv6` only and a peer expecting an RFC 8950 IPv4-over-IPv6 session drops it (`v2-v3.md`
/// ловушка №4).
const BGP_AFI_IPV4: &str = "ip";

/// This device's own identity - grouped into one struct purely to keep `desired_state`'s
/// parameter count sane. `node_name` is `--node`/`metadata.name`; `loopback`/`ipv6_loopback` are
/// already derived by the caller (`slipmesh_core::ipv6::{ipv4_loopback, ipv6_loopback}` from this
/// device's own `NodeConfig.spec.node_id`) - mirrors `bird::RouterIdentity` in
/// `operators/router/src/bird.rs` exactly.
pub struct OwnIdentity<'a> {
    pub node_name: &'a str,
    pub loopback: Ipv4Addr,
    pub ipv6_loopback: Ipv6Addr,
    /// Base64 X25519 private key for this device's own WireGuard identity - never the public key;
    /// nothing in `desired_state` needs our own public key (only the peer's, from
    /// `NodeConfig.status.publicKey` - publishing *our* public key back to our own `NodeConfig` is
    /// a `run.rs`-level concern, not part of computing desired device state).
    pub private_key_b64: &'a str,
}

#[derive(Debug, Clone, PartialEq)]
pub struct DesiredState {
    pub wireguard_interfaces: Vec<DesiredWireguardInterface>,
    pub ip_addresses: Vec<DesiredIpAddress>,
    pub ip_v6_addresses: Vec<DesiredIpv6Address>,
    pub wireguard_peers: Vec<DesiredWireguardPeer>,
    pub list_members: Vec<DesiredListMember>,
    pub loopback_bridge: DesiredBridge,
    pub ospf_instance: DesiredOspfInstance,
    pub ospf_area: DesiredOspfArea,
    pub ospf_interface_templates: Vec<DesiredOspfInterfaceTemplate>,
    pub bgp_networks: Vec<DesiredAddressListEntry>,
    pub bgp_instance: DesiredBgpInstance,
    pub bgp_connections: Vec<DesiredBgpConnection>,
}

struct AcceptedLink {
    iface: String,
    listen_port: u16,
    peer_public_key_b64: String,
    endpoint_address: Option<String>,
    endpoint_port: Option<u16>,
    persistent_keepalive: Option<u16>,
}

/// Everything needed to configure this device's side of one `MeshLink` - `None` (with a
/// `tracing::warn!`) for any link that isn't yet ready from this device's perspective: peer
/// `NodeConfig` missing, or peer's public key not yet computed. Neither is a hard error - a future
/// run converges once the missing piece appears (mirroring how `mesh::reconcile` itself treats the
/// exact same conditions as "await change", not a failure).
///
/// No allocation-status branch any more: `MeshLink.status` lost `network`/`port` in the
/// NodeConfig/ClusterConfig migration - `listen_port` is just `link.spec.port` directly, a manual
/// field like `obfuscation`.
fn accept_link(
    link: &MeshLink,
    node_configs: &[Arc<NodeConfig>],
    own_node_name: &str,
) -> Option<AcceptedLink> {
    let link_name = link.metadata.name.as_deref().unwrap_or("<unnamed>");
    let peer_name = link.spec.peer_label(own_node_name)?;

    let Some(peer_node) = node_configs
        .iter()
        .find(|n| n.metadata.name.as_deref() == Some(peer_name))
    else {
        tracing::warn!(
            link = link_name,
            peer = peer_name,
            "NodeConfig not found, skipping link"
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

    let iface = format!(
        "mesh-{}",
        slipmesh_core::ipv6::short_id(peer_node.spec.node_id)
    );
    let listen_port = link.spec.port;

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
        peer_public_key_b64,
        endpoint_address,
        endpoint_port,
        persistent_keepalive,
    })
}

pub fn desired_state(
    own: &OwnIdentity<'_>,
    bgp_as: u32,
    ipv4_loopback_network: (Ipv4Addr, u8),
    ipv6_loopback_network: (Ipv6Addr, u8),
    node_configs: &[Arc<NodeConfig>],
    mesh_links: &[Arc<MeshLink>],
    physically_connected_prefixes: &[String],
) -> anyhow::Result<DesiredState> {
    let mut wireguard_interfaces = Vec::new();
    let ip_addresses = vec![DesiredIpAddress {
        address: format!("{}/32", own.loopback),
        interface: LOOPBACK_BRIDGE.to_string(),
        disabled: false,
    }];
    // `advertise: false` matches `v2-v3.md` §4's `/ipv6 address add ... advertise=no` - this is a
    // loopback identity, not a LAN prefix to hand out via SLAAC RA.
    let ip_v6_addresses = vec![DesiredIpv6Address {
        address: format!("{}/128", own.ipv6_loopback),
        interface: LOOPBACK_BRIDGE.to_string(),
        advertise: false,
        disabled: false,
    }];
    let mut wireguard_peers = Vec::new();
    let mut list_members = Vec::new();

    for link in mesh_links {
        let Some(accepted) = accept_link(link, node_configs, own.node_name) else {
            continue;
        };

        wireguard_interfaces.push(DesiredWireguardInterface {
            name: accepted.iface.clone(),
            listen_port: accepted.listen_port,
            private_key_b64: own.private_key_b64.to_string(),
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
        slipmesh_core::desired_state::ospf_ifaces_from(mesh_links, node_configs, own.node_name)
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

    // Own loopback /32 is announced alongside physically-connected prefixes - the
    // NodeConfig/ClusterConfig migration's companion fix in slipmesh-operators (RTS_DEVICE now
    // exported into ibgp6_*, see AGENTS.md) means every mesh node's own loopback is reachable via
    // RFC 8950; RouterOS mirrors that by adding it to the same `bgp-networks` address-list
    // `output.network` already matches against (a "network statement": RouterOS only announces an
    // address-list entry that's already a real route in the RIB, which the connected `/32` on
    // `router-lo` always is - no `output.redistribute=connected` needed on top).
    let mut bgp_network_addrs: Vec<String> = physically_connected_prefixes
        .iter()
        .filter(|prefix| {
            let ok = slipmesh_core::cidr::parse_cidr(prefix).is_ok();
            if !ok {
                tracing::warn!(prefix = %prefix, "physically-connected prefix is not a valid CIDR, skipping");
            }
            ok
        })
        .cloned()
        .collect();
    bgp_network_addrs.push(format!("{}/32", own.loopback));
    // RouterOS's `ip firewall address-list` echoes a host-only entry back without its `/32`
    // suffix (confirmed live: writing "10.62.0.255/32" reads back as "10.62.0.255") - strip it
    // here so a /32 entry (own loopback, or a /32 physically-connected prefix) compares like
    // with like instead of the diff perpetually re-adding/removing the exact same entry.
    let bgp_networks = bgp_network_addrs
        .into_iter()
        .map(|address| DesiredAddressListEntry {
            list: BGP_NETWORKS_LIST.to_string(),
            address: address
                .strip_suffix("/32")
                .map(str::to_string)
                .unwrap_or(address),
            disabled: false,
        })
        .collect();

    let mut bgp_connections = Vec::new();
    for peer in slipmesh_core::desired_state::bgp_peers_from(
        node_configs,
        ipv4_loopback_network,
        ipv6_loopback_network,
        own.node_name,
    ) {
        bgp_connections.push(DesiredBgpConnection {
            name: format!("bgp-{}", slipmesh_core::ipv6::short_id(peer.node_id)),
            instance: BGP_INSTANCE.to_string(),
            local_address: own.ipv6_loopback,
            local_role: "ibgp".to_string(),
            remote_address: peer.ipv6_loopback,
            multihop: true,
            afi: BGP_AFI_IPV4.to_string(),
            output_network: BGP_NETWORKS_LIST.to_string(),
            disabled: false,
        });
    }

    Ok(DesiredState {
        wireguard_interfaces,
        ip_addresses,
        ip_v6_addresses,
        wireguard_peers,
        list_members,
        loopback_bridge: DesiredBridge {
            name: LOOPBACK_BRIDGE.to_string(),
            disabled: false,
        },
        ospf_instance: DesiredOspfInstance {
            name: OSPF_INSTANCE.to_string(),
            version: 3,
            router_id: own.loopback,
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
    use slipmesh_core::mesh_types::{MeshLinkSpec, MeshLinkStatus, Obfuscation};
    use slipmesh_core::node_config_types::{NodeConfigSpec, NodeConfigStatus};

    const IPV4_NET: (Ipv4Addr, u8) = (Ipv4Addr::new(10, 62, 0, 0), 24);
    const IPV6_NET: (Ipv6Addr, u8) = (Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 0), 16);

    fn own() -> OwnIdentity<'static> {
        OwnIdentity {
            node_name: "hq",
            loopback: Ipv4Addr::new(10, 62, 0, 1),
            ipv6_loopback: "fd00::1".parse().unwrap(),
            private_key_b64: "own-private-key",
        }
    }

    fn node_config(
        name: &str,
        node_id: Ipv4Addr,
        endpoint: Option<&str>,
        public_key: Option<&str>,
    ) -> Arc<NodeConfig> {
        let mut n = NodeConfig::new(
            name,
            NodeConfigSpec {
                node_id,
                endpoint: endpoint.map(str::to_string),
            },
        );
        n.status = Some(NodeConfigStatus {
            conditions: vec![],
            public_key: public_key.map(str::to_string),
        });
        Arc::new(n)
    }

    fn ready_link(node_a: &str, node_b: &str, port: u16) -> Arc<MeshLink> {
        let mut l = MeshLink::new(
            &format!("{node_a}-{node_b}"),
            MeshLinkSpec {
                node_a: node_a.to_string(),
                node_b: node_b.to_string(),
                obfuscation: Obfuscation::default(),
                port,
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
        });
        Arc::new(l)
    }

    #[test]
    fn always_includes_the_loopback_addresses_and_singletons() {
        let state = desired_state(&own(), 65062, IPV4_NET, IPV6_NET, &[], &[], &[]).unwrap();
        assert_eq!(state.ip_addresses.len(), 1);
        assert_eq!(state.ip_addresses[0].address, "10.62.0.1/32");
        assert_eq!(state.ip_addresses[0].interface, LOOPBACK_BRIDGE);
        assert_eq!(state.ip_v6_addresses.len(), 1);
        assert_eq!(state.ip_v6_addresses[0].address, "fd00::1/128");
        assert!(!state.ip_v6_addresses[0].advertise);
        assert_eq!(state.loopback_bridge.name, LOOPBACK_BRIDGE);
        assert_eq!(state.ospf_instance.version, 3);
        assert_eq!(state.ospf_instance.router_id, Ipv4Addr::new(10, 62, 0, 1));
        assert_eq!(state.bgp_instance.as_number, 65062);
        // Loopback OSPF interface-template is always present, even with zero mesh links.
        assert_eq!(state.ospf_interface_templates.len(), 1);
        assert!(state.ospf_interface_templates[0].passive);
        // Own loopback is always announced via BGP, even with no physically-connected prefixes -
        // stripped of its /32 (RouterOS echoes a host-only address-list entry back bare).
        assert_eq!(state.bgp_networks.len(), 1);
        assert_eq!(state.bgp_networks[0].address, "10.62.0.1");
    }

    #[test]
    fn accepts_a_fully_ready_link_with_an_endpoint() {
        let node_configs = vec![
            node_config("hq", Ipv4Addr::new(0, 0, 0, 1), None, Some("hq-pub")),
            node_config(
                "fra",
                Ipv4Addr::new(0, 0, 0, 2),
                Some("fra.example.com"),
                Some("fra-pub"),
            ),
        ];
        let links = vec![ready_link("hq", "fra", 51820)];
        let state = desired_state(
            &own(),
            65062,
            IPV4_NET,
            IPV6_NET,
            &node_configs,
            &links,
            &[],
        )
        .unwrap();

        assert_eq!(state.wireguard_interfaces.len(), 1);
        assert_eq!(state.wireguard_interfaces[0].name, "mesh-2");
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

        // Mesh links carry no IPv4/IPv6 address at all any more - only the loopback does.
        assert_eq!(state.ip_addresses.len(), 1);
        assert_eq!(state.ip_v6_addresses.len(), 1);
        assert!(
            state
                .list_members
                .iter()
                .any(|m| m.interface == "mesh-2" && m.list == "LAN")
        );
    }

    #[test]
    fn nat_peer_with_no_endpoint_gets_no_endpoint_or_keepalive() {
        let node_configs = vec![
            node_config("hq", Ipv4Addr::new(0, 0, 0, 1), None, Some("hq-pub")),
            node_config("lon", Ipv4Addr::new(0, 0, 0, 3), None, Some("lon-pub")), // no endpoint - NAT'd
        ];
        let links = vec![ready_link("lon", "hq", 51821)];
        let state = desired_state(
            &own(),
            65062,
            IPV4_NET,
            IPV6_NET,
            &node_configs,
            &links,
            &[],
        )
        .unwrap();

        assert_eq!(state.wireguard_peers.len(), 1);
        assert_eq!(state.wireguard_peers[0].endpoint_address, None);
        assert_eq!(state.wireguard_peers[0].endpoint_port, None);
        assert_eq!(state.wireguard_peers[0].persistent_keepalive, None);
    }

    #[test]
    fn skips_a_link_whose_peer_node_config_is_missing() {
        let links = vec![ready_link("hq", "ghost", 51820)];
        let state = desired_state(&own(), 65062, IPV4_NET, IPV6_NET, &[], &links, &[]).unwrap();
        assert!(state.wireguard_interfaces.is_empty());
        assert!(state.wireguard_peers.is_empty());
    }

    #[test]
    fn skips_a_link_whose_peer_has_no_public_key_yet() {
        let node_configs = vec![
            node_config("hq", Ipv4Addr::new(0, 0, 0, 1), None, Some("hq-pub")),
            node_config("fra", Ipv4Addr::new(0, 0, 0, 2), None, None), // public_key not computed yet
        ];
        let links = vec![ready_link("hq", "fra", 51820)];
        let state = desired_state(
            &own(),
            65062,
            IPV4_NET,
            IPV6_NET,
            &node_configs,
            &links,
            &[],
        )
        .unwrap();
        assert!(state.wireguard_interfaces.is_empty());
    }

    #[test]
    fn ignores_a_link_this_node_is_not_a_party_to() {
        let node_configs = vec![
            node_config("fra", Ipv4Addr::new(0, 0, 0, 2), None, Some("fra-pub")),
            node_config("lon", Ipv4Addr::new(0, 0, 0, 3), None, Some("lon-pub")),
        ];
        let links = vec![ready_link("fra", "lon", 51820)];
        let state = desired_state(
            &own(),
            65062,
            IPV4_NET,
            IPV6_NET,
            &node_configs,
            &links,
            &[],
        )
        .unwrap();
        assert!(state.wireguard_interfaces.is_empty());
    }

    #[test]
    fn physically_connected_prefixes_become_bgp_networks_alongside_own_loopback() {
        let prefixes = vec!["192.168.252.0/24".to_string(), "not-a-cidr".to_string()];
        let state = desired_state(&own(), 65062, IPV4_NET, IPV6_NET, &[], &[], &prefixes).unwrap();
        assert_eq!(state.bgp_networks.len(), 2);
        assert!(
            state
                .bgp_networks
                .iter()
                .any(|n| n.address == "192.168.252.0/24")
        );
        assert!(state.bgp_networks.iter().any(|n| n.address == "10.62.0.1"));
        assert!(
            state
                .bgp_networks
                .iter()
                .all(|n| n.list == BGP_NETWORKS_LIST)
        );
    }

    #[test]
    fn bgp_connections_exclude_self_and_include_every_other_node_over_ipv6_loopbacks() {
        let node_configs = vec![
            node_config("hq", Ipv4Addr::new(0, 0, 0, 1), None, Some("hq-pub")),
            node_config("fra", Ipv4Addr::new(0, 0, 0, 2), None, Some("fra-pub")),
            node_config("lon", Ipv4Addr::new(0, 0, 0, 3), None, Some("lon-pub")),
        ];
        let state =
            desired_state(&own(), 65062, IPV4_NET, IPV6_NET, &node_configs, &[], &[]).unwrap();
        assert_eq!(state.bgp_connections.len(), 2);
        let fra = state
            .bgp_connections
            .iter()
            .find(|c| c.name == "bgp-2")
            .unwrap();
        assert_eq!(fra.remote_address, "fd00::2".parse::<Ipv6Addr>().unwrap());
        assert_eq!(fra.local_address, "fd00::1".parse::<Ipv6Addr>().unwrap());
        assert!(fra.multihop);
        assert_eq!(fra.afi, "ip");
        assert!(state.bgp_connections.iter().any(|c| c.name == "bgp-3"));
        assert!(!state.bgp_connections.iter().any(|c| c.name == "bgp-1"));
    }
}
