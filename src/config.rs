//! Pure "compute what this RouterOS device should look like" logic - translates the
//! `talos-extensions` `AwgConfig`/`RouterConfig` (already fully resolved by `patches generate` from
//! `mesh.yaml`) into RouterOS's own tables. The RouterOS analogue of what `awg`'s own netlink
//! converger and `router::bird::render` do for a Linux node, just targeting the RouterOS API
//! instead of the kernel/a BIRD config file. Touches neither `patch::read_patch_file` nor
//! `mikrotik_rs`: I/O stays in thin shims, the logic that decides anything stays here.

use crate::cidr;
use crate::diff::{
    DesiredAddressListEntry, DesiredBgpConnection, DesiredBgpInstance, DesiredBridge,
    DesiredIpAddress, DesiredIpv6Address, DesiredListMember, DesiredOspfArea, DesiredOspfInstance,
    DesiredOspfInterfaceTemplate, DesiredWireguardInterface, DesiredWireguardPeer,
};
use crate::sanitize::validate_endpoint;
use awg::config::AwgConfig;
use router::config::RouterConfig;
use std::collections::BTreeSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

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
/// `afi=ipv6` only and a peer expecting an RFC 8950 IPv4-over-IPv6 session drops it.
const BGP_AFI_IPV4: &str = "ip";

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

/// `router.node.loopback_addresses` is exactly one IPv4 + one IPv6 CIDR (enforced by
/// `router::config::validate`, already run in `patch::read_patch_file`) - pulls both out by family.
fn own_loopbacks(router: &RouterConfig) -> anyhow::Result<(Ipv4Addr, Ipv6Addr)> {
    let mut v4 = None;
    let mut v6 = None;
    for addr in &router.node.loopback_addresses {
        let (ip, _prefix) = router::config::parse_loopback_address(addr)
            .map_err(|e| anyhow::anyhow!("invalid loopback_addresses entry {addr:?}: {e}"))?;
        match ip {
            IpAddr::V4(a) => v4 = Some(a),
            IpAddr::V6(a) => v6 = Some(a),
        }
    }
    Ok((
        v4.ok_or_else(|| anyhow::anyhow!("node.loopback_addresses has no IPv4 entry"))?,
        v6.ok_or_else(|| anyhow::anyhow!("node.loopback_addresses has no IPv6 entry"))?,
    ))
}

/// Only the suffix-`*` grammar `mesh.yaml`/`render.rs` actually produce (`"mesh-*"`) - sufficient
/// for `ospf_interfaces`/`direct_interfaces`, both fed straight into BIRD's own glob-capable
/// `interface` clause on Linux nodes. RouterOS has no equivalent daemon-level pattern engine to
/// lean on, so this tool matches locally instead.
fn glob_match(pattern: &str, name: &str) -> bool {
    match pattern.strip_suffix('*') {
        Some(prefix) => name.starts_with(prefix),
        None => pattern == name,
    }
}

fn parse_endpoint(endpoint: &str) -> anyhow::Result<(String, u16)> {
    let (host, port) = endpoint
        .rsplit_once(':')
        .ok_or_else(|| anyhow::anyhow!("{endpoint:?} is not \"host:port\""))?;
    validate_endpoint(host)?;
    let port: u16 = port
        .parse()
        .map_err(|e| anyhow::anyhow!("{endpoint:?}: invalid port: {e}"))?;
    Ok((host.to_string(), port))
}

pub fn desired_state(
    awg: &AwgConfig,
    router: &RouterConfig,
    physically_connected: &[(String, String)],
) -> anyhow::Result<DesiredState> {
    let (own_loopback, own_ipv6_loopback) = own_loopbacks(router)?;

    let mut wireguard_interfaces = Vec::new();
    let mut wireguard_peers = Vec::new();
    let mut list_members = Vec::new();
    let mut mesh_link_locals = Vec::new();
    let mut mesh_ipv4_addresses = Vec::new();

    for iface in &awg.interfaces {
        wireguard_interfaces.push(DesiredWireguardInterface {
            name: iface.name.clone(),
            listen_port: iface.listen_port,
            private_key_b64: iface.private_key.clone(),
            disabled: false,
        });
        list_members.push(DesiredListMember {
            list: LAN_LIST.to_string(),
            interface: iface.name.clone(),
            disabled: false,
        });
        // `iface.addresses` is whatever `patches generate` already computed for the Linux side,
        // reused verbatim (same per-node link-local convention as the loopback bridge's own
        // address; see `router::config`'s addressing doc comments) - applying it explicitly here
        // rather than relying on RouterOS's own auto-generation, which isn't reliable for a
        // WireGuard interface: with a single mesh interface it is fine, but once a second one
        // exists auto-generation produces the *identical* address on every interface, and
        // RouterOS's own duplicate address detection marks every one past the first `invalid`. Can carry more than one IPv6 entry now (`cluster.tunnel_networks.ipv6`, a
        // second, deliberately still link-local-scoped address - see `mesh_config::ClusterConfig::
        // tunnel_networks`'s doc comment) alongside a v4 one (`cluster.tunnel_networks.ipv4`) -
        // that v4 entry is the actual fix `tunnel_networks` exists for: a mesh-* interface
        // otherwise carries no IPv4 address at all, so NAT/MASQUERADE has nothing valid to pick as
        // a source when `service_subnet` traffic egresses via one.
        for addr in &iface.addresses {
            if addr.contains(':') {
                mesh_link_locals.push(DesiredIpv6Address {
                    address: addr.clone(),
                    interface: iface.name.clone(),
                    advertise: false,
                    disabled: false,
                });
            } else {
                mesh_ipv4_addresses.push(DesiredIpAddress {
                    address: addr.clone(),
                    interface: iface.name.clone(),
                    disabled: false,
                });
            }
        }

        for peer in &iface.peers {
            let (endpoint_address, endpoint_port, persistent_keepalive) = match &peer.endpoint {
                Some(endpoint) => {
                    let (host, port) = parse_endpoint(endpoint)?;
                    (Some(host), Some(port), Some(MESH_PERSISTENT_KEEPALIVE))
                }
                // NAT'd peer with no reachable endpoint: no Endpoint/PersistentKeepalive, wait for
                // it to initiate the handshake and roam in.
                None => (None, None, None),
            };
            wireguard_peers.push(DesiredWireguardPeer {
                interface: iface.name.clone(),
                name: iface.name.trim_start_matches("mesh-").to_string(),
                public_key_b64: peer.public_key.clone(),
                allowed_address: peer
                    .allowed_ips
                    .as_ref()
                    .map(|ips| ips.join(","))
                    .unwrap_or_else(|| "0.0.0.0/0,::/0".to_string()),
                endpoint_address,
                endpoint_port,
                persistent_keepalive,
                disabled: false,
            });
        }
    }

    let mut ip_addresses = vec![DesiredIpAddress {
        address: format!("{own_loopback}/32"),
        interface: LOOPBACK_BRIDGE.to_string(),
        disabled: false,
    }];
    ip_addresses.extend(mesh_ipv4_addresses);
    // `advertise: false`: this is a loopback identity, not a LAN prefix to hand out via SLAAC RA. Mesh interfaces' own link-locals
    // (`mesh_link_locals`, built above from `iface.addresses`) join the same table - RouterOS's own
    // auto-generated ones are actively managed away from now on (see `mikrotik.rs::
    // read_ipv6_addresses`), not left to collide.
    let mut ip_v6_addresses = vec![DesiredIpv6Address {
        address: format!("{own_ipv6_loopback}/128"),
        interface: LOOPBACK_BRIDGE.to_string(),
        advertise: false,
        disabled: false,
    }];
    // OSPFv3 runs entirely over link-local addresses, and RouterOS will not originate an
    // Intra-Area-Prefix-LSA for an interface that has none - it falls back to advertising the
    // loopback only through `redistribute=connected`, i.e. as an AS-external LSA. BIRD's kernel
    // export on the Talos side accepts intra-area OSPF routes, so an external-only advertisement
    // is learned and then never installed: every node holds a Full adjacency with this device and
    // none of them can route to its loopback, leaving its iBGP sessions down in both directions.
    // With the address present, RouterOS originates the intra-area prefix LSA and the sessions
    // come up.
    //
    // Same address the mesh interfaces carry (one link-local per node by construction, see the
    // loop above), so it is taken from there rather than recomputed - if that convention ever
    // changes, both follow it together.
    if let Some(link_local) = mesh_link_locals.first().map(|a| a.address.clone()) {
        ip_v6_addresses.push(DesiredIpv6Address {
            address: link_local,
            interface: LOOPBACK_BRIDGE.to_string(),
            advertise: false,
            disabled: false,
        });
    }
    ip_v6_addresses.extend(mesh_link_locals);

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
    let mesh_names: Vec<&str> = awg.interfaces.iter().map(|i| i.name.as_str()).collect();
    let mut matched_mesh: Vec<&str> = Vec::new();
    for pattern in &router.ospf_interfaces {
        if pattern == LOOPBACK_BRIDGE {
            continue; // already covered by the unconditional passive loopback template above
        }
        for name in &mesh_names {
            if glob_match(pattern, name) && !matched_mesh.contains(name) {
                matched_mesh.push(name);
            }
        }
    }
    for name in matched_mesh {
        ospf_interface_templates.push(DesiredOspfInterfaceTemplate {
            interfaces: name.to_string(),
            area: OSPF_AREA.to_string(),
            type_: Some("ptp".to_string()),
            cost: Some(OSPF_PEER_COST),
            hello_interval: Some(OSPF_HELLO_INTERVAL.to_string()),
            dead_interval: Some(OSPF_DEAD_INTERVAL.to_string()),
            passive: false,
            disabled: false,
        });
    }

    // Announce set: physically-connected prefixes on an interface matching `direct_interfaces`,
    // physically-connected prefixes falling inside a `learn` range, and literal `announce` entries
    // - the same three sources BIRD's own kernel-protocol export filter uses for Linux nodes (see
    // `router::bird::render`'s doc comment). Own loopback /32 is always announced on top,
    // independent of these fields - every mesh node's own loopback must stay reachable via RFC
    // 8950 regardless of what it declares as "directly connected".
    let mut bgp_network_addrs: BTreeSet<String> = BTreeSet::new();
    for (iface, prefix) in physically_connected {
        let direct = router
            .direct_interfaces
            .iter()
            .any(|pattern| glob_match(pattern, iface));
        let learned = router.learn.iter().any(|range| {
            cidr::cidr_contains(range, prefix).unwrap_or_else(|e| {
                tracing::warn!(range = %range, prefix = %prefix, error = %e, "skipping unparsable learn range/prefix");
                false
            })
        });
        if direct || learned {
            bgp_network_addrs.insert(prefix.clone());
        }
    }
    for entry in &router.announce {
        bgp_network_addrs.insert(entry.net.clone());
    }
    bgp_network_addrs.insert(format!("{own_loopback}/32"));
    // RouterOS's `ip firewall address-list` echoes a host-only entry back without its `/32`
    // suffix (a written "10.0.0.255/32" reads back as "10.0.0.255") - strip it
    // here so a /32 entry compares like with like instead of the diff perpetually
    // re-adding/removing the exact same entry.
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
    for peer in &router.bgp_peers {
        let remote_address: Ipv6Addr = peer.address.parse().map_err(|e| {
            anyhow::anyhow!(
                "bgp peer {:?}: invalid address {:?}: {e}",
                peer.name,
                peer.address
            )
        })?;
        bgp_connections.push(DesiredBgpConnection {
            name: format!("bgp-{}", peer.name),
            instance: BGP_INSTANCE.to_string(),
            local_address: own_ipv6_loopback,
            local_role: "ibgp".to_string(),
            remote_address,
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
            router_id: own_loopback,
            redistribute_connected: true,
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
            as_number: router.bgp_as,
            router_id: own_loopback,
            routing_table: "main".to_string(),
            disabled: false,
        },
        bgp_connections,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use awg::config::{InterfaceEntry, PeerEntry};
    use router::config::{BgpPeerEntry, NodeIdentity};

    fn router_config() -> RouterConfig {
        RouterConfig {
            node: NodeIdentity {
                loopback_addresses: vec!["10.62.0.1/32".to_string(), "fd00::1/128".to_string()],
            },
            bgp_as: 65062,
            bgp_peers: vec![],
            ospf_interfaces: vec![],
            direct_interfaces: vec![],
            learn: vec![],
            announce: vec![],
            bypass: None,
        }
    }

    fn iface(name: &str, port: u16) -> InterfaceEntry {
        InterfaceEntry {
            name: name.to_string(),
            listen_port: port,
            addresses: vec![],
            private_key: "own-private-key".to_string(),
            obfuscation: Default::default(),
            handshake_stale_secs: None,
            peers: vec![],
        }
    }

    fn peer(public_key: &str, endpoint: Option<&str>) -> PeerEntry {
        PeerEntry {
            public_key: public_key.to_string(),
            endpoint: endpoint.map(str::to_string),
            allowed_ips: None,
            advanced_security: false,
        }
    }

    #[test]
    fn always_includes_the_loopback_addresses_and_singletons() {
        let state = desired_state(&AwgConfig::default(), &router_config(), &[]).unwrap();
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
        assert_eq!(state.ospf_interface_templates.len(), 1);
        assert!(state.ospf_interface_templates[0].passive);
        assert_eq!(state.bgp_networks.len(), 1);
        assert_eq!(state.bgp_networks[0].address, "10.62.0.1");
    }

    #[test]
    fn wireguard_interface_and_peer_with_an_endpoint() {
        let mut i = iface("mesh-2", 51820);
        i.peers.push(peer("fra-pub", Some("fra.example.com:51820")));
        let awg = AwgConfig {
            interfaces: vec![i],
        };
        let mut router = router_config();
        router.ospf_interfaces = vec!["mesh-*".to_string()];
        let state = desired_state(&awg, &router, &[]).unwrap();

        assert_eq!(state.wireguard_interfaces.len(), 1);
        assert_eq!(state.wireguard_interfaces[0].name, "mesh-2");
        assert_eq!(state.wireguard_interfaces[0].listen_port, 51820);
        assert_eq!(
            state.wireguard_interfaces[0].private_key_b64,
            "own-private-key"
        );

        assert_eq!(state.wireguard_peers.len(), 1);
        let p = &state.wireguard_peers[0];
        assert_eq!(p.public_key_b64, "fra-pub");
        assert_eq!(p.name, "2");
        assert_eq!(p.endpoint_address, Some("fra.example.com".to_string()));
        assert_eq!(p.endpoint_port, Some(51820));
        assert_eq!(p.persistent_keepalive, Some(25));
        assert_eq!(p.allowed_address, "0.0.0.0/0,::/0");

        assert!(
            state
                .list_members
                .iter()
                .any(|m| m.interface == "mesh-2" && m.list == "LAN")
        );
        assert_eq!(state.ospf_interface_templates.len(), 2);
        assert!(
            state
                .ospf_interface_templates
                .iter()
                .any(|t| t.interfaces == "mesh-2" && t.type_.as_deref() == Some("ptp"))
        );
    }

    #[test]
    fn mesh_interface_addresses_are_applied_verbatim_from_the_patch_file() {
        let mut i1 = iface("mesh-2", 51820);
        i1.addresses = vec!["fe80::a3e:ff/64".to_string()];
        let mut i2 = iface("mesh-3", 51821);
        i2.addresses = vec!["fe80::a3e:ff/64".to_string()]; // same literal, different interface
        let awg = AwgConfig {
            interfaces: vec![i1, i2],
        };
        let state = desired_state(&awg, &router_config(), &[]).unwrap();

        // Loopback bridge's own /128, the same link-local copied onto the loopback bridge (OSPFv3
        // needs one there to originate an Intra-Area-Prefix-LSA - see desired_state), plus one
        // entry per mesh interface: the identical literal is applied to both, matching what
        // patches generate already computes for the Linux side.
        assert_eq!(state.ip_v6_addresses.len(), 4);
        assert!(
            state
                .ip_v6_addresses
                .iter()
                .any(|a| a.interface == LOOPBACK_BRIDGE && a.address == "fe80::a3e:ff/64")
        );
        assert!(
            state
                .ip_v6_addresses
                .iter()
                .any(|a| a.interface == "mesh-2" && a.address == "fe80::a3e:ff/64" && !a.advertise)
        );
        assert!(
            state
                .ip_v6_addresses
                .iter()
                .any(|a| a.interface == "mesh-3" && a.address == "fe80::a3e:ff/64" && !a.advertise)
        );
    }

    #[test]
    fn interface_with_no_addresses_gets_no_extra_ipv6_row() {
        let awg = AwgConfig {
            interfaces: vec![iface("mesh-2", 51820)],
        };
        let state = desired_state(&awg, &router_config(), &[]).unwrap();
        assert_eq!(state.ip_v6_addresses.len(), 1); // loopback bridge only
    }

    #[test]
    fn mesh_interface_ipv4_tunnel_address_becomes_a_desired_ip_address() {
        // `cluster.tunnel_networks.ipv4` (see mesh_config::ClusterConfig's doc comment): a mesh
        // interface can carry a v4 entry alongside its link-local(s) - the fix for NAT/MASQUERADE
        // otherwise having no valid source address when service_subnet traffic egresses via one.
        let mut i = iface("mesh-2", 51820);
        i.addresses = vec!["fe80::a3e:ff/64".to_string(), "10.62.1.255/32".to_string()];
        let awg = AwgConfig {
            interfaces: vec![i],
        };
        let state = desired_state(&awg, &router_config(), &[]).unwrap();

        // Loopback bridge's own /32 plus the mesh interface's tunnel v4 address.
        assert_eq!(state.ip_addresses.len(), 2);
        assert!(
            state
                .ip_addresses
                .iter()
                .any(|a| a.interface == "mesh-2" && a.address == "10.62.1.255/32")
        );
        // The v6 entry still goes to ip_v6_addresses, not ip_addresses - loopback /128, the
        // loopback bridge's copy of the link-local, and the mesh interface's own.
        assert_eq!(state.ip_v6_addresses.len(), 3);
    }

    #[test]
    fn nat_peer_with_no_endpoint_gets_no_endpoint_or_keepalive() {
        let mut i = iface("mesh-3", 51821);
        i.peers.push(peer("lon-pub", None));
        let awg = AwgConfig {
            interfaces: vec![i],
        };
        let state = desired_state(&awg, &router_config(), &[]).unwrap();

        assert_eq!(state.wireguard_peers.len(), 1);
        assert_eq!(state.wireguard_peers[0].endpoint_address, None);
        assert_eq!(state.wireguard_peers[0].endpoint_port, None);
        assert_eq!(state.wireguard_peers[0].persistent_keepalive, None);
    }

    #[test]
    fn explicit_allowed_ips_are_joined_verbatim() {
        let mut i = iface("mesh-9", 51900);
        let mut p = peer("rw-pub", None);
        p.allowed_ips = Some(vec!["10.99.0.5/32".to_string()]);
        i.peers.push(p);
        let awg = AwgConfig {
            interfaces: vec![i],
        };
        let state = desired_state(&awg, &router_config(), &[]).unwrap();
        assert_eq!(state.wireguard_peers[0].allowed_address, "10.99.0.5/32");
    }

    #[test]
    fn malformed_endpoint_is_an_error() {
        let mut i = iface("mesh-2", 51820);
        i.peers.push(peer("fra-pub", Some("no-port-here")));
        let awg = AwgConfig {
            interfaces: vec![i],
        };
        assert!(desired_state(&awg, &router_config(), &[]).is_err());
    }

    #[test]
    fn direct_interfaces_glob_selects_which_physically_connected_prefixes_are_announced() {
        let mut router = router_config();
        router.direct_interfaces = vec!["ether*".to_string()];
        let physically_connected = vec![
            ("ether1".to_string(), "192.168.88.0/24".to_string()),
            ("wan0".to_string(), "203.0.113.0/24".to_string()),
        ];
        let state = desired_state(&AwgConfig::default(), &router, &physically_connected).unwrap();
        assert!(
            state
                .bgp_networks
                .iter()
                .any(|n| n.address == "192.168.88.0/24")
        );
        assert!(
            !state
                .bgp_networks
                .iter()
                .any(|n| n.address == "203.0.113.0/24")
        );
    }

    #[test]
    fn learn_range_selects_a_physically_connected_prefix_not_matched_by_direct_interfaces() {
        let mut router = router_config();
        router.learn = vec!["10.99.0.0/16".to_string()];
        let physically_connected = vec![("cni0".to_string(), "10.99.5.0/24".to_string())];
        let state = desired_state(&AwgConfig::default(), &router, &physically_connected).unwrap();
        assert!(
            state
                .bgp_networks
                .iter()
                .any(|n| n.address == "10.99.5.0/24")
        );
    }

    #[test]
    fn announce_entries_are_always_included_regardless_of_live_state() {
        let mut router = router_config();
        router.announce.push(router::config::AnnounceEntry {
            net: "172.16.0.0/24".to_string(),
            label: None,
        });
        let state = desired_state(&AwgConfig::default(), &router, &[]).unwrap();
        assert!(
            state
                .bgp_networks
                .iter()
                .any(|n| n.address == "172.16.0.0/24")
        );
    }

    #[test]
    fn unmatched_physically_connected_prefixes_are_not_announced() {
        let mut router = router_config();
        router.direct_interfaces = vec!["ether*".to_string()];
        let physically_connected = vec![("wan0".to_string(), "203.0.113.0/24".to_string())];
        let state = desired_state(&AwgConfig::default(), &router, &physically_connected).unwrap();
        // Only own loopback is announced - the WAN prefix matches nothing.
        assert_eq!(state.bgp_networks.len(), 1);
        assert_eq!(state.bgp_networks[0].address, "10.62.0.1");
    }

    #[test]
    fn bgp_connections_map_one_to_one_from_bgp_peers_over_ipv6_loopbacks() {
        let mut router = router_config();
        router.bgp_peers = vec![
            BgpPeerEntry {
                name: "node-h".to_string(),
                address: "fd00::2".to_string(),
            },
            BgpPeerEntry {
                name: "node-d".to_string(),
                address: "fd00::3".to_string(),
            },
        ];
        let state = desired_state(&AwgConfig::default(), &router, &[]).unwrap();
        assert_eq!(state.bgp_connections.len(), 2);
        let fra = state
            .bgp_connections
            .iter()
            .find(|c| c.name == "bgp-node-h")
            .unwrap();
        assert_eq!(fra.remote_address, "fd00::2".parse::<Ipv6Addr>().unwrap());
        assert_eq!(fra.local_address, "fd00::1".parse::<Ipv6Addr>().unwrap());
        assert!(fra.multihop);
        assert_eq!(fra.afi, "ip");
    }

    #[test]
    fn invalid_bgp_peer_address_is_an_error() {
        let mut router = router_config();
        router.bgp_peers = vec![BgpPeerEntry {
            name: "bad".to_string(),
            address: "not-an-ip".to_string(),
        }];
        assert!(desired_state(&AwgConfig::default(), &router, &[]).is_err());
    }
}
