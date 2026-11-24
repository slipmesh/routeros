//! Pure "compute what this RouterOS device should look like" logic - translates the node's
//! `AwgConfig`/`RouterConfig` into RouterOS's own tables. Touches neither the `slipmesh` reader nor
//! `mikrotik_rs`: I/O stays in thin shims, the logic that decides anything stays here.

use crate::diff::{
    DesiredAddressListEntry, DesiredBfdConfiguration, DesiredBgpConnection, DesiredBgpInstance,
    DesiredBridge, DesiredIpAddress, DesiredIpv6Address, DesiredListMember, DesiredOspfArea,
    DesiredOspfInstance, DesiredOspfInterfaceTemplate, DesiredWireguardInterface,
    DesiredWireguardPeer,
};
use crate::sanitize::validate_endpoint;
use sliplib_config::awg::{AwgConfig, InterfaceEntry, PeerEntry};
use sliplib_config::router::{ROUTER_LOOPBACK, RouterConfig};
use sliplib_net::{IpNet, Ipv4Net, Ipv6Net};
use std::collections::BTreeSet;

pub const LAN_LIST: &str = "LAN";
/// Version-neutral name (was `"default-v2"` under OSPFv2) - the `version` field alone now
/// distinguishes the instance; see `mikrotik.rs::apply_ospf_instance`'s doc comment on the
/// in-place `2 -> 3` transition this rename anticipates.
pub const OSPF_INSTANCE: &str = "default";
pub const OSPF_AREA: &str = "backbone";
pub const BGP_INSTANCE: &str = "default";
pub const BGP_NETWORKS_LIST: &str = "bgp-networks";
const OSPF_PEER_COST: u16 = 10;
const OSPF_HELLO_INTERVAL: &str = "10s";
const OSPF_DEAD_INTERVAL: &str = "40s";
/// RouterOS 7.20+'s explicit AFI selector for a BGP connection - without it, a session negotiates
/// `afi=ipv6` only and a peer expecting an RFC 8950 IPv4-over-IPv6 session drops it.
const BGP_AFI_IPV4: &str = "ip";

/// A link to a `routeros` node is `wireguard`, whose keepalive is one number. `0` is desired as
/// none: the device reads the two back alike.
fn keepalive_seconds(interface: &InterfaceEntry, peer: &PeerEntry) -> Option<u16> {
    Some(interface.keepalive_of(peer).lo()).filter(|&seconds| seconds != 0)
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
    /// Empty unless the mesh asked for BFD. RouterOS forbids any session not covered by an
    /// entry here, so this is what permits the ones `use-bfd` asks OSPF to consult.
    pub bfd_configurations: Vec<DesiredBfdConfiguration>,
    pub bgp_networks: Vec<DesiredAddressListEntry>,
    pub bgp_instance: DesiredBgpInstance,
    pub bgp_connections: Vec<DesiredBgpConnection>,
}

/// Never advertised: none of these is a LAN prefix to hand out via SLAAC RA.
///
/// `auto-link-local=no` on a manual link-local makes it replace the address RouterOS generates for
/// the interface; left at the default `yes`, the generated one comes back next to it on every boot
/// and OSPFv3 may bind to that instead, advertising a next hop the other end of the link does not
/// consider on-link. RouterOS refuses the flag on any other address, so there it stays unset.
fn own_ipv6_address(address: Ipv6Net, interface: &str) -> DesiredIpv6Address {
    DesiredIpv6Address {
        address: address.to_string(),
        interface: interface.to_string(),
        advertise: false,
        auto_link_local: address.addr().is_unicast_link_local().then_some(false),
        disabled: false,
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
    physically_connected: &[(String, Ipv4Net)],
) -> anyhow::Result<DesiredState> {
    let loopbacks = router.node.loopback_addresses;
    let (own_loopback, own_ipv6_loopback) = (loopbacks.ipv4.0.addr(), loopbacks.ipv6.0.addr());

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
            mtu: iface.mtu,
        });
        list_members.push(DesiredListMember {
            list: LAN_LIST.to_string(),
            interface: iface.name.clone(),
            disabled: false,
        });
        // `iface.addresses` is applied verbatim rather than left to RouterOS's own link-local
        // generation: with a second mesh interface, generation gives every interface the identical
        // address, and duplicate address detection marks every one past the first `invalid`. With
        // `addressing.tunnel.ipv4` an IPv4 address comes with the link-local, without which
        // masquerade has no source address on a mesh interface.
        for address in &iface.addresses {
            match address.0 {
                IpNet::V6(address) => mesh_link_locals.push(own_ipv6_address(address, &iface.name)),
                IpNet::V4(address) => mesh_ipv4_addresses.push(DesiredIpAddress {
                    address: address.to_string(),
                    interface: iface.name.clone(),
                    disabled: false,
                }),
            }
        }

        for peer in &iface.peers {
            let (endpoint_address, endpoint_port, persistent_keepalive) = match &peer.endpoint {
                Some(endpoint) => {
                    let (host, port) = parse_endpoint(endpoint)?;
                    let keepalive = keepalive_seconds(iface, peer);
                    (Some(host), Some(port), keepalive)
                }
                // NAT'd peer with no reachable endpoint: no Endpoint/PersistentKeepalive, wait for
                // it to initiate the handshake and roam in.
                None => (None, None, None),
            };
            wireguard_peers.push(DesiredWireguardPeer {
                interface: iface.name.clone(),
                // sliplib names every peer it renders.
                name: peer.name.clone().unwrap_or_default(),
                public_key_b64: peer.public_key.clone(),
                allowed_address: peer
                    .allowed_ips_or_all()
                    .iter()
                    .map(|prefix| prefix.0.to_string())
                    .collect::<Vec<_>>()
                    .join(","),
                endpoint_address,
                endpoint_port,
                persistent_keepalive,
                disabled: false,
            });
        }
    }

    let mut ip_addresses = vec![DesiredIpAddress {
        address: format!("{own_loopback}/32"),
        interface: ROUTER_LOOPBACK.to_string(),
        disabled: false,
    }];
    ip_addresses.extend(mesh_ipv4_addresses);
    // Mesh interfaces' own link-locals (`mesh_link_locals`, built above from `iface.addresses`)
    // join the loopback's addresses in the same table.
    let mut ip_v6_addresses = vec![own_ipv6_address(own_ipv6_loopback.into(), ROUTER_LOOPBACK)];
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
    if let Some(link_local) = mesh_link_locals.first() {
        ip_v6_addresses.push(DesiredIpv6Address {
            interface: ROUTER_LOOPBACK.to_string(),
            ..link_local.clone()
        });
    }
    ip_v6_addresses.extend(mesh_link_locals);

    // The loopback is passive - it has no neighbour, so nothing to check the liveness of.
    let mut ospf_interface_templates = vec![DesiredOspfInterfaceTemplate {
        interfaces: ROUTER_LOOPBACK.to_string(),
        area: OSPF_AREA.to_string(),
        type_: None,
        cost: None,
        hello_interval: None,
        dead_interval: None,
        passive: true,
        use_bfd: false,
        disabled: false,
    }];
    let mesh_names: Vec<&str> = awg.interfaces.iter().map(|i| i.name.as_str()).collect();
    let mut matched_mesh: Vec<&str> = Vec::new();
    for pattern in &router.ospf_interfaces {
        if pattern.is_router_loopback() {
            continue; // already covered by the unconditional passive loopback template above
        }
        for name in &mesh_names {
            if pattern.matches(name) && !matched_mesh.contains(name) {
                matched_mesh.push(name);
            }
        }
    }
    for name in &matched_mesh {
        ospf_interface_templates.push(DesiredOspfInterfaceTemplate {
            interfaces: (*name).to_string(),
            area: OSPF_AREA.to_string(),
            type_: Some("ptp".to_string()),
            cost: Some(OSPF_PEER_COST),
            hello_interval: Some(OSPF_HELLO_INTERVAL.to_string()),
            dead_interval: Some(OSPF_DEAD_INTERVAL.to_string()),
            passive: false,
            use_bfd: router.bfd.is_some(),
            disabled: false,
        });
    }

    // One entry per mesh interface rather than one listing them all: it mirrors the templates
    // above, and RouterOS evaluates these in order, so overlapping entries would make which one
    // applies depend on their arrangement.
    let bfd_configurations: Vec<DesiredBfdConfiguration> = match &router.bfd {
        Some(bfd) => matched_mesh
            .iter()
            .map(|name| DesiredBfdConfiguration {
                interfaces: (*name).to_string(),
                min_rx: format!("{}ms", bfd.min_rx_ms),
                min_tx: format!("{}ms", bfd.min_tx_ms),
                multiplier: u16::from(bfd.multiplier),
            })
            .collect(),
        None => Vec::new(),
    };

    // Announce set: physically-connected prefixes on an interface matching `direct_interfaces`,
    // physically-connected prefixes falling inside a `learn` range, and literal `announce` entries
    // - the node's three announcement sources. Own loopback /32 is always announced on top,
    // independent of these fields - every mesh node's own loopback must stay reachable via RFC 8950
    // regardless of what it declares as "directly connected".
    let mut bgp_network_addrs: BTreeSet<String> = BTreeSet::new();
    for (iface, prefix) in physically_connected {
        let direct = router
            .direct_interfaces
            .iter()
            .any(|pattern| pattern.matches(iface));
        let learned = router.learn.iter().any(|range| range.0.contains(prefix));
        if direct || learned {
            bgp_network_addrs.insert(prefix.to_string());
        }
    }
    for entry in &router.announce {
        bgp_network_addrs.insert(entry.net.0.to_string());
    }
    bgp_network_addrs.insert(format!("{own_loopback}/32"));
    // RouterOS's `ip firewall address-list` echoes a host-only entry back without its `/32`
    // suffix (a written "198.51.100.1/32" reads back as "198.51.100.1") - strip it
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
        let remote_address = peer.address;
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
            name: ROUTER_LOOPBACK.to_string(),
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
        bfd_configurations,
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
    use crate::test_support::wg_key;
    use sliplib_config::Range;
    use sliplib_config::awg::{InterfaceEntry, PeerEntry};
    use sliplib_config::router::{BgpPeerEntry, NodeIdentity};
    use std::net::{Ipv4Addr, Ipv6Addr};

    fn connected(list: &[(&str, &str)]) -> Vec<(String, Ipv4Net)> {
        list.iter()
            .map(|(iface, prefix)| ((*iface).to_owned(), prefix.parse().unwrap()))
            .collect()
    }

    fn router_config() -> RouterConfig {
        RouterConfig {
            node: NodeIdentity {
                loopback_addresses: sliplib_yaml::from_str(r#"["198.51.100.1/32", "3fff::1/128"]"#)
                    .unwrap(),
            },
            bgp_as: 65062,
            bgp_peers: vec![],
            ospf_interfaces: vec![],
            direct_interfaces: vec![],
            learn: vec![],
            announce: vec![],
            bypass: None,
            bfd: None,
        }
    }

    fn iface(name: &str, port: u16) -> InterfaceEntry {
        InterfaceEntry {
            name: name.to_string(),
            listen_port: port,
            addresses: vec![],
            private_key: wg_key("own").into(),
            obfuscation: Default::default(),
            mtu: None,
            peers: vec![],
        }
    }

    fn peer(key_label: &str, endpoint: Option<&str>) -> PeerEntry {
        PeerEntry {
            public_key: wg_key(key_label),
            name: Some(key_label.to_owned()),
            endpoint: endpoint.map(str::to_string),
            allowed_ips: None,
            persistent_keepalive: None,
        }
    }

    /// Both halves are asserted together because either alone does nothing: RouterOS forbids a
    /// session with no `/routing/bfd/configuration` entry covering it, and an entry nothing
    /// consults is never used. The loopback is excluded on purpose - it has no neighbour.
    #[test]
    fn bfd_configures_and_requests_only_the_mesh_interfaces_and_only_when_asked() {
        let awg = AwgConfig {
            interfaces: vec![iface("mesh-2", 51820)],
        };
        let mut router = router_config();
        router.ospf_interfaces = sliplib_yaml::from_str(r#"["mesh-*"]"#).unwrap();

        router.bfd = Some(sliplib_config::router::BfdSettings {
            min_rx_ms: 500,
            ..Default::default()
        });
        let on = desired_state(&awg, &router, &[]).unwrap();
        assert_eq!(on.bfd_configurations.len(), 1);
        assert_eq!(on.bfd_configurations[0].interfaces, "mesh-2");
        assert_eq!(on.bfd_configurations[0].min_rx, "500ms");
        assert_eq!(on.bfd_configurations[0].min_tx, "300ms");
        assert_eq!(on.bfd_configurations[0].multiplier, 5);
        for t in &on.ospf_interface_templates {
            assert_eq!(
                t.use_bfd,
                t.interfaces != ROUTER_LOOPBACK,
                "{}",
                t.interfaces
            );
        }

        router.bfd = None;
        let off = desired_state(&awg, &router, &[]).unwrap();
        assert!(off.bfd_configurations.is_empty());
        assert!(off.ospf_interface_templates.iter().all(|t| !t.use_bfd));
    }

    #[test]
    fn an_interface_gets_one_ospf_template_however_many_patterns_take_it_and_none_if_none_does() {
        let awg = AwgConfig {
            interfaces: vec![iface("mesh-2", 51820), iface("wg-3", 51821)],
        };
        let mut router = router_config();
        router.ospf_interfaces = sliplib_yaml::from_str(r#"["mesh-*", "mesh-2"]"#).unwrap();
        let state = desired_state(&awg, &router, &[]).unwrap();
        let templates: Vec<&str> = state
            .ospf_interface_templates
            .iter()
            .map(|t| t.interfaces.as_str())
            .collect();
        assert_eq!(templates, [ROUTER_LOOPBACK, "mesh-2"]);
    }

    #[test]
    fn always_includes_the_loopback_addresses_and_singletons() {
        let state = desired_state(&AwgConfig::default(), &router_config(), &[]).unwrap();
        assert_eq!(state.ip_addresses.len(), 1);
        assert_eq!(state.ip_addresses[0].address, "198.51.100.1/32");
        assert_eq!(state.ip_addresses[0].interface, ROUTER_LOOPBACK);
        assert_eq!(state.ip_v6_addresses.len(), 1);
        assert_eq!(state.ip_v6_addresses[0].address, "3fff::1/128");
        assert!(!state.ip_v6_addresses[0].advertise);
        assert_eq!(state.loopback_bridge.name, ROUTER_LOOPBACK);
        assert_eq!(state.ospf_instance.version, 3);
        assert_eq!(
            state.ospf_instance.router_id,
            Ipv4Addr::new(198, 51, 100, 1)
        );
        assert_eq!(state.bgp_instance.as_number, 65062);
        assert_eq!(state.ospf_interface_templates.len(), 1);
        assert!(state.ospf_interface_templates[0].passive);
        assert_eq!(state.bgp_networks.len(), 1);
        assert_eq!(state.bgp_networks[0].address, "198.51.100.1");
    }

    #[test]
    fn a_wireguard_interface_takes_the_mtu_its_awg_interface_has() {
        let mut with_mtu = iface("mesh-2", 51820);
        with_mtu.mtu = Some(1440);
        let awg = AwgConfig {
            interfaces: vec![with_mtu, iface("mesh-3", 51821)],
        };
        let state = desired_state(&awg, &router_config(), &[]).unwrap();
        let mtus: Vec<_> = state.wireguard_interfaces.iter().map(|i| i.mtu).collect();
        assert_eq!(mtus, [Some(1440), None]);
    }

    #[test]
    fn wireguard_interface_and_peer_with_an_endpoint() {
        let mut i = iface("mesh-2", 51820);
        i.peers
            .push(peer("east-pub", Some("east.example.com:51820")));
        let awg = AwgConfig {
            interfaces: vec![i],
        };
        let mut router = router_config();
        router.ospf_interfaces = sliplib_yaml::from_str(r#"["mesh-*"]"#).unwrap();
        let state = desired_state(&awg, &router, &[]).unwrap();

        assert_eq!(state.wireguard_interfaces.len(), 1);
        assert_eq!(state.wireguard_interfaces[0].name, "mesh-2");
        assert_eq!(state.wireguard_interfaces[0].listen_port, 51820);
        assert_eq!(
            state.wireguard_interfaces[0].private_key_b64.expose(),
            wg_key("own")
        );

        assert_eq!(state.wireguard_peers.len(), 1);
        let p = &state.wireguard_peers[0];
        assert_eq!(p.public_key_b64, wg_key("east-pub"));
        assert_eq!(p.name, "east-pub");
        assert_eq!(p.endpoint_address, Some("east.example.com".to_string()));
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
    fn mesh_interface_addresses_are_applied_as_the_awg_config_gives_them() {
        let mut i1 = iface("mesh-2", 51820);
        i1.addresses = sliplib_yaml::from_str(r#"["fe80::c612:ff/64"]"#).unwrap();
        let mut i2 = iface("mesh-3", 51821);
        i2.addresses = sliplib_yaml::from_str(r#"["fe80::c612:ff/64"]"#).unwrap(); // same literal, different interface
        let awg = AwgConfig {
            interfaces: vec![i1, i2],
        };
        let state = desired_state(&awg, &router_config(), &[]).unwrap();

        // Loopback bridge's own /128, the same link-local copied onto the loopback bridge (OSPFv3
        // needs one there to originate an Intra-Area-Prefix-LSA - see desired_state), plus one
        // entry per mesh interface: the identical literal is applied to both.
        assert_eq!(state.ip_v6_addresses.len(), 4);
        assert!(
            state
                .ip_v6_addresses
                .iter()
                .any(|a| a.interface == ROUTER_LOOPBACK && a.address == "fe80::c612:ff/64")
        );
        assert!(
            state.ip_v6_addresses.iter().any(|a| a.interface == "mesh-2"
                && a.address == "fe80::c612:ff/64"
                && !a.advertise)
        );
        assert!(
            state.ip_v6_addresses.iter().any(|a| a.interface == "mesh-3"
                && a.address == "fe80::c612:ff/64"
                && !a.advertise)
        );
    }

    /// With `auto-link-local=yes` RouterOS keeps generating its own link-local next to ours after
    /// every boot, and OSPFv3 on the mesh can bind to that one instead. RouterOS refuses the flag
    /// on any other address ("selected address is not link local"), so the loopback ULA leaves it
    /// unset.
    #[test]
    fn link_locals_replace_the_generated_one_and_the_ula_leaves_the_flag_unset() {
        let mut i = iface("mesh-2", 51820);
        i.addresses = sliplib_yaml::from_str(r#"["fe80::c612:ff/64"]"#).unwrap();
        let awg = AwgConfig {
            interfaces: vec![i],
        };
        let state = desired_state(&awg, &router_config(), &[]).unwrap();

        assert_eq!(state.ip_v6_addresses.len(), 3);
        for a in &state.ip_v6_addresses {
            let expected = a.address.starts_with("fe80:").then_some(false);
            assert_eq!(
                a.auto_link_local, expected,
                "{} on {}",
                a.address, a.interface
            );
        }
    }

    #[test]
    fn mesh_interface_ipv4_tunnel_address_becomes_a_desired_ip_address() {
        // `addressing.tunnel.ipv4`: a mesh interface can carry a v4 entry alongside its
        // link-local(s) - the fix for NAT/MASQUERADE
        // otherwise having no valid source address when service_subnet traffic egresses via one.
        let mut i = iface("mesh-2", 51820);
        i.addresses =
            sliplib_yaml::from_str(r#"["fe80::c612:ff/64", "198.51.100.255/32"]"#).unwrap();
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
                .any(|a| a.interface == "mesh-2" && a.address == "198.51.100.255/32")
        );
        // The v6 entry still goes to ip_v6_addresses, not ip_addresses - loopback /128, the
        // loopback bridge's copy of the link-local, and the mesh interface's own.
        assert_eq!(state.ip_v6_addresses.len(), 3);
    }

    /// The keepalive desired for the one peer of an interface, at `endpoint` with its entry's
    /// keepalive `set`.
    fn keepalive_desired(
        endpoint: Option<&str>,
        set: Option<Range<u16>>,
    ) -> anyhow::Result<Option<u16>> {
        let mut i = iface("mesh-2", 51820);
        i.peers.push(PeerEntry {
            persistent_keepalive: set,
            ..peer("east-pub", endpoint)
        });
        let awg = AwgConfig {
            interfaces: vec![i],
        };
        Ok(desired_state(&awg, &router_config(), &[])?.wireguard_peers[0].persistent_keepalive)
    }

    const DIALED: Option<&str> = Some("192.0.2.2:51820");

    fn keepalive_of_a_dialed_peer(set: Range<u16>) -> anyhow::Result<Option<u16>> {
        keepalive_desired(DIALED, Some(set))
    }

    #[test]
    fn a_dialed_peer_takes_the_keepalive_its_entry_sets() {
        assert_eq!(keepalive_of_a_dialed_peer(10.into()).unwrap(), Some(10));
    }

    // RouterOS reads back a keepalive of 0 as it reads back none: desired as either, it would be
    // set again at every run.
    #[test]
    fn a_dialed_peer_whose_entry_sends_no_keepalive_desires_none() {
        assert_eq!(keepalive_of_a_dialed_peer(0.into()).unwrap(), None);
    }

    #[test]
    fn nat_peer_with_no_endpoint_gets_no_endpoint_or_keepalive() {
        let mut i = iface("mesh-3", 51821);
        i.peers.push(peer("west-pub", None));
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
    fn malformed_endpoint_is_an_error() {
        let mut i = iface("mesh-2", 51820);
        i.peers.push(peer("east-pub", Some("no-port-here")));
        let awg = AwgConfig {
            interfaces: vec![i],
        };
        assert!(desired_state(&awg, &router_config(), &[]).is_err());
    }

    #[test]
    fn direct_interfaces_glob_selects_which_physically_connected_prefixes_are_announced() {
        let mut router = router_config();
        router.direct_interfaces = sliplib_yaml::from_str(r#"["ether*"]"#).unwrap();
        let physically_connected =
            connected(&[("ether1", "203.0.113.0/27"), ("wan0", "192.0.2.0/24")]);
        let state = desired_state(&AwgConfig::default(), &router, &physically_connected).unwrap();
        assert!(
            state
                .bgp_networks
                .iter()
                .any(|n| n.address == "203.0.113.0/27")
        );
        assert!(
            !state
                .bgp_networks
                .iter()
                .any(|n| n.address == "192.0.2.0/24")
        );
    }

    #[test]
    fn a_learn_range_selects_only_prefixes_inside_it() {
        let mut router = router_config();
        router.learn = sliplib_yaml::from_str(r#"["203.0.113.5/26", "203.0.113.96/28"]"#).unwrap();
        let physically_connected = connected(&[
            ("cni0", "203.0.113.32/27"),
            ("cni1", "203.0.113.64/27"),
            ("cni2", "203.0.113.96/27"),
        ]);
        let state = desired_state(&AwgConfig::default(), &router, &physically_connected).unwrap();
        let announced_prefixes: Vec<&str> = state
            .bgp_networks
            .iter()
            .map(|n| n.address.as_str())
            .filter(|address| address.contains('/'))
            .collect();
        assert_eq!(announced_prefixes, ["203.0.113.32/27"]);
    }

    #[test]
    fn announce_entries_are_always_included_regardless_of_live_state() {
        let mut router = router_config();
        router.announce.push(sliplib_config::router::AnnounceEntry {
            net: sliplib_yaml::from_str(r#""203.0.113.192/26""#).unwrap(),
            label: None,
        });
        let state = desired_state(&AwgConfig::default(), &router, &[]).unwrap();
        assert!(
            state
                .bgp_networks
                .iter()
                .any(|n| n.address == "203.0.113.192/26")
        );
    }

    #[test]
    fn bgp_connections_map_one_to_one_from_bgp_peers_over_ipv6_loopbacks() {
        let mut router = router_config();
        router.bgp_peers = vec![
            BgpPeerEntry {
                name: "node-h".to_string(),
                address: "3fff::2".parse().unwrap(),
            },
            BgpPeerEntry {
                name: "node-d".to_string(),
                address: "3fff::3".parse().unwrap(),
            },
        ];
        let state = desired_state(&AwgConfig::default(), &router, &[]).unwrap();
        assert_eq!(state.bgp_connections.len(), 2);
        let east = state
            .bgp_connections
            .iter()
            .find(|c| c.name == "bgp-node-h")
            .unwrap();
        assert_eq!(east.remote_address, "3fff::2".parse::<Ipv6Addr>().unwrap());
        assert_eq!(east.local_address, "3fff::1".parse::<Ipv6Addr>().unwrap());
        assert!(east.multihop);
        assert_eq!(east.afi, "ip");
    }
}
