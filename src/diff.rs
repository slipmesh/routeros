//! The add/update/remove plan per RouterOS table. It removes every current row it does not want,
//! so a shared table's rows reach it only through `mikrotik::Keyed::is_ours`.

use sliplib_secrets::wireguard::PrivateKey;
use std::collections::HashMap;
use std::hash::Hash;
use std::net::{Ipv4Addr, Ipv6Addr};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Plan<D> {
    pub add: Vec<D>,
    pub update: Vec<(String, D)>,
    pub remove: Vec<String>,
}

#[cfg(test)]
impl<D> Plan<D> {
    pub fn is_empty(&self) -> bool {
        self.add.is_empty() && self.update.is_empty() && self.remove.is_empty()
    }
}

pub trait HasId {
    fn id(&self) -> &str;
}

fn diff<C, D, K>(
    current: &[C],
    desired: &[D],
    current_key: impl Fn(&C) -> K,
    desired_key: impl Fn(&D) -> K,
    unchanged: impl Fn(&C, &D) -> bool,
) -> Plan<D>
where
    C: HasId,
    D: Clone,
    K: Eq + Hash,
{
    let mut desired_by_key: HashMap<K, &D> = desired.iter().map(|d| (desired_key(d), d)).collect();

    let mut remove = Vec::new();
    let mut update = Vec::new();

    for c in current {
        match desired_by_key.remove(&current_key(c)) {
            Some(d) => {
                if !unchanged(c, d) {
                    update.push((c.id().to_owned(), d.clone()));
                }
            }
            None => remove.push(c.id().to_owned()),
        }
    }

    let add = desired_by_key.into_values().cloned().collect();

    Plan {
        add,
        update,
        remove,
    }
}

pub fn singleton<T: PartialEq + Clone>(current: Option<&(String, T)>, desired: &T) -> Plan<T> {
    let (add, update) = match current {
        None => (vec![desired.clone()], vec![]),
        Some((_, existing)) if existing == desired => (vec![], vec![]),
        Some((id, _)) => (vec![], vec![(id.clone(), desired.clone())]),
    };
    Plan {
        add,
        update,
        remove: vec![],
    }
}

/// RouterOS sends a set flag-style property (`passive`) as an empty string.
pub fn passive_flag_is_true(raw: Option<&str>) -> bool {
    matches!(raw, Some("") | Some("true"))
}

/// RouterOS leaves a raw id (`*<hex>`) in place of a deleted interface.
pub fn is_ours(interface: &str, ours: &[String]) -> bool {
    ours.iter().any(|our| our == interface) || is_raw_orphan_id(interface)
}

pub fn is_raw_orphan_id(interface: &str) -> bool {
    interface
        .strip_prefix('*')
        .is_some_and(|rest| !rest.is_empty() && rest.chars().all(|c| c.is_ascii_hexdigit()))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DesiredWireguardInterface {
    pub name: String,
    pub listen_port: u16,
    pub private_key_b64: PrivateKey,
    pub disabled: bool,
    pub mtu: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CurrentWireguardInterface {
    pub id: String,
    pub name: String,
    pub listen_port: u16,
    pub private_key_b64: PrivateKey,
    pub disabled: bool,
    pub mtu: Option<u32>,
}

impl HasId for CurrentWireguardInterface {
    fn id(&self) -> &str {
        &self.id
    }
}

pub fn wireguard_interfaces(
    current: &[CurrentWireguardInterface],
    desired: &[DesiredWireguardInterface],
) -> Plan<DesiredWireguardInterface> {
    diff(
        current,
        desired,
        |c| c.name.clone(),
        |d| d.name.clone(),
        |c, d| {
            // RouterOS reads a key back clamped: compared as text, each run would rewrite it.
            (c.listen_port, c.disabled, &c.private_key_b64)
                == (d.listen_port, d.disabled, &d.private_key_b64)
                && d.mtu.is_none_or(|mtu| c.mtu == Some(mtu))
        },
    )
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DesiredWireguardPeer {
    pub interface: String,
    pub name: String,
    pub public_key_b64: String,
    pub allowed_address: String,
    pub endpoint_address: Option<String>,
    pub endpoint_port: Option<u16>,
    pub persistent_keepalive: Option<u16>,
    pub disabled: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CurrentWireguardPeer {
    pub id: String,
    pub interface: String,
    pub name: String,
    pub public_key_b64: String,
    pub allowed_address: String,
    pub endpoint_address: Option<String>,
    pub endpoint_port: Option<u16>,
    pub persistent_keepalive: Option<u16>,
    pub disabled: bool,
}

impl HasId for CurrentWireguardPeer {
    fn id(&self) -> &str {
        &self.id
    }
}

pub fn wireguard_peers(
    current: &[CurrentWireguardPeer],
    desired: &[DesiredWireguardPeer],
) -> Plan<DesiredWireguardPeer> {
    diff(
        current,
        desired,
        |c| (c.interface.clone(), c.name.clone()),
        |d| (d.interface.clone(), d.name.clone()),
        |c, d| {
            c.public_key_b64 == d.public_key_b64
                && c.allowed_address == d.allowed_address
                && c.endpoint_address == d.endpoint_address
                && c.endpoint_port == d.endpoint_port
                && c.persistent_keepalive == d.persistent_keepalive
                && c.disabled == d.disabled
        },
    )
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DesiredIpAddress {
    pub address: String,
    pub interface: String,
    pub disabled: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CurrentIpAddress {
    pub id: String,
    pub address: String,
    pub interface: String,
    pub disabled: bool,
}

impl HasId for CurrentIpAddress {
    fn id(&self) -> &str {
        &self.id
    }
}

pub fn ip_addresses(
    current: &[CurrentIpAddress],
    desired: &[DesiredIpAddress],
) -> Plan<DesiredIpAddress> {
    diff(
        current,
        desired,
        |c| (c.interface.clone(), c.address.clone()),
        |d| (d.interface.clone(), d.address.clone()),
        |c, d| c.disabled == d.disabled,
    )
}

/// `advertise=no` keeps RouterOS from announcing the loopback's address by SLAAC RA.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DesiredIpv6Address {
    pub address: String,
    pub interface: String,
    pub advertise: bool,
    pub auto_link_local: Option<bool>,
    pub disabled: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CurrentIpv6Address {
    pub id: String,
    pub address: String,
    pub interface: String,
    pub advertise: bool,
    pub auto_link_local: bool,
    pub disabled: bool,
}

impl HasId for CurrentIpv6Address {
    fn id(&self) -> &str {
        &self.id
    }
}

pub fn ipv6_addresses(
    current: &[CurrentIpv6Address],
    desired: &[DesiredIpv6Address],
) -> Plan<DesiredIpv6Address> {
    diff(
        current,
        desired,
        |c| (c.interface.clone(), c.address.clone()),
        |d| (d.interface.clone(), d.address.clone()),
        |c, d| {
            c.advertise == d.advertise
                && d.auto_link_local.is_none_or(|v| v == c.auto_link_local)
                && c.disabled == d.disabled
        },
    )
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DesiredListMember {
    pub list: String,
    pub interface: String,
    pub disabled: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CurrentListMember {
    pub id: String,
    pub list: String,
    pub interface: String,
    pub disabled: bool,
}

impl HasId for CurrentListMember {
    fn id(&self) -> &str {
        &self.id
    }
}

pub fn list_members(
    current: &[CurrentListMember],
    desired: &[DesiredListMember],
) -> Plan<DesiredListMember> {
    diff(
        current,
        desired,
        |c| (c.list.clone(), c.interface.clone()),
        |d| (d.list.clone(), d.interface.clone()),
        |c, d| c.disabled == d.disabled,
    )
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DesiredOspfInterfaceTemplate {
    pub interfaces: String,
    pub use_bfd: bool,
    pub area: String,
    pub type_: Option<String>,
    pub cost: Option<u16>,
    pub hello_interval: Option<String>,
    pub dead_interval: Option<String>,
    pub passive: bool,
    pub disabled: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CurrentOspfInterfaceTemplate {
    pub id: String,
    pub interfaces: String,
    pub use_bfd: bool,
    pub area: String,
    pub type_: Option<String>,
    pub cost: Option<u16>,
    pub hello_interval: Option<String>,
    pub dead_interval: Option<String>,
    pub passive_raw: Option<String>,
    pub disabled: bool,
}

impl HasId for CurrentOspfInterfaceTemplate {
    fn id(&self) -> &str {
        &self.id
    }
}

/// `set` with `passive=no` leaves RouterOS's flag on, so these need an `unset`.
pub fn passive_to_unset(
    current: &[CurrentOspfInterfaceTemplate],
    plan: &Plan<DesiredOspfInterfaceTemplate>,
) -> Vec<String> {
    plan.update
        .iter()
        .filter(|(id, d)| {
            !d.passive
                && current
                    .iter()
                    .any(|c| &c.id == id && passive_flag_is_true(c.passive_raw.as_deref()))
        })
        .map(|(id, _)| id.clone())
        .collect()
}

pub fn ospf_interface_templates(
    current: &[CurrentOspfInterfaceTemplate],
    desired: &[DesiredOspfInterfaceTemplate],
) -> Plan<DesiredOspfInterfaceTemplate> {
    diff(
        current,
        desired,
        |c| c.interfaces.clone(),
        |d| d.interfaces.clone(),
        |c, d| {
            // RouterOS reads back its own defaults for fields left unset.
            c.area == d.area
                && d.type_.as_ref().is_none_or(|t| c.type_.as_ref() == Some(t))
                && d.cost.is_none_or(|v| c.cost == Some(v))
                && d.hello_interval
                    .as_ref()
                    .is_none_or(|v| c.hello_interval.as_ref() == Some(v))
                && d.dead_interval
                    .as_ref()
                    .is_none_or(|v| c.dead_interval.as_ref() == Some(v))
                && c.disabled == d.disabled
                && c.use_bfd == d.use_bfd
                && passive_flag_is_true(c.passive_raw.as_deref()) == d.passive
        },
    )
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DesiredBfdConfiguration {
    pub interfaces: String,
    /// RouterOS time literals (`300ms`), compared as text as `/print` echoes them.
    pub min_rx: String,
    pub min_tx: String,
    pub multiplier: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CurrentBfdConfiguration {
    pub id: String,
    pub interfaces: String,
    pub min_rx: Option<String>,
    pub min_tx: Option<String>,
    pub multiplier: Option<u16>,
}

impl HasId for CurrentBfdConfiguration {
    fn id(&self) -> &str {
        &self.id
    }
}

pub fn bfd_configurations(
    current: &[CurrentBfdConfiguration],
    desired: &[DesiredBfdConfiguration],
) -> Plan<DesiredBfdConfiguration> {
    diff(
        current,
        desired,
        |c| c.interfaces.clone(),
        |d| d.interfaces.clone(),
        |c, d| {
            c.min_rx.as_deref() == Some(d.min_rx.as_str())
                && c.min_tx.as_deref() == Some(d.min_tx.as_str())
                && c.multiplier == Some(d.multiplier)
        },
    )
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DesiredAddressListEntry {
    pub list: String,
    pub address: String,
    pub disabled: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CurrentAddressListEntry {
    pub id: String,
    pub list: String,
    pub address: String,
    pub disabled: bool,
}

impl HasId for CurrentAddressListEntry {
    fn id(&self) -> &str {
        &self.id
    }
}

pub fn bgp_networks(
    current: &[CurrentAddressListEntry],
    desired: &[DesiredAddressListEntry],
) -> Plan<DesiredAddressListEntry> {
    diff(
        current,
        desired,
        |c| (c.list.clone(), c.address.clone()),
        |d| (d.list.clone(), d.address.clone()),
        |c, d| c.disabled == d.disabled,
    )
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DesiredBridge {
    pub name: String,
    pub disabled: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DesiredOspfInstance {
    pub name: String,
    pub version: u8,
    pub router_id: Ipv4Addr,
    /// RouterOS' `passive` originates no prefix LSA for the loopback, so iBGP to it never comes up.
    /// Redistributing every connected route is safe: this instance is IPv6-only, and the loopback
    /// is the only interface with an IPv6 address.
    pub redistribute_connected: bool,
    pub disabled: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DesiredOspfArea {
    pub name: String,
    pub area_id: String,
    pub instance: String,
    pub disabled: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DesiredBgpInstance {
    pub name: String,
    pub as_number: u32,
    pub router_id: Ipv4Addr,
    pub routing_table: String,
    pub disabled: bool,
}

/// The loopbacks are several OSPF hops apart, so the sessions are `multihop`. Without `afi`,
/// RouterOS negotiates IPv6 only and BIRD drops the session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DesiredBgpConnection {
    pub name: String,
    pub instance: String,
    pub local_address: Ipv6Addr,
    pub local_role: String,
    pub remote_address: Ipv6Addr,
    pub multihop: bool,
    pub afi: String,
    pub output_network: String,
    pub disabled: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CurrentBgpConnection {
    pub id: String,
    pub name: String,
    pub instance: String,
    pub local_address: Ipv6Addr,
    pub local_role: String,
    pub remote_address: Ipv6Addr,
    pub multihop: bool,
    pub afi: String,
    pub output_network: String,
    pub disabled: bool,
}

impl HasId for CurrentBgpConnection {
    fn id(&self) -> &str {
        &self.id
    }
}

pub fn bgp_connections(
    current: &[CurrentBgpConnection],
    desired: &[DesiredBgpConnection],
) -> Plan<DesiredBgpConnection> {
    diff(
        current,
        desired,
        |c| c.name.clone(),
        |d| d.name.clone(),
        |c, d| {
            c.instance == d.instance
                && c.local_address == d.local_address
                && c.local_role == d.local_role
                && c.remote_address == d.remote_address
                && c.multihop == d.multihop
                && c.afi == d.afi
                && c.output_network == d.output_network
                && c.disabled == d.disabled
        },
    )
}

#[cfg(test)]
mod singleton_tests {
    use super::*;

    #[test]
    fn a_singleton_is_created_left_or_updated_by_id() {
        let plan = |add: &[&'static str], update: &[&'static str]| Plan {
            add: add.to_vec(),
            update: update.iter().map(|d| ("id1".to_string(), *d)).collect(),
            remove: vec![],
        };
        let cases = [
            (None, "desired", plan(&["desired"], &[])),
            (Some(("id1".to_string(), "same")), "same", plan(&[], &[])),
            (Some(("id1".to_string(), "old")), "new", plan(&[], &["new"])),
        ];
        for (current, desired, expected) in cases {
            assert_eq!(singleton(current.as_ref(), &desired), expected);
        }
    }
}

#[cfg(test)]
mod wireguard_interfaces_tests {
    use super::*;
    use crate::test_support::wg_key;
    use sliplib_secrets::wireguard::encode_key;

    fn desired(name: &str, port: u16) -> DesiredWireguardInterface {
        DesiredWireguardInterface {
            name: name.to_string(),
            listen_port: port,
            private_key_b64: wg_key("interface").into(),
            disabled: false,
            mtu: None,
        }
    }

    fn current(id: &str, name: &str, port: u16) -> CurrentWireguardInterface {
        CurrentWireguardInterface {
            id: id.to_string(),
            name: name.to_string(),
            listen_port: port,
            private_key_b64: wg_key("interface").into(),
            disabled: false,
            mtu: Some(1420),
        }
    }

    #[test]
    fn an_interface_is_updated_to_the_mtu_asked_for_and_left_at_its_own_otherwise() {
        let cur = vec![current("*1", "mesh-east", 51820)];
        let mut asked = desired("mesh-east", 51820);
        asked.mtu = Some(1440);
        let plan = wireguard_interfaces(&cur, std::slice::from_ref(&asked));
        assert_eq!(plan.update, vec![("*1".to_string(), asked.clone())]);
        asked.mtu = Some(1420);
        assert!(wireguard_interfaces(&cur, &[asked]).is_empty());
        assert!(wireguard_interfaces(&cur, &[desired("mesh-east", 51820)]).is_empty());
    }

    #[test]
    fn a_key_is_updated_when_it_changes_and_left_as_the_device_clamps_it() {
        let mut d = desired("mesh-east", 51820);
        d.private_key_b64 = wg_key("new").into();
        let plan = wireguard_interfaces(&[current("*1", "mesh-east", 51820)], &[d.clone()]);
        assert_eq!(plan.update.len(), 1);
        assert_eq!(plan.update[0].1, d);

        // Every bit set, as generated and as RouterOS stores it once clamped.
        let mut clamped = [0xFF; 32];
        clamped[0] = 0xF8;
        clamped[31] = 0x7F;
        d.private_key_b64 = encode_key(&[0xFF; 32]).into();
        let mut c = current("*1", "mesh-east", 51820);
        c.private_key_b64 = encode_key(&clamped).into();
        assert!(wireguard_interfaces(&[c], &[d]).is_empty());
    }

    #[test]
    fn combined_add_update_remove() {
        let cur = vec![
            current("*1", "mesh-east", 51820), // unchanged
            current("*2", "mesh-west", 51821), // port changes below
            current("*3", "mesh-stale", 9999), // no longer desired
        ];
        let des = vec![
            desired("mesh-east", 51820),
            desired("mesh-west", 51822),
            desired("mesh-new", 51823),
        ];
        let plan = wireguard_interfaces(&cur, &des);
        assert_eq!(plan.add, vec![desired("mesh-new", 51823)]);
        assert_eq!(
            plan.update,
            vec![("*2".to_string(), desired("mesh-west", 51822))]
        );
        assert_eq!(plan.remove, vec!["*3".to_string()]);
    }
}

#[cfg(test)]
mod ip_addresses_tests {
    use super::*;

    fn desired(address: &str, interface: &str) -> DesiredIpAddress {
        DesiredIpAddress {
            address: address.to_string(),
            interface: interface.to_string(),
            disabled: false,
        }
    }

    fn current(id: &str, address: &str, interface: &str) -> CurrentIpAddress {
        CurrentIpAddress {
            id: id.to_string(),
            address: address.to_string(),
            interface: interface.to_string(),
            disabled: false,
        }
    }

    #[test]
    fn an_address_moved_to_another_interface_is_removed_and_added_again() {
        let cur = vec![
            current("*1", "198.51.100.192/31", "mesh-east"),
            current("*2", "198.51.100.194/31", "mesh-north"),
        ];
        let des = vec![
            desired("198.51.100.192/31", "mesh-west"),
            desired("198.51.100.194/31", "mesh-north"),
        ];
        let plan = ip_addresses(&cur, &des);
        assert_eq!(plan.remove, vec!["*1".to_string()]);
        assert_eq!(plan.add, vec![desired("198.51.100.192/31", "mesh-west")]);
        assert!(plan.update.is_empty());
    }
}

#[cfg(test)]
mod wireguard_peers_tests {
    use super::*;
    use crate::test_support::wg_key;

    fn desired(interface: &str, name: &str, endpoint: Option<&str>) -> DesiredWireguardPeer {
        DesiredWireguardPeer {
            interface: interface.to_string(),
            name: name.to_string(),
            public_key_b64: wg_key("peer"),
            allowed_address: "0.0.0.0/0,::/0".to_string(),
            endpoint_address: endpoint.map(str::to_string),
            endpoint_port: endpoint.map(|_| 51820),
            persistent_keepalive: endpoint.map(|_| 25),
            disabled: false,
        }
    }

    #[test]
    fn combined_add_update_remove() {
        let mut unkept = desired("mesh-north", "north", Some("192.0.2.5"));
        unkept.persistent_keepalive = None;
        let cur = vec![
            CurrentWireguardPeer {
                id: "*1".to_string(),
                interface: "mesh-east".to_string(),
                name: "east".to_string(),
                public_key_b64: wg_key("old"),
                allowed_address: "0.0.0.0/0,::/0".to_string(),
                endpoint_address: None,
                endpoint_port: None,
                persistent_keepalive: None,
                disabled: false,
            },
            CurrentWireguardPeer {
                id: "*2".to_string(),
                interface: "mesh-stale".to_string(),
                name: "stale".to_string(),
                public_key_b64: wg_key("stale"),
                allowed_address: "0.0.0.0/0,::/0".to_string(),
                endpoint_address: None,
                endpoint_port: None,
                persistent_keepalive: None,
                disabled: false,
            },
            CurrentWireguardPeer {
                id: "*3".to_string(),
                interface: unkept.interface.clone(),
                name: unkept.name.clone(),
                public_key_b64: unkept.public_key_b64.clone(),
                allowed_address: unkept.allowed_address.clone(),
                endpoint_address: unkept.endpoint_address.clone(),
                endpoint_port: unkept.endpoint_port,
                persistent_keepalive: None,
                disabled: false,
            },
        ];
        let mut updated = desired("mesh-east", "east", None);
        updated.public_key_b64 = wg_key("new");
        let des = vec![
            updated.clone(),
            desired("mesh-west", "west", Some("192.0.2.4")),
            unkept,
        ];

        let plan = wireguard_peers(&cur, &des);
        assert_eq!(
            plan.add,
            vec![desired("mesh-west", "west", Some("192.0.2.4"))]
        );
        assert_eq!(plan.update, vec![("*1".to_string(), updated)]);
        assert_eq!(plan.remove, vec!["*2".to_string()]);
    }
}

#[cfg(test)]
mod list_members_tests {
    use super::*;

    #[test]
    fn footprint_check_includes_orphaned_raw_ids() {
        assert!(is_ours("*4A", &[]));
        assert!(!is_ours("*not-hex", &[]));
        assert!(!is_ours("*", &[]));
    }

    #[test]
    fn a_member_is_updated_by_its_id_only_when_disabled_differs() {
        let member = |id: &str, interface: &str, disabled| CurrentListMember {
            id: id.to_owned(),
            list: "LAN".to_owned(),
            interface: interface.to_owned(),
            disabled,
        };
        let desired = |interface: &str| DesiredListMember {
            list: "LAN".to_owned(),
            interface: interface.to_owned(),
            disabled: false,
        };
        let plan = list_members(
            &[
                member("*1", "mesh-east", true),
                member("*2", "mesh-west", false),
            ],
            &[desired("mesh-east"), desired("mesh-west")],
        );
        assert_eq!(plan.update, [("*1".to_owned(), desired("mesh-east"))]);
        assert!(plan.add.is_empty() && plan.remove.is_empty());
    }
}

#[cfg(test)]
mod ospf_interface_templates_tests {
    use super::*;

    fn loopback_desired(interfaces: &str) -> DesiredOspfInterfaceTemplate {
        DesiredOspfInterfaceTemplate {
            interfaces: interfaces.to_string(),
            area: "backbone".to_string(),
            type_: None,
            cost: None,
            hello_interval: None,
            dead_interval: None,
            passive: true,
            use_bfd: false,
            disabled: false,
        }
    }

    fn peer_desired(interfaces: &str) -> DesiredOspfInterfaceTemplate {
        DesiredOspfInterfaceTemplate {
            interfaces: interfaces.to_string(),
            area: "backbone".to_string(),
            type_: Some("ptp".to_string()),
            cost: Some(10),
            hello_interval: Some("10s".to_string()),
            dead_interval: Some("40s".to_string()),
            passive: false,
            use_bfd: false,
            disabled: false,
        }
    }

    fn current_peer(
        id: &str,
        interfaces: &str,
        passive_raw: Option<&str>,
    ) -> CurrentOspfInterfaceTemplate {
        CurrentOspfInterfaceTemplate {
            id: id.to_string(),
            interfaces: interfaces.to_string(),
            area: "backbone".to_string(),
            type_: Some("ptp".to_string()),
            cost: Some(10),
            hello_interval: Some("10s".to_string()),
            dead_interval: Some("40s".to_string()),
            passive_raw: passive_raw.map(str::to_string),
            use_bfd: false,
            disabled: false,
        }
    }

    #[test]
    fn passive_is_unset_only_where_the_device_has_it_and_desired_does_not() {
        let cur = vec![
            current_peer("*1", "mesh-a", Some("")),
            current_peer("*2", "mesh-b", None),
        ];
        let mut b = peer_desired("mesh-b");
        b.cost = Some(20);
        let des = vec![peer_desired("mesh-a"), b];
        let plan = ospf_interface_templates(&cur, &des);
        assert_eq!(plan.update.len(), 2);
        assert_eq!(passive_to_unset(&cur, &plan), vec!["*1".to_string()]);
    }

    #[test]
    fn routeros_default_values_for_unset_optional_fields_are_a_noop() {
        let cur = vec![CurrentOspfInterfaceTemplate {
            id: "*1".to_string(),
            interfaces: "router-lo".to_string(),
            area: "backbone".to_string(),
            type_: Some("broadcast".to_string()),
            cost: Some(1),
            hello_interval: Some("10s".to_string()),
            dead_interval: Some("40s".to_string()),
            passive_raw: Some(String::new()),
            use_bfd: false,
            disabled: false,
        }];
        let des = vec![loopback_desired("router-lo")];
        assert!(ospf_interface_templates(&cur, &des).is_empty());

        let mut not_passive = cur;
        not_passive[0].passive_raw = None;
        let plan = ospf_interface_templates(&not_passive, &des);
        assert_eq!(plan.update, vec![("*1".to_string(), des[0].clone())]);
    }

    #[test]
    fn turning_bfd_on_updates_the_template_rather_than_replacing_it() {
        let mut cur = vec![CurrentOspfInterfaceTemplate {
            id: "*1".to_string(),
            interfaces: "mesh-east".to_string(),
            area: "backbone".to_string(),
            type_: Some("ptp".to_string()),
            cost: Some(10),
            hello_interval: Some("10s".to_string()),
            dead_interval: Some("40s".to_string()),
            passive_raw: None,
            use_bfd: false,
            disabled: false,
        }];
        let mut des = peer_desired("mesh-east");
        des.use_bfd = true;

        let plan = ospf_interface_templates(&cur, std::slice::from_ref(&des));
        assert_eq!(plan.update.len(), 1);
        assert!(plan.add.is_empty() && plan.remove.is_empty());

        cur[0].use_bfd = true;
        assert!(ospf_interface_templates(&cur, &[des]).is_empty());
    }
}

#[cfg(test)]
mod bgp_networks_tests {
    use super::*;

    fn desired(address: &str) -> DesiredAddressListEntry {
        DesiredAddressListEntry {
            list: "bgp-networks".to_string(),
            address: address.to_string(),
            disabled: false,
        }
    }

    fn current(id: &str, address: &str) -> CurrentAddressListEntry {
        CurrentAddressListEntry {
            id: id.to_string(),
            list: "bgp-networks".to_string(),
            address: address.to_string(),
            disabled: false,
        }
    }

    #[test]
    fn combined_add_and_remove() {
        let cur = vec![
            current("*1", "203.0.113.0/27"),
            current("*2", "203.0.113.64/27"),
        ];
        let des = vec![desired("203.0.113.32/27"), desired("203.0.113.64/27")];
        let plan = bgp_networks(&cur, &des);
        assert_eq!(plan.add, vec![desired("203.0.113.32/27")]);
        assert_eq!(plan.remove, vec!["*1".to_string()]);
        assert!(plan.update.is_empty());
    }
}

#[cfg(test)]
mod bgp_connections_tests {
    use super::*;

    fn desired(name: &str, remote: Ipv6Addr) -> DesiredBgpConnection {
        DesiredBgpConnection {
            name: name.to_string(),
            instance: "default".to_string(),
            local_address: "3fff::1".parse().unwrap(),
            local_role: "ibgp".to_string(),
            remote_address: remote,
            multihop: true,
            afi: "ip".to_string(),
            output_network: "bgp-networks".to_string(),
            disabled: false,
        }
    }

    fn current(id: &str, name: &str, remote: Ipv6Addr) -> CurrentBgpConnection {
        CurrentBgpConnection {
            id: id.to_string(),
            name: name.to_string(),
            instance: "default".to_string(),
            local_address: "3fff::1".parse().unwrap(),
            local_role: "ibgp".to_string(),
            remote_address: remote,
            multihop: true,
            afi: "ip".to_string(),
            output_network: "bgp-networks".to_string(),
            disabled: false,
        }
    }

    #[test]
    fn a_changed_field_updates_the_connection_by_id() {
        let cur = vec![current("*1", "bgp-east", "3fff::2".parse().unwrap())];
        let remote = desired("bgp-east", "3fff::3".parse().unwrap());
        let mut multihop = desired("bgp-east", "3fff::2".parse().unwrap());
        multihop.multihop = false;
        for des in [remote, multihop] {
            let plan = bgp_connections(&cur, std::slice::from_ref(&des));
            assert_eq!(plan.update, vec![("*1".to_string(), des)]);
        }
    }
}

#[cfg(test)]
mod ipv6_addresses_tests {
    use super::*;

    fn is_link_local(address: &str) -> bool {
        let host = address.split_once('/').map_or(address, |(host, _)| host);
        host.parse::<std::net::Ipv6Addr>()
            .unwrap()
            .is_unicast_link_local()
    }

    fn desired(address: &str, interface: &str) -> DesiredIpv6Address {
        DesiredIpv6Address {
            address: address.to_string(),
            interface: interface.to_string(),
            advertise: false,
            auto_link_local: is_link_local(address).then_some(false),
            disabled: false,
        }
    }

    fn current(id: &str, address: &str, interface: &str) -> CurrentIpv6Address {
        CurrentIpv6Address {
            id: id.to_string(),
            address: address.to_string(),
            interface: interface.to_string(),
            advertise: false,
            auto_link_local: !is_link_local(address),
            disabled: false,
        }
    }

    #[test]
    fn an_address_is_updated_on_a_changed_flag_and_left_on_an_unset_one() {
        let loopback = current("*1", "3fff::1/128", "router-lo");
        let mut advertised = desired("3fff::1/128", "router-lo");
        advertised.advertise = true;
        let mut auto_link_local = current("*1", "fe80::ff/64", "mesh-2");
        auto_link_local.auto_link_local = true;
        let cases = [
            (loopback.clone(), advertised.clone(), Some(advertised)),
            (
                auto_link_local,
                desired("fe80::ff/64", "mesh-2"),
                Some(desired("fe80::ff/64", "mesh-2")),
            ),
            // RouterOS reports the flag on every address but takes it only on a link-local.
            (loopback, desired("3fff::1/128", "router-lo"), None),
        ];
        for (cur, des, update) in cases {
            let plan = ipv6_addresses(&[cur], &[des]);
            let update: Vec<_> = update.map(|d| ("*1".to_string(), d)).into_iter().collect();
            assert_eq!(plan.update, update);
            assert!(plan.add.is_empty() && plan.remove.is_empty());
        }
    }
}

#[cfg(test)]
mod bfd_configuration_tests {
    use super::*;

    fn desired(interfaces: &str) -> DesiredBfdConfiguration {
        DesiredBfdConfiguration {
            interfaces: interfaces.to_string(),
            min_rx: "300ms".to_string(),
            min_tx: "300ms".to_string(),
            multiplier: 5,
        }
    }

    fn current(id: &str, interfaces: &str, min_rx: &str) -> CurrentBfdConfiguration {
        CurrentBfdConfiguration {
            id: id.to_string(),
            interfaces: interfaces.to_string(),
            min_rx: Some(min_rx.to_string()),
            min_tx: Some("300ms".to_string()),
            multiplier: Some(5),
        }
    }

    #[test]
    fn an_entry_is_keyed_by_its_interface_and_updated_on_its_interval() {
        let none = Plan {
            add: vec![],
            update: vec![],
            remove: vec![],
        };
        let cases = [
            (
                current("*1", "mesh-east", "300ms"),
                "mesh-east",
                none.clone(),
            ),
            (
                current("*1", "mesh-east", "900ms"),
                "mesh-east",
                Plan {
                    update: vec![("*1".to_string(), desired("mesh-east"))],
                    ..none.clone()
                },
            ),
            (
                current("*1", "mesh-gone", "300ms"),
                "mesh-new",
                Plan {
                    add: vec![desired("mesh-new")],
                    remove: vec!["*1".to_string()],
                    ..none
                },
            ),
        ];
        for (cur, interface, plan) in cases {
            assert_eq!(bfd_configurations(&[cur], &[desired(interface)]), plan);
        }
    }
}
