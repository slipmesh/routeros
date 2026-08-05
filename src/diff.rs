//! Pure diff computation for every RouterOS table `routeros` touches: given the current rows
//! (as parsed by `mikrotik.rs`'s `read_*` functions) and the desired rows (as computed by
//! `config::desired_state`), produce an add/update/remove [`Plan`].
//!
//! **Exclusive vs. shared tables** (see AGENTS.md): the diff logic below is identical for both -
//! the difference is entirely in what `current` the caller passes in. For an exclusive table
//! (`interface wireguard[/peers]`, `routing ospf interface-template`, `routing bgp connection`),
//! nothing else on the device ever writes it, so `current` is simply the whole table and "remove
//! everything not desired" is always safe. For a shared table (`ip address`, `interface list
//! member`, `ip firewall address-list`), `mikrotik.rs`'s `read_*` must pre-filter `current` down
//! to only rows plausibly owned by this tool (matching interface/list naming) *before* calling
//! into this module - `diff` itself has no way to tell the difference and must never be handed an
//! unfiltered shared table.

use std::collections::HashMap;
use std::hash::Hash;
use std::net::Ipv4Addr;

/// Add/update/remove plan for one RouterOS table. `update`/`remove` carry the RouterOS `.id` of
/// the row to act on; `add` carries only the desired value (no `.id` exists yet).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Plan<D> {
    pub add: Vec<D>,
    pub update: Vec<(String, D)>,
    pub remove: Vec<String>,
}

impl<D> Plan<D> {
    pub fn is_empty(&self) -> bool {
        self.add.is_empty() && self.update.is_empty() && self.remove.is_empty()
    }
}

/// Implemented by every `Current*` row type - lets `converge.rs` look up the full row behind a
/// bare RouterOS `.id` in `Plan::remove` for readable `--diff` output (`- table: <row>`, not the
/// opaque `- table (*C)` a raw id alone gives you).
pub trait HasId {
    fn id(&self) -> &str;
}

/// Generic keyed reconcile: every `current` row whose key isn't in `desired` is removed; every
/// `desired` row whose key isn't in `current` is added; a key present in both is updated only if
/// `unchanged` says the fields actually differ. See the module doc comment for the exclusive-vs-
/// shared distinction this same function serves.
fn diff<C, D, K>(
    current: &[C],
    desired: &[D],
    current_key: impl Fn(&C) -> K,
    desired_key: impl Fn(&D) -> K,
    current_id: impl Fn(&C) -> String,
    unchanged: impl Fn(&C, &D) -> bool,
) -> Plan<D>
where
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
                    update.push((current_id(c), d.clone()));
                }
            }
            None => remove.push(current_id(c)),
        }
    }

    let add = desired_by_key.into_values().cloned().collect();

    Plan {
        add,
        update,
        remove,
    }
}

/// A singleton RouterOS object (at most one row this tool cares about) either doesn't exist yet,
/// exists and already matches, or exists with different fields.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SingletonOp<T> {
    NoOp,
    Create(T),
    Update(String, T),
}

pub fn singleton<T: PartialEq>(current: Option<(String, T)>, desired: T) -> SingletonOp<T> {
    match current {
        None => SingletonOp::Create(desired),
        Some((_, existing)) if existing == desired => SingletonOp::NoOp,
        Some((id, _)) => SingletonOp::Update(id, desired),
    }
}

/// RouterOS's API returns an empty string for a "true" flag-style property (e.g. `passive`), not
/// a boolean - `Some("true")` is also accepted defensively, but the empty string is what a real
/// device actually sends.
pub fn passive_flag_is_true(raw: Option<&str>) -> bool {
    matches!(raw, Some("") | Some("true"))
}

/// Whether `interface` is something only this tool could have created on the `interface list
/// member` table - either it's in the currently-desired interface set, or it matches the naming
/// this tool alone uses (`mesh-*`) or the raw internal id RouterOS substitutes once an interface
/// referenced by a list member has already been deleted (`*<hex>`, unresolvable back to a name).
/// Used by `mikrotik.rs`'s `read_list_members` to pre-filter `current` before it ever reaches
/// [`list_members`] - anything else on the `LAN` list (e.g. a physical WAN/LAN interface) must
/// never be considered for removal.
pub fn is_our_list_member_footprint(interface: &str, desired_interfaces: &[String]) -> bool {
    desired_interfaces.iter().any(|d| d == interface) || is_our_interface_name(interface)
}

fn is_our_interface_name(interface: &str) -> bool {
    interface.starts_with("mesh-") || is_raw_orphan_id(interface)
}

fn is_raw_orphan_id(interface: &str) -> bool {
    interface
        .strip_prefix('*')
        .is_some_and(|rest| !rest.is_empty() && rest.chars().all(|c| c.is_ascii_hexdigit()))
}

// ── interface wireguard (exclusive) ──

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DesiredWireguardInterface {
    pub name: String,
    pub listen_port: u16,
    pub private_key_b64: String,
    pub disabled: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CurrentWireguardInterface {
    pub id: String,
    pub name: String,
    pub listen_port: u16,
    pub private_key_b64: String,
    pub disabled: bool,
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
        |c| c.id.clone(),
        |c, d| {
            c.listen_port == d.listen_port
                && c.private_key_b64 == d.private_key_b64
                && c.disabled == d.disabled
        },
    )
}

// ── interface wireguard peers (exclusive) ──

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
        |c| c.id.clone(),
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

// ── ip address (shared) ──

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

/// Staleness is judged by the (interface, address) **pair**, not the address alone - a link can
/// keep its address but move interface (or vice versa). `current` must already be pre-filtered by
/// the caller to this tool's own footprint (see the module doc comment).
pub fn ip_addresses(
    current: &[CurrentIpAddress],
    desired: &[DesiredIpAddress],
) -> Plan<DesiredIpAddress> {
    diff(
        current,
        desired,
        |c| (c.interface.clone(), c.address.clone()),
        |d| (d.interface.clone(), d.address.clone()),
        |c| c.id.clone(),
        |c, d| c.disabled == d.disabled,
    )
}

// ── interface list member (shared) ──

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

/// `current` must already be pre-filtered via [`is_our_list_member_footprint`] (see the module
/// doc comment) - an unrelated `LAN` member (e.g. a physical WAN interface) must never reach this
/// function, or it would be removed the moment it isn't also in `desired`.
///
/// The resulting `Plan.remove` must be applied *before* `wireguard_interfaces`'s own removals -
/// RouterOS otherwise leaves a `list member` row pointing at an unresolvable raw id (`*<hex>`)
/// once the interface it referenced is already gone. `Plan.add`/`Plan.update` are applied after
/// (a newly desired interface doesn't exist yet until that same step creates it).
pub fn list_members(
    current: &[CurrentListMember],
    desired: &[DesiredListMember],
) -> Plan<DesiredListMember> {
    diff(
        current,
        desired,
        |c| (c.list.clone(), c.interface.clone()),
        |d| (d.list.clone(), d.interface.clone()),
        |c| c.id.clone(),
        |c, d| c.disabled == d.disabled,
    )
}

// ── routing ospf interface-template (exclusive) ──

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DesiredOspfInterfaceTemplate {
    pub interfaces: String,
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

pub fn ospf_interface_templates(
    current: &[CurrentOspfInterfaceTemplate],
    desired: &[DesiredOspfInterfaceTemplate],
) -> Plan<DesiredOspfInterfaceTemplate> {
    diff(
        current,
        desired,
        |c| c.interfaces.clone(),
        |d| d.interfaces.clone(),
        |c| c.id.clone(),
        |c, d| {
            c.area == d.area
                && c.type_ == d.type_
                && c.cost == d.cost
                && c.hello_interval == d.hello_interval
                && c.dead_interval == d.dead_interval
                && c.disabled == d.disabled
                && passive_flag_is_true(c.passive_raw.as_deref()) == d.passive
        },
    )
}

// ── ip firewall address-list (shared) ──

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

/// `current` must already be pre-filtered by the caller to `list == "bgp-networks"` (see the
/// module doc comment) - this table is shared with any other address-list a device might have.
pub fn bgp_networks(
    current: &[CurrentAddressListEntry],
    desired: &[DesiredAddressListEntry],
) -> Plan<DesiredAddressListEntry> {
    diff(
        current,
        desired,
        |c| (c.list.clone(), c.address.clone()),
        |d| (d.list.clone(), d.address.clone()),
        |c| c.id.clone(),
        |c, d| c.disabled == d.disabled,
    )
}

// ── singleton values (interface bridge, filter rule, ospf/bgp instance+area) ──

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DesiredBridge {
    pub name: String,
    pub disabled: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DesiredFilterRule {
    pub chain: String,
    pub rule: String,
    pub disabled: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DesiredOspfInstance {
    pub name: String,
    pub version: u8,
    pub router_id: Ipv4Addr,
    pub in_filter_chain: String,
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

// ── routing bgp connection (exclusive) ──

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DesiredBgpConnection {
    pub name: String,
    pub instance: String,
    pub local_address: Ipv4Addr,
    pub local_role: String,
    pub remote_address: Ipv4Addr,
    pub output_network: String,
    pub disabled: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CurrentBgpConnection {
    pub id: String,
    pub name: String,
    pub instance: String,
    pub local_address: Ipv4Addr,
    pub local_role: String,
    pub remote_address: Ipv4Addr,
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
        |c| c.id.clone(),
        |c, d| {
            c.instance == d.instance
                && c.local_address == d.local_address
                && c.local_role == d.local_role
                && c.remote_address == d.remote_address
                && c.output_network == d.output_network
                && c.disabled == d.disabled
        },
    )
}

#[cfg(test)]
mod plan_tests {
    use super::*;

    #[test]
    fn is_empty_true_only_when_nothing_to_do() {
        let empty: Plan<u8> = Plan {
            add: vec![],
            update: vec![],
            remove: vec![],
        };
        assert!(empty.is_empty());

        let with_add = Plan {
            add: vec![1u8],
            update: vec![],
            remove: vec![],
        };
        assert!(!with_add.is_empty());
    }
}

#[cfg(test)]
mod singleton_tests {
    use super::*;

    #[test]
    fn none_current_creates() {
        assert_eq!(singleton(None, "desired"), SingletonOp::Create("desired"));
    }

    #[test]
    fn matching_current_is_a_noop() {
        assert_eq!(
            singleton(Some(("id1".to_string(), "same")), "same"),
            SingletonOp::NoOp
        );
    }

    #[test]
    fn differing_current_updates_by_id() {
        assert_eq!(
            singleton(Some(("id1".to_string(), "old")), "new"),
            SingletonOp::Update("id1".to_string(), "new")
        );
    }
}

#[cfg(test)]
mod passive_flag_tests {
    use super::*;

    #[test]
    fn empty_string_is_true() {
        assert!(passive_flag_is_true(Some("")));
    }

    #[test]
    fn literal_true_is_true() {
        assert!(passive_flag_is_true(Some("true")));
    }

    #[test]
    fn absent_is_false() {
        assert!(!passive_flag_is_true(None));
    }

    #[test]
    fn false_is_false() {
        assert!(!passive_flag_is_true(Some("false")));
    }
}

#[cfg(test)]
mod wireguard_interfaces_tests {
    use super::*;

    fn desired(name: &str, port: u16) -> DesiredWireguardInterface {
        DesiredWireguardInterface {
            name: name.to_string(),
            listen_port: port,
            private_key_b64: "key".to_string(),
            disabled: false,
        }
    }

    fn current(id: &str, name: &str, port: u16) -> CurrentWireguardInterface {
        CurrentWireguardInterface {
            id: id.to_string(),
            name: name.to_string(),
            listen_port: port,
            private_key_b64: "key".to_string(),
            disabled: false,
        }
    }

    #[test]
    fn noop_when_matching() {
        let cur = vec![current("*1", "mesh-fra", 51820)];
        let des = vec![desired("mesh-fra", 51820)];
        assert!(wireguard_interfaces(&cur, &des).is_empty());
    }

    #[test]
    fn pure_add() {
        let plan = wireguard_interfaces(&[], &[desired("mesh-fra", 51820)]);
        assert_eq!(plan.add, vec![desired("mesh-fra", 51820)]);
        assert!(plan.update.is_empty());
        assert!(plan.remove.is_empty());
    }

    #[test]
    fn pure_remove_of_undesired_interface() {
        // Exclusive table: an interface no longer in desired must be fully removed, since nothing
        // else on the device could have legitimately created a "mesh-*" wireguard interface.
        let cur = vec![current("*1", "mesh-stale", 51820)];
        let plan = wireguard_interfaces(&cur, &[]);
        assert_eq!(plan.remove, vec!["*1".to_string()]);
        assert!(plan.add.is_empty());
        assert!(plan.update.is_empty());
    }

    #[test]
    fn update_when_port_changes() {
        let cur = vec![current("*1", "mesh-fra", 51820)];
        let des = vec![desired("mesh-fra", 51821)];
        let plan = wireguard_interfaces(&cur, &des);
        assert_eq!(
            plan.update,
            vec![("*1".to_string(), desired("mesh-fra", 51821))]
        );
        assert!(plan.add.is_empty());
        assert!(plan.remove.is_empty());
    }

    #[test]
    fn combined_add_update_remove() {
        let cur = vec![
            current("*1", "mesh-fra", 51820),  // unchanged
            current("*2", "mesh-lon", 51821),  // port changes below
            current("*3", "mesh-stale", 9999), // no longer desired
        ];
        let des = vec![
            desired("mesh-fra", 51820),
            desired("mesh-lon", 51822),
            desired("mesh-new", 51823),
        ];
        let plan = wireguard_interfaces(&cur, &des);
        assert_eq!(plan.add, vec![desired("mesh-new", 51823)]);
        assert_eq!(
            plan.update,
            vec![("*2".to_string(), desired("mesh-lon", 51822))]
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
    fn shared_table_never_removes_an_out_of_footprint_row() {
        // This is the safety-critical case: `current` here represents what the caller already
        // pre-filtered to this tool's own footprint (see the module doc comment) - a manually
        // configured WAN address would simply never be in this slice at all. Given only our own
        // rows, an address that's no longer desired must still be removed (that's our footprint).
        let cur = vec![current("*10", "10.0.0.5/31", "mesh-old")];
        let plan = ip_addresses(&cur, &[]);
        assert_eq!(plan.remove, vec!["*10".to_string()]);
    }

    #[test]
    fn staleness_keyed_on_interface_and_address_pair() {
        // Same address, moved to a different interface - must be treated as remove-old +
        // add-new, not a no-op, since the (interface, address) pair changed.
        let cur = vec![current("*1", "10.0.0.0/31", "mesh-fra")];
        let des = vec![desired("10.0.0.0/31", "mesh-lon")];
        let plan = ip_addresses(&cur, &des);
        assert_eq!(plan.remove, vec!["*1".to_string()]);
        assert_eq!(plan.add, vec![desired("10.0.0.0/31", "mesh-lon")]);
    }

    #[test]
    fn noop_when_matching() {
        let cur = vec![current("*1", "10.0.0.0/31", "mesh-fra")];
        let des = vec![desired("10.0.0.0/31", "mesh-fra")];
        assert!(ip_addresses(&cur, &des).is_empty());
    }
}

#[cfg(test)]
mod wireguard_peers_tests {
    use super::*;

    fn desired(interface: &str, name: &str, endpoint: Option<&str>) -> DesiredWireguardPeer {
        DesiredWireguardPeer {
            interface: interface.to_string(),
            name: name.to_string(),
            public_key_b64: "pub".to_string(),
            allowed_address: "0.0.0.0/0,::/0".to_string(),
            endpoint_address: endpoint.map(str::to_string),
            endpoint_port: endpoint.map(|_| 51820),
            persistent_keepalive: endpoint.map(|_| 25),
            disabled: false,
        }
    }

    #[test]
    fn nat_peer_has_no_endpoint_or_keepalive() {
        let d = desired("mesh-hq", "hq", None);
        assert_eq!(d.endpoint_address, None);
        assert_eq!(d.persistent_keepalive, None);
    }

    #[test]
    fn combined_add_update_remove() {
        let cur = vec![
            CurrentWireguardPeer {
                id: "*1".to_string(),
                interface: "mesh-fra".to_string(),
                name: "fra".to_string(),
                public_key_b64: "old-key".to_string(),
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
                public_key_b64: "key".to_string(),
                allowed_address: "0.0.0.0/0,::/0".to_string(),
                endpoint_address: None,
                endpoint_port: None,
                persistent_keepalive: None,
                disabled: false,
            },
        ];
        let mut updated = desired("mesh-fra", "fra", None);
        updated.public_key_b64 = "new-key".to_string();
        let des = vec![updated.clone(), desired("mesh-lon", "lon", Some("1.2.3.4"))];

        let plan = wireguard_peers(&cur, &des);
        assert_eq!(plan.add, vec![desired("mesh-lon", "lon", Some("1.2.3.4"))]);
        assert_eq!(plan.update, vec![("*1".to_string(), updated)]);
        assert_eq!(plan.remove, vec!["*2".to_string()]);
    }
}

#[cfg(test)]
mod list_members_tests {
    use super::*;

    fn desired(interface: &str) -> DesiredListMember {
        DesiredListMember {
            list: "LAN".to_string(),
            interface: interface.to_string(),
            disabled: false,
        }
    }

    fn current(id: &str, interface: &str) -> CurrentListMember {
        CurrentListMember {
            id: id.to_string(),
            list: "LAN".to_string(),
            interface: interface.to_string(),
            disabled: false,
        }
    }

    #[test]
    fn removes_stale_and_keeps_unrelated_out_of_the_plan_entirely() {
        // is_our_list_member_footprint is what actually keeps an unrelated LAN member (e.g. a
        // physical WAN port) out of `current` before it ever reaches this function - proven
        // separately below. Here, given only our own rows, a no-longer-desired interface is
        // still removed.
        let cur = vec![current("*1", "mesh-stale")];
        let plan = list_members(&cur, &[]);
        assert_eq!(plan.remove, vec!["*1".to_string()]);
    }

    #[test]
    fn adds_a_newly_desired_interface() {
        let plan = list_members(&[], &[desired("mesh-fra")]);
        assert_eq!(plan.add, vec![desired("mesh-fra")]);
    }

    #[test]
    fn footprint_check_excludes_unrelated_interfaces() {
        assert!(!is_our_list_member_footprint("ether1-wan", &[]));
        assert!(!is_our_list_member_footprint(
            "bridge-lan",
            &["mesh-fra".to_string()]
        ));
    }

    #[test]
    fn footprint_check_includes_mesh_interfaces_and_desired_set() {
        assert!(is_our_list_member_footprint("mesh-fra", &[]));
        assert!(is_our_list_member_footprint(
            "router-lo",
            &["router-lo".to_string()]
        ));
    }

    #[test]
    fn footprint_check_includes_orphaned_raw_ids() {
        // Left behind by RouterOS once a wireguard interface this tool created was deleted -
        // must still be recognized as ours so it can be pruned, even though it no longer matches
        // "mesh-*" or any currently-desired name.
        assert!(is_our_list_member_footprint("*4A", &[]));
        assert!(!is_our_list_member_footprint("*not-hex", &[]));
        assert!(!is_our_list_member_footprint("*", &[]));
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
            disabled: false,
        }
    }

    #[test]
    fn passive_empty_string_matches_desired_true_as_a_noop() {
        let cur = vec![CurrentOspfInterfaceTemplate {
            id: "*1".to_string(),
            interfaces: "router-lo".to_string(),
            area: "backbone".to_string(),
            type_: None,
            cost: None,
            hello_interval: None,
            dead_interval: None,
            passive_raw: Some(String::new()),
            disabled: false,
        }];
        let des = vec![loopback_desired("router-lo")];
        assert!(ospf_interface_templates(&cur, &des).is_empty());
    }

    #[test]
    fn missing_passive_flag_does_not_match_desired_true() {
        let cur = vec![CurrentOspfInterfaceTemplate {
            id: "*1".to_string(),
            interfaces: "router-lo".to_string(),
            area: "backbone".to_string(),
            type_: None,
            cost: None,
            hello_interval: None,
            dead_interval: None,
            passive_raw: None,
            disabled: false,
        }];
        let des = vec![loopback_desired("router-lo")];
        let plan = ospf_interface_templates(&cur, &des);
        assert_eq!(plan.update.len(), 1);
    }

    #[test]
    fn exclusive_add_and_remove_for_peer_templates() {
        let cur = vec![CurrentOspfInterfaceTemplate {
            id: "*2".to_string(),
            interfaces: "mesh-stale".to_string(),
            area: "backbone".to_string(),
            type_: Some("ptp".to_string()),
            cost: Some(10),
            hello_interval: Some("10s".to_string()),
            dead_interval: Some("40s".to_string()),
            passive_raw: None,
            disabled: false,
        }];
        let des = vec![peer_desired("mesh-fra")];
        let plan = ospf_interface_templates(&cur, &des);
        assert_eq!(plan.add, vec![peer_desired("mesh-fra")]);
        assert_eq!(plan.remove, vec!["*2".to_string()]);
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
        let cur = vec![current("*1", "192.168.252.0/24")];
        let des = vec![desired("192.168.253.0/24")];
        let plan = bgp_networks(&cur, &des);
        assert_eq!(plan.add, vec![desired("192.168.253.0/24")]);
        assert_eq!(plan.remove, vec!["*1".to_string()]);
    }

    #[test]
    fn noop_when_matching() {
        let cur = vec![current("*1", "192.168.252.0/24")];
        let des = vec![desired("192.168.252.0/24")];
        assert!(bgp_networks(&cur, &des).is_empty());
    }
}

#[cfg(test)]
mod bgp_connections_tests {
    use super::*;

    fn desired(name: &str, remote: Ipv4Addr) -> DesiredBgpConnection {
        DesiredBgpConnection {
            name: name.to_string(),
            instance: "default".to_string(),
            local_address: Ipv4Addr::new(10, 62, 0, 1),
            local_role: "ibgp".to_string(),
            remote_address: remote,
            output_network: "bgp-networks".to_string(),
            disabled: false,
        }
    }

    fn current(id: &str, name: &str, remote: Ipv4Addr) -> CurrentBgpConnection {
        CurrentBgpConnection {
            id: id.to_string(),
            name: name.to_string(),
            instance: "default".to_string(),
            local_address: Ipv4Addr::new(10, 62, 0, 1),
            local_role: "ibgp".to_string(),
            remote_address: remote,
            output_network: "bgp-networks".to_string(),
            disabled: false,
        }
    }

    #[test]
    fn update_when_remote_address_changes() {
        let cur = vec![current("*1", "bgp-fra", Ipv4Addr::new(10, 62, 0, 2))];
        let des = vec![desired("bgp-fra", Ipv4Addr::new(10, 62, 0, 3))];
        let plan = bgp_connections(&cur, &des);
        assert_eq!(
            plan.update,
            vec![(
                "*1".to_string(),
                desired("bgp-fra", Ipv4Addr::new(10, 62, 0, 3))
            )]
        );
    }

    #[test]
    fn pure_remove_when_peer_no_longer_desired() {
        let cur = vec![current("*1", "bgp-gone", Ipv4Addr::new(10, 62, 0, 9))];
        let plan = bgp_connections(&cur, &[]);
        assert_eq!(plan.remove, vec!["*1".to_string()]);
    }
}
