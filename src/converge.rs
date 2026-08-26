//! Orchestrates the fixed, dependency-correct RouterOS convergence order for one run: read
//! current state -> diff -> (optionally) apply, table by table. Thin glue - correctness lives in
//! `diff.rs`'s tests, not here: there is no mocking framework anywhere in this ecosystem, so this
//! module's own correctness is checked in the manual live-device pass rather than by unit tests.
//!
//! Order - dependency-correct, and remove-before-add within each exclusive table:
//! 1. `interface list member` stale removal (before any interface is deleted).
//! 2. `interface wireguard` (exclusive).
//! 3. `interface bridge` (loopback, singleton) - before its own address can be set.
//! 4. `ip address` (loopback `/32` - mesh links carry no IPv4 any more, OSPFv3/RFC 8950 underlay).
//! 5. `ipv6 address` (loopback ULA `/128` - independent of step 4, order between the two doesn't
//!    matter).
//! 6. `interface wireguard peers` (exclusive).
//! 7. `interface list member` add/update (after interfaces exist).
//! 8. `routing ospf instance` (singleton).
//! 9. `routing ospf area` (singleton).
//! 10. `routing ospf interface-template` (exclusive).
//! 11. `ip firewall address-list` (`bgp-networks`).
//! 12. `routing bgp instance` (singleton).
//! 13. `routing bgp connection` (exclusive).

use crate::config::{self, DesiredState};
use crate::diff::{Plan, SingletonOp};
use crate::mikrotik;
use mikrotik_rs::MikrotikDevice;

#[derive(Debug, Default)]
pub struct ConvergeReport {
    pub added: usize,
    pub updated: usize,
    pub removed: usize,
    /// One human-readable line per add/update/remove action, across every table - what `--diff`
    /// prints. Populated identically whether or not `apply` actually ran (see [`run`]).
    pub diff_lines: Vec<String>,
}

impl ConvergeReport {
    /// `current` is the same slice the caller just diffed against - used to resolve a `Plan::
    /// remove` id back to the actual row being removed, so `- table (*C)` in `--diff` output
    /// becomes `- table: CurrentWireguardInterface { name: "mesh-node-g", ... }` instead of an
    /// opaque RouterOS internal id nobody can act on without a separate device query.
    fn record<C: crate::diff::HasId + std::fmt::Debug, D: std::fmt::Debug>(
        &mut self,
        table: &str,
        current: &[C],
        plan: &Plan<D>,
    ) {
        self.added += plan.add.len();
        self.updated += plan.update.len();
        self.removed += plan.remove.len();
        for d in &plan.add {
            self.diff_lines.push(format!("+ {table}: {d:?}"));
        }
        for (id, d) in &plan.update {
            self.diff_lines.push(format!("~ {table} ({id}): {d:?}"));
        }
        for id in &plan.remove {
            match current.iter().find(|c| c.id() == id) {
                Some(c) => self.diff_lines.push(format!("- {table}: {c:?}")),
                None => self.diff_lines.push(format!("- {table} ({id})")),
            }
        }
    }

    fn record_singleton<D: std::fmt::Debug>(&mut self, table: &str, op: &SingletonOp<D>) {
        match op {
            SingletonOp::NoOp => {}
            SingletonOp::Create(d) => {
                self.added += 1;
                self.diff_lines.push(format!("+ {table}: {d:?}"));
            }
            SingletonOp::Update(id, d) => {
                self.updated += 1;
                self.diff_lines.push(format!("~ {table} ({id}): {d:?}"));
            }
        }
    }
}

fn only_remove<D: Clone>(plan: &Plan<D>) -> Plan<D> {
    Plan {
        add: vec![],
        update: vec![],
        remove: plan.remove.clone(),
    }
}

fn only_add_update<D: Clone>(plan: &Plan<D>) -> Plan<D> {
    Plan {
        add: plan.add.clone(),
        update: plan.update.clone(),
        remove: vec![],
    }
}

async fn apply_singleton<D: Clone>(
    op: SingletonOp<D>,
    apply: bool,
    do_apply: impl AsyncFnOnce(SingletonOp<D>) -> anyhow::Result<()>,
) -> anyhow::Result<()> {
    if apply { do_apply(op).await } else { Ok(()) }
}

/// Reads, diffs, and (if `apply`) applies every RouterOS table in the order above. `apply =
/// false` (i.e. `--check`) still performs every read/diff step - a real connection is required
/// either way - it just skips every `apply_*` call. Returns a full report either way, so `--diff`
/// prints the same thing whether or not `--check` is also set.
pub async fn run(
    device: &MikrotikDevice,
    desired: &DesiredState,
    apply: bool,
) -> anyhow::Result<ConvergeReport> {
    let mut report = ConvergeReport::default();

    // 1. Pre-cleanup: stale `interface list member` rows, before any interface deletion.
    let desired_ifaces: Vec<String> = desired
        .wireguard_interfaces
        .iter()
        .map(|i| i.name.clone())
        .collect();
    let current_list_members = mikrotik::read_list_members(device, &desired_ifaces).await?;
    let list_member_plan = crate::diff::list_members(&current_list_members, &desired.list_members);
    report.record(
        "interface list member",
        &current_list_members,
        &list_member_plan,
    );
    let remove_only = only_remove(&list_member_plan);
    if apply && !remove_only.is_empty() {
        mikrotik::apply_list_members(device, &remove_only).await?;
    }

    // 2. interface wireguard (exclusive).
    let current_wg = mikrotik::read_wireguard_interfaces(device).await?;
    let wg_plan = crate::diff::wireguard_interfaces(&current_wg, &desired.wireguard_interfaces);
    report.record("interface wireguard", &current_wg, &wg_plan);
    if apply && !wg_plan.is_empty() {
        mikrotik::apply_wireguard_interfaces(device, &wg_plan).await?;
    }

    // 3. interface bridge (loopback, singleton) - before its own address can be set.
    let current_bridge =
        mikrotik::read_loopback_bridge(device, &desired.loopback_bridge.name).await?;
    let bridge_op = crate::diff::singleton(current_bridge, desired.loopback_bridge.clone());
    report.record_singleton("interface bridge", &bridge_op);
    apply_singleton(bridge_op, apply, async |op| {
        mikrotik::apply_loopback_bridge(device, op).await
    })
    .await?;

    // 4. ip address (loopback /32 - mesh links carry no IPv4 any more).
    let mut our_ifaces = desired_ifaces.clone();
    our_ifaces.push(desired.loopback_bridge.name.clone());
    let current_addrs = mikrotik::read_ip_addresses(device, &our_ifaces).await?;
    let addr_plan = crate::diff::ip_addresses(&current_addrs, &desired.ip_addresses);
    report.record("ip address", &current_addrs, &addr_plan);
    if apply && !addr_plan.is_empty() {
        mikrotik::apply_ip_addresses(device, &addr_plan).await?;
    }

    // 5. ipv6 address (loopback ULA /128 - mesh-* interfaces get no static IPv6, RouterOS
    // generates their link-local on its own).
    let current_v6_addrs = mikrotik::read_ipv6_addresses(device, &our_ifaces).await?;
    let v6_addr_plan = crate::diff::ipv6_addresses(&current_v6_addrs, &desired.ip_v6_addresses);
    report.record("ipv6 address", &current_v6_addrs, &v6_addr_plan);
    if apply && !v6_addr_plan.is_empty() {
        mikrotik::apply_ipv6_addresses(device, &v6_addr_plan).await?;
    }

    // 6. interface wireguard peers (exclusive).
    let current_peers = mikrotik::read_wireguard_peers(device).await?;
    let peers_plan = crate::diff::wireguard_peers(&current_peers, &desired.wireguard_peers);
    report.record("interface wireguard peers", &current_peers, &peers_plan);
    if apply && !peers_plan.is_empty() {
        mikrotik::apply_wireguard_peers(device, &peers_plan).await?;
    }

    // 7. interface list member add/update (after interfaces exist; remove already done in step 1).
    let add_update_only = only_add_update(&list_member_plan);
    if apply && !add_update_only.is_empty() {
        mikrotik::apply_list_members(device, &add_update_only).await?;
    }

    // 8-9. routing ospf instance / ospf area (singletons).
    let current_ospf_instance =
        mikrotik::read_ospf_instance(device, &desired.ospf_instance.name).await?;
    let ospf_instance_op =
        crate::diff::singleton(current_ospf_instance, desired.ospf_instance.clone());
    report.record_singleton("routing ospf instance", &ospf_instance_op);
    apply_singleton(ospf_instance_op, apply, async |op| {
        mikrotik::apply_ospf_instance(device, op).await
    })
    .await?;

    let current_ospf_area = mikrotik::read_ospf_area(device, &desired.ospf_area.name).await?;
    let ospf_area_op = crate::diff::singleton(current_ospf_area, desired.ospf_area.clone());
    report.record_singleton("routing ospf area", &ospf_area_op);
    apply_singleton(ospf_area_op, apply, async |op| {
        mikrotik::apply_ospf_area(device, op).await
    })
    .await?;

    // 10. routing ospf interface-template (exclusive).
    let current_templates = mikrotik::read_ospf_interface_templates(device).await?;
    let template_plan = crate::diff::ospf_interface_templates(
        &current_templates,
        &desired.ospf_interface_templates,
    );
    report.record(
        "routing ospf interface-template",
        &current_templates,
        &template_plan,
    );
    if apply && !template_plan.is_empty() {
        mikrotik::apply_ospf_interface_templates(device, &template_plan).await?;
    }

    // 11. ip firewall address-list (bgp-networks).
    let current_networks = mikrotik::read_bgp_networks(device, config::BGP_NETWORKS_LIST).await?;
    let networks_plan = crate::diff::bgp_networks(&current_networks, &desired.bgp_networks);
    report.record(
        "ip firewall address-list",
        &current_networks,
        &networks_plan,
    );
    if apply && !networks_plan.is_empty() {
        mikrotik::apply_bgp_networks(device, &networks_plan).await?;
    }

    // 12. routing bgp instance (singleton).
    let current_bgp_instance =
        mikrotik::read_bgp_instance(device, &desired.bgp_instance.name).await?;
    let bgp_instance_op =
        crate::diff::singleton(current_bgp_instance, desired.bgp_instance.clone());
    report.record_singleton("routing bgp instance", &bgp_instance_op);
    apply_singleton(bgp_instance_op, apply, async |op| {
        mikrotik::apply_bgp_instance(device, op).await
    })
    .await?;

    // 13. routing bgp connection (exclusive).
    let current_connections = mikrotik::read_bgp_connections(device).await?;
    let connections_plan =
        crate::diff::bgp_connections(&current_connections, &desired.bgp_connections);
    report.record(
        "routing bgp connection",
        &current_connections,
        &connections_plan,
    );
    if apply && !connections_plan.is_empty() {
        mikrotik::apply_bgp_connections(device, &connections_plan).await?;
    }

    Ok(report)
}
