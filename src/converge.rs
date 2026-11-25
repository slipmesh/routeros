//! Reads, diffs, and (unless `--check`) applies every RouterOS table of one run, in a fixed order.
//! The steps are generic over the table; what decides is in `diff.rs` and `mikrotik.rs`.
//!
//! Order - dependency-correct, and remove-before-add within each table (`mikrotik::commands`):
//! 1. `interface list member` stale removal (before any interface is deleted).
//! 2. `interface wireguard` (exclusive).
//! 3. `interface bridge` (loopback, singleton) - before its own address can be set.
//! 4. `ip address` (the loopback `/32`, and a mesh interface's tunnel IPv4 when the config has one).
//! 5. `ipv6 address` (loopback ULA `/128` and the link-locals - independent of step 4, order
//!    between the two doesn't matter).
//! 6. `interface wireguard peers` (exclusive).
//! 7. `interface list member` add/update (after interfaces exist).
//! 8. `routing ospf instance` (singleton).
//! 9. `routing ospf area` (singleton).
//! 10. `routing bfd configuration` (exclusive) - before the templates that ask OSPF to consult
//!     it, since RouterOS forbids any session no entry here covers.
//! 11. `routing ospf interface-template` (exclusive).
//! 12. `ip firewall address-list` (`bgp-networks`).
//! 13. `routing bgp instance` (singleton).
//! 14. `routing bgp connection` (exclusive).

use crate::config::DesiredState;
use crate::diff::{self, CurrentWireguardInterface, DesiredWireguardInterface, Plan};
use crate::mikrotik::{
    self, BfdConfigurations, BgpConnections, BgpInstance, BgpNetworks, IpAddresses, Ipv6Addresses,
    Keyed, ListMembers, LoopbackBridge, OspfArea, OspfInstance, OspfInterfaceTemplates, Singleton,
    WireguardInterfaces, WireguardPeers,
};
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
    /// Counts the plan's adds and updates and records a line for each.
    fn record_changes<D: std::fmt::Debug>(&mut self, table: &str, plan: &Plan<D>) {
        self.added += plan.add.len();
        self.updated += plan.update.len();
        for d in &plan.add {
            self.diff_lines.push(format!("+ {table}: {d:?}"));
        }
        for (id, d) in &plan.update {
            self.diff_lines.push(format!("~ {table} ({id}): {d:?}"));
        }
    }

    /// [`Self::record_changes`], then the removals. `current` is the same slice the caller just
    /// diffed against - used to resolve a `Plan::remove` id back to the actual row being removed,
    /// so `- table (*C)` in `--diff` output becomes `- table: CurrentWireguardInterface { name:
    /// "mesh-node-g", ... }` instead of an opaque RouterOS internal id nobody can act on without a
    /// separate device query.
    fn record<C: crate::diff::HasId + std::fmt::Debug, D: std::fmt::Debug>(
        &mut self,
        table: &str,
        current: &[C],
        plan: &Plan<D>,
    ) {
        self.record_changes(table, plan);
        self.removed += plan.remove.len();
        for id in &plan.remove {
            match current.iter().find(|c| c.id() == id) {
                Some(c) => self.diff_lines.push(format!("- {table}: {c:?}")),
                None => self.diff_lines.push(format!("- {table} ({id})")),
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

/// The interfaces of the links: those asked for, and those `interface wireguard` holds, which only
/// this tool writes.
fn our_interfaces(
    asked: &[DesiredWireguardInterface],
    held: &[CurrentWireguardInterface],
) -> Vec<String> {
    asked
        .iter()
        .map(|interface| &interface.name)
        .chain(held.iter().map(|interface| &interface.name))
        .cloned()
        .collect()
}

fn plan_of<T: Keyed>(
    report: &mut ConvergeReport,
    current: &[T::Current],
    desired: &[T::Desired],
) -> Plan<T::Desired> {
    let plan = T::plan(current, desired);
    report.record(T::NAME, current, &plan);
    plan
}

async fn write<T: Keyed>(
    device: &MikrotikDevice,
    current: &[T::Current],
    plan: &Plan<T::Desired>,
    apply: bool,
) -> anyhow::Result<()> {
    if apply {
        mikrotik::send(device, T::PATH, &T::commands(current, plan)).await?;
    }
    Ok(())
}

/// Reads, diffs, records and (if `apply`) writes one table, given the interfaces that are ours.
async fn step<T: Keyed>(
    device: &MikrotikDevice,
    report: &mut ConvergeReport,
    ours: &[String],
    desired: &[T::Desired],
    apply: bool,
) -> anyhow::Result<()> {
    let current = mikrotik::read::<T>(device, ours).await?;
    let plan = plan_of::<T>(report, &current, desired);
    write::<T>(device, &current, &plan, apply).await
}

/// The same for the one row of a singleton table called `name`.
async fn singleton_step<T: Singleton>(
    device: &MikrotikDevice,
    report: &mut ConvergeReport,
    name: &str,
    desired: &T::Desired,
    apply: bool,
) -> anyhow::Result<()> {
    let current = mikrotik::read_singleton::<T>(device, name).await?;
    let plan = diff::singleton(current.as_ref(), desired);
    report.record_changes(T::NAME, &plan);
    if apply {
        mikrotik::send(device, T::PATH, &mikrotik::commands::<T>(&plan)).await?;
    }
    Ok(())
}

/// Reads, diffs, and (if `apply`) applies every RouterOS table in the order above. `apply =
/// false` (i.e. `--check`) still performs every read/diff step - a real connection is required
/// either way - it just sends no write. Returns a full report either way, so `--diff` prints the
/// same thing whether or not `--check` is also set.
pub async fn run(
    device: &MikrotikDevice,
    desired: &DesiredState,
    apply: bool,
) -> anyhow::Result<ConvergeReport> {
    let mut report = ConvergeReport::default();

    // Read before step 1, so that the members of an interface step 2 deletes go in the same run.
    let current_wg = mikrotik::read::<WireguardInterfaces>(device, &[]).await?;
    let ours = our_interfaces(&desired.wireguard_interfaces, &current_wg);

    // 1. Pre-cleanup: stale `interface list member` rows, before any interface deletion.
    let current_members = mikrotik::read::<ListMembers>(device, &ours).await?;
    let members = plan_of::<ListMembers>(&mut report, &current_members, &desired.list_members);
    write::<ListMembers>(device, &current_members, &only_remove(&members), apply).await?;

    // 2. interface wireguard (exclusive).
    let wg =
        plan_of::<WireguardInterfaces>(&mut report, &current_wg, &desired.wireguard_interfaces);
    write::<WireguardInterfaces>(device, &current_wg, &wg, apply).await?;

    // 3. interface bridge (loopback, singleton) - before its own address can be set.
    let bridge = &desired.loopback_bridge;
    singleton_step::<LoopbackBridge>(device, &mut report, &bridge.name, bridge, apply).await?;

    // 4. ip address (the loopback /32, and the mesh interfaces' tunnel IPv4 if any).
    let mut our_ifaces = ours.clone();
    our_ifaces.push(bridge.name.clone());
    step::<IpAddresses>(
        device,
        &mut report,
        &our_ifaces,
        &desired.ip_addresses,
        apply,
    )
    .await?;

    // 5. ipv6 address (loopback ULA /128 and the link-locals of the loopback and the links'
    // interfaces).
    step::<Ipv6Addresses>(
        device,
        &mut report,
        &our_ifaces,
        &desired.ip_v6_addresses,
        apply,
    )
    .await?;

    // 6. interface wireguard peers (exclusive).
    step::<WireguardPeers>(device, &mut report, &[], &desired.wireguard_peers, apply).await?;

    // 7. interface list member add/update (after interfaces exist; remove already done in step 1).
    write::<ListMembers>(device, &current_members, &only_add_update(&members), apply).await?;

    // 8-9. routing ospf instance / ospf area (singletons).
    let instance = &desired.ospf_instance;
    singleton_step::<OspfInstance>(device, &mut report, &instance.name, instance, apply).await?;
    let area = &desired.ospf_area;
    singleton_step::<OspfArea>(device, &mut report, &area.name, area, apply).await?;

    // 10. routing bfd configuration (exclusive) - before the templates that ask for it.
    step::<BfdConfigurations>(device, &mut report, &[], &desired.bfd_configurations, apply).await?;

    // 11. routing ospf interface-template (exclusive).
    let templates = &desired.ospf_interface_templates;
    step::<OspfInterfaceTemplates>(device, &mut report, &[], templates, apply).await?;

    // 12. ip firewall address-list (bgp-networks).
    step::<BgpNetworks>(device, &mut report, &[], &desired.bgp_networks, apply).await?;

    // 13. routing bgp instance (singleton).
    let bgp = &desired.bgp_instance;
    singleton_step::<BgpInstance>(device, &mut report, &bgp.name, bgp, apply).await?;

    // 14. routing bgp connection (exclusive).
    step::<BgpConnections>(device, &mut report, &[], &desired.bgp_connections, apply).await?;

    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::wg_key;

    fn row(pairs: &[(&str, &str)]) -> mikrotik::Row {
        pairs
            .iter()
            .map(|(key, value)| (key.to_string(), Some(value.to_string())))
            .collect()
    }

    #[test]
    fn what_lies_on_an_interface_only_the_device_still_holds_goes_in_one_run() {
        let held = CurrentWireguardInterface {
            id: "*1".to_owned(),
            name: "mesh-gone".to_owned(),
            listen_port: 51820,
            private_key_b64: wg_key("own").into(),
            disabled: false,
            mtu: None,
        };
        let ours = our_interfaces(&[], &[held]);

        let member = row(&[(".id", "*2"), ("list", "LAN"), ("interface", "mesh-gone")]);
        let members = mikrotik::footprint::<ListMembers>(&[member], &ours).unwrap();
        assert_eq!(crate::diff::list_members(&members, &[]).remove, ["*2"]);

        let address = row(&[
            (".id", "*3"),
            ("address", "198.51.100.9/32"),
            ("interface", "mesh-gone"),
        ]);
        let addresses = mikrotik::footprint::<IpAddresses>(&[address], &ours).unwrap();
        assert_eq!(crate::diff::ip_addresses(&addresses, &[]).remove, ["*3"]);
    }

    #[test]
    fn a_plan_is_recorded_as_its_counts_and_one_line_per_row() {
        let ip = |address: &str| crate::diff::DesiredIpAddress {
            address: address.to_owned(),
            interface: "router-lo".to_owned(),
            disabled: false,
        };
        let held = crate::diff::CurrentIpAddress {
            id: "*3".to_owned(),
            address: "192.0.2.3/32".to_owned(),
            interface: "router-lo".to_owned(),
            disabled: false,
        };
        let plan = Plan {
            add: vec![ip("192.0.2.1/32")],
            update: vec![("*2".to_owned(), ip("192.0.2.2/32"))],
            remove: vec!["*3".to_owned(), "*9".to_owned()],
        };
        let mut report = ConvergeReport::default();
        report.record("ip address", &[held], &plan);
        assert_eq!((report.added, report.updated, report.removed), (1, 1, 2));
        assert_eq!(
            report.diff_lines,
            [
                r#"+ ip address: DesiredIpAddress { address: "192.0.2.1/32", interface: "router-lo", disabled: false }"#,
                r#"~ ip address (*2): DesiredIpAddress { address: "192.0.2.2/32", interface: "router-lo", disabled: false }"#,
                r#"- ip address: CurrentIpAddress { id: "*3", address: "192.0.2.3/32", interface: "router-lo", disabled: false }"#,
                "- ip address (*9)",
            ]
        );
    }
}
