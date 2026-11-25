//! Reads, diffs and, unless `--check`, writes every RouterOS table of a run, in dependency order.

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
    /// One line per add, update and remove: what `--diff` prints.
    pub diff_lines: Vec<String>,
}

impl ConvergeReport {
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

    /// `current` turns a removed id back into its row for `--diff`.
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

/// Only this tool writes `interface wireguard`, so every interface it holds is ours.
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

pub async fn run(
    device: &MikrotikDevice,
    desired: &DesiredState,
    apply: bool,
) -> anyhow::Result<ConvergeReport> {
    let mut report = ConvergeReport::default();

    // Read first, so that the members of an interface deleted below go in this run.
    let current_wg = mikrotik::read::<WireguardInterfaces>(device, &[]).await?;
    let ours = our_interfaces(&desired.wireguard_interfaces, &current_wg);

    // Members go before any interface is deleted.
    let current_members = mikrotik::read::<ListMembers>(device, &ours).await?;
    let members = plan_of::<ListMembers>(&mut report, &current_members, &desired.list_members);
    write::<ListMembers>(device, &current_members, &only_remove(&members), apply).await?;

    let wg =
        plan_of::<WireguardInterfaces>(&mut report, &current_wg, &desired.wireguard_interfaces);
    write::<WireguardInterfaces>(device, &current_wg, &wg, apply).await?;

    // The bridge goes before its own address.
    let bridge = &desired.loopback_bridge;
    singleton_step::<LoopbackBridge>(device, &mut report, &bridge.name, bridge, apply).await?;

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

    step::<Ipv6Addresses>(
        device,
        &mut report,
        &our_ifaces,
        &desired.ip_v6_addresses,
        apply,
    )
    .await?;

    step::<WireguardPeers>(device, &mut report, &[], &desired.wireguard_peers, apply).await?;

    // Members are added after the interfaces exist.
    write::<ListMembers>(device, &current_members, &only_add_update(&members), apply).await?;

    let instance = &desired.ospf_instance;
    singleton_step::<OspfInstance>(device, &mut report, &instance.name, instance, apply).await?;
    let area = &desired.ospf_area;
    singleton_step::<OspfArea>(device, &mut report, &area.name, area, apply).await?;

    // BFD goes before the templates: RouterOS refuses a BFD session no entry covers.
    step::<BfdConfigurations>(device, &mut report, &[], &desired.bfd_configurations, apply).await?;

    let templates = &desired.ospf_interface_templates;
    step::<OspfInterfaceTemplates>(device, &mut report, &[], templates, apply).await?;

    step::<BgpNetworks>(device, &mut report, &[], &desired.bgp_networks, apply).await?;

    let bgp = &desired.bgp_instance;
    singleton_step::<BgpInstance>(device, &mut report, &bgp.name, bgp, apply).await?;

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
