//! Thin RouterOS device shim: TLS connection, reading a table, and sending the commands that write
//! it. Each table states its path, how a row parses and what an `add` and a `set` send; `diff.rs`
//! decides the plan, and [`commands`] turns it into the commands. The socket I/O is checked only
//! against a live device.
//!
//! Attribute names are the ones the RouterOS API is called with here; the few not confirmed on a
//! device say so where they are read or written. A WireGuard peer's label is kept in its
//! `comment`.

use crate::credentials::RouterCredentials;
use crate::diff::{
    self, CurrentAddressListEntry, CurrentBfdConfiguration, CurrentBgpConnection, CurrentIpAddress,
    CurrentIpv6Address, CurrentListMember, CurrentOspfInterfaceTemplate, CurrentWireguardInterface,
    CurrentWireguardPeer, DesiredAddressListEntry, DesiredBfdConfiguration, DesiredBgpConnection,
    DesiredBgpInstance, DesiredBridge, DesiredIpAddress, DesiredIpv6Address, DesiredListMember,
    DesiredOspfArea, DesiredOspfInstance, DesiredOspfInterfaceTemplate, DesiredWireguardInterface,
    DesiredWireguardPeer, HasId, Plan,
};
use mikrotik_rs::proto::command::Cmd;
use mikrotik_rs::{CommandBuilder, Event, MikrotikDevice};
use sliplib_config::router::ROUTER_LOOPBACK;
use sliplib_net::Ipv4Net;
use std::collections::HashMap;
use std::fmt::Debug;
use std::net::{Ipv4Addr, Ipv6Addr};

pub(crate) type Row = HashMap<String, Option<String>>;

/// What one `add` or `set` sends, in the order sent.
pub(crate) type Attributes = Vec<(&'static str, String)>;

fn get<'a>(row: &'a Row, key: &str) -> Option<&'a str> {
    row.get(key).and_then(|v| v.as_deref())
}

fn get_required<'a>(row: &'a Row, key: &str, id: &str) -> anyhow::Result<&'a str> {
    get(row, key).ok_or_else(|| anyhow::anyhow!("row {id:?} is missing required field {key:?}"))
}

fn get_id(row: &Row) -> anyhow::Result<String> {
    get(row, ".id")
        .map(str::to_string)
        .ok_or_else(|| anyhow::anyhow!("row is missing its own .id"))
}

fn get_bool_flag(row: &Row, key: &str) -> bool {
    crate::diff::passive_flag_is_true(get(row, key))
}

/// A presence-style RouterOS flag (e.g. `passive` on `routing ospf interface-template`) round-
/// trips through the API as **key presence**, not a meaningful value - confirmed against a real
/// device: a passive row has the `passive` key present (with an empty/`None` inner value), a
/// non-passive row omits the key entirely (`row.get("passive")` and a plain `get()` can't tell
/// "present with an empty value" apart from "absent", since both collapse to `None` - this checks
/// `contains_key` instead). Normalizes to the `Some("")`/`None` shape [`crate::diff::
/// passive_flag_is_true`] already expects. Unlike `passive`, `disabled` is *not* this style - it's
/// always present with an explicit `"true"`/`"false"` string value, which [`get_bool_flag`]
/// already handles correctly.
fn get_flag_presence(row: &Row, key: &str) -> Option<String> {
    row.contains_key(key).then(String::new)
}

fn get_opt_u16(row: &Row, key: &str) -> anyhow::Result<Option<u16>> {
    get(row, key)
        .map(|v| {
            v.parse::<u16>()
                .map_err(|e| anyhow::anyhow!("field {key:?} = {v:?} is not a u16: {e}"))
        })
        .transpose()
}

/// RouterOS echoes `persistent-keepalive` back with a trailing time-unit suffix (e.g. `"25s"`),
/// even though a bare integer (interpreted as seconds) is accepted when *setting* it - confirmed
/// against a real device, this attribute's exact wire shape not having been independently
/// verified before. `hello-interval`/`dead-interval` are stored as raw strings
/// elsewhere and don't need this - only this field is modeled as a plain `u16` seconds count.
fn get_opt_keepalive_seconds(row: &Row, key: &str) -> anyhow::Result<Option<u16>> {
    get(row, key)
        .map(|v| {
            v.trim_end_matches('s').parse::<u16>().map_err(|e| {
                anyhow::anyhow!("field {key:?} = {v:?} is not a keepalive duration: {e}")
            })
        })
        .transpose()
}

fn yes_no(on: bool) -> String {
    if on { "yes" } else { "no" }.to_owned()
}

/// Establishes a TLS connection using the host's own trusted CA store (`rustls-native-certs`) -
/// never `tls_insecure()`. `rustls::ClientConfig::builder()` takes the process-default crypto
/// provider, which `run` installs once at startup.
pub async fn connect(creds: &RouterCredentials) -> anyhow::Result<MikrotikDevice> {
    let mut roots = rustls::RootCertStore::empty();
    for cert in rustls_native_certs::load_native_certs().certs {
        roots.add(cert)?;
    }
    let config = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let server_name = rustls::pki_types::ServerName::try_from(creds.host.clone())
        .map_err(|e| anyhow::anyhow!("invalid TLS server name {:?}: {e}", creds.host))?;

    let addr = format!("{}:{}", creds.host, creds.port);
    let device = MikrotikDevice::builder(addr)
        .credentials(&creds.username, creds.password.as_deref())
        .tls_config(std::sync::Arc::new(config), server_name)
        .connect()
        .await
        .map_err(|e| anyhow::anyhow!("failed to connect to RouterOS device: {e}"))?;
    Ok(device)
}

async fn execute(device: &MikrotikDevice, cmd: CommandBuilder<Cmd>) -> anyhow::Result<Vec<Row>> {
    let mut rx = device
        .send_command(cmd.build())
        .await
        .map_err(|e| anyhow::anyhow!("failed to send command: {e}"))?;
    let mut rows = Vec::new();
    while let Some(event) = rx.recv().await {
        match event {
            Event::Reply { response, .. } => rows.push(response.attributes),
            Event::Done { .. } | Event::Empty { .. } => return Ok(rows),
            Event::Trap { response, .. } => {
                anyhow::bail!(
                    "RouterOS command failed: {} (category: {:?})",
                    response.message,
                    response.category
                )
            }
            Event::Fatal { reason } => anyhow::bail!("RouterOS connection failed: {reason}"),
        }
    }
    Ok(rows)
}

async fn print(device: &MikrotikDevice, path: &str) -> anyhow::Result<Vec<Row>> {
    execute(
        device,
        CommandBuilder::new().command(&format!("{path}/print")),
    )
    .await
}

/// How one table is written.
pub(crate) trait Table {
    type Desired: Clone + Debug;
    const PATH: &'static str;
    /// What the report and `--diff` call the table.
    const NAME: &'static str;
    fn add_attributes(desired: &Self::Desired) -> Attributes;
    /// A `set` sends what an `add` does, unless the table says otherwise.
    fn set_attributes(desired: &Self::Desired) -> Attributes {
        Self::add_attributes(desired)
    }
}

/// A table whose rows the diff matches by key.
pub(crate) trait Keyed: Table {
    type Current: HasId + Debug;
    fn parse(row: &Row) -> anyhow::Result<Self::Current>;
    /// Whether a row is this tool's, given its interfaces in `ours`. Every row is, unless the
    /// table has other writers: `diff` removes every row it is handed that is not desired.
    fn is_ours(_current: &Self::Current, _ours: &[String]) -> bool {
        true
    }
    fn plan(current: &[Self::Current], desired: &[Self::Desired]) -> Plan<Self::Desired>;
    fn commands(_current: &[Self::Current], plan: &Plan<Self::Desired>) -> Vec<Command> {
        commands::<Self>(plan)
    }
}

/// A table this tool keeps one row of, found by its name.
pub(crate) trait Singleton: Table<Desired: PartialEq> {
    fn parse(row: &Row) -> Self::Desired;
}

/// One write to a table.
pub(crate) enum Command {
    Remove(String),
    Add(Attributes),
    Set(String, Attributes),
    /// Returns a property to its default.
    Unset(String, &'static str),
}

impl Command {
    fn build(&self, path: &str) -> CommandBuilder<Cmd> {
        let command = |verb: &str| CommandBuilder::new().command(&format!("{path}/{verb}"));
        match self {
            Self::Remove(id) => command("remove").attribute(".id", Some(id)),
            Self::Add(attributes) => with_attributes(command("add"), attributes),
            Self::Set(id, attributes) => {
                with_attributes(command("set").attribute(".id", Some(id)), attributes)
            }
            // RouterOS addresses the row as `numbers` here, not `.id` as `set` does.
            Self::Unset(id, property) => command("unset")
                .attribute("numbers", Some(id))
                .attribute("value-name", Some(property)),
        }
    }
}

fn with_attributes(mut b: CommandBuilder<Cmd>, attributes: &Attributes) -> CommandBuilder<Cmd> {
    for (key, value) in attributes {
        b = b.attribute(key, Some(value));
    }
    b
}

/// The commands that apply `plan`: its removals, then its adds, then its updates.
/// - RouterOS refuses a renamed interface's port while the old interface holds it.
/// - It refuses an address whose prefix length changes while the old one is there.
pub(crate) fn commands<T: Table + ?Sized>(plan: &Plan<T::Desired>) -> Vec<Command> {
    let removals = plan.remove.iter().map(|id| Command::Remove(id.clone()));
    let adds = plan.add.iter().map(|d| Command::Add(T::add_attributes(d)));
    let updates = plan
        .update
        .iter()
        .map(|(id, d)| Command::Set(id.clone(), T::set_attributes(d)));
    removals.chain(adds).chain(updates).collect()
}

pub async fn send(device: &MikrotikDevice, path: &str, commands: &[Command]) -> anyhow::Result<()> {
    for command in commands {
        execute(device, command.build(path)).await?;
    }
    Ok(())
}

/// The rows of `T` that are ours, see [`Keyed::is_ours`].
pub async fn read<T: Keyed>(
    device: &MikrotikDevice,
    ours: &[String],
) -> anyhow::Result<Vec<T::Current>> {
    footprint::<T>(&print(device, T::PATH).await?, ours)
}

/// The rows that are ours; one that does not parse is kept, to be refused.
pub(crate) fn footprint<T: Keyed>(
    rows: &[Row],
    ours: &[String],
) -> anyhow::Result<Vec<T::Current>> {
    rows.iter()
        .map(T::parse)
        .filter(|row| row.as_ref().map_or(true, |c| T::is_ours(c, ours)))
        .collect()
}

pub async fn read_singleton<T: Singleton>(
    device: &MikrotikDevice,
    name: &str,
) -> anyhow::Result<Option<(String, T::Desired)>> {
    let rows = print(device, T::PATH).await?;
    Ok(by_name(&rows, name)?.map(|(id, row)| (id, T::parse(row))))
}

/// The row called `name`, with its id; every row up to it must have one.
fn by_name<'r>(rows: &'r [Row], name: &str) -> anyhow::Result<Option<(String, &'r Row)>> {
    for row in rows {
        let id = get_id(row)?;
        if get(row, "name") == Some(name) {
            return Ok(Some((id, row)));
        }
    }
    Ok(None)
}

pub(crate) struct WireguardInterfaces;

impl Table for WireguardInterfaces {
    type Desired = DesiredWireguardInterface;
    const PATH: &'static str = "/interface/wireguard";
    const NAME: &'static str = "interface wireguard";

    fn add_attributes(d: &Self::Desired) -> Attributes {
        let mut attributes = vec![("name", d.name.clone())];
        attributes.extend(Self::set_attributes(d));
        attributes
    }

    fn set_attributes(d: &Self::Desired) -> Attributes {
        let mut attributes = vec![
            ("listen-port", d.listen_port.to_string()),
            ("private-key", d.private_key_b64.expose().to_owned()),
            ("disabled", yes_no(d.disabled)),
        ];
        attributes.extend(d.mtu.map(|mtu| ("mtu", mtu.to_string())));
        attributes
    }
}

impl Keyed for WireguardInterfaces {
    type Current = CurrentWireguardInterface;

    fn parse(row: &Row) -> anyhow::Result<Self::Current> {
        let id = get_id(row)?;
        Ok(CurrentWireguardInterface {
            name: get_required(row, "name", &id)?.to_string(),
            listen_port: get_required(row, "listen-port", &id)?
                .parse()
                .map_err(|e| anyhow::anyhow!("listen-port is not a u16: {e}"))?,
            private_key_b64: get(row, "private-key").unwrap_or_default().into(),
            disabled: get_bool_flag(row, "disabled"),
            mtu: get(row, "mtu")
                .map(|mtu| mtu.parse())
                .transpose()
                .map_err(|e| anyhow::anyhow!("mtu is not a number: {e}"))?,
            id,
        })
    }

    fn plan(current: &[Self::Current], desired: &[Self::Desired]) -> Plan<Self::Desired> {
        diff::wireguard_interfaces(current, desired)
    }
}

pub(crate) struct WireguardPeers;

impl Table for WireguardPeers {
    type Desired = DesiredWireguardPeer;
    const PATH: &'static str = "/interface/wireguard/peers";
    const NAME: &'static str = "interface wireguard peers";

    fn add_attributes(d: &Self::Desired) -> Attributes {
        vec![
            ("interface", d.interface.clone()),
            ("comment", d.name.clone()),
            ("public-key", d.public_key_b64.clone()),
            ("allowed-address", d.allowed_address.clone()),
            // An empty value clears an endpoint the device still holds; omitting it would keep that.
            (
                "endpoint-address",
                d.endpoint_address.clone().unwrap_or_default(),
            ),
            // Peers have no `unset`, so an absent port or keepalive is written as `0`, RouterOS's
            // default; an empty value is refused for both.
            ("endpoint-port", d.endpoint_port.unwrap_or(0).to_string()),
            (
                "persistent-keepalive",
                d.persistent_keepalive.unwrap_or(0).to_string(),
            ),
            ("disabled", yes_no(d.disabled)),
        ]
    }
}

impl Keyed for WireguardPeers {
    type Current = CurrentWireguardPeer;

    fn parse(row: &Row) -> anyhow::Result<Self::Current> {
        let id = get_id(row)?;
        Ok(CurrentWireguardPeer {
            interface: get_required(row, "interface", &id)?.to_string(),
            // See the module doc comment: RouterOS's own peer table has no `name` property -
            // `comment` is used here to carry the peer's name.
            name: get(row, "comment").unwrap_or_default().to_string(),
            public_key_b64: get(row, "public-key").unwrap_or_default().to_string(),
            allowed_address: get(row, "allowed-address").unwrap_or_default().to_string(),
            endpoint_address: get(row, "endpoint-address").map(str::to_string),
            // A cleared port reads back as `0`, see `add_attributes`.
            endpoint_port: get_opt_u16(row, "endpoint-port")?.filter(|&p| p != 0),
            // A keepalive that sends none reads back as `0`, as one never set does.
            persistent_keepalive: get_opt_keepalive_seconds(row, "persistent-keepalive")?
                .filter(|&seconds| seconds != 0),
            disabled: get_bool_flag(row, "disabled"),
            id,
        })
    }

    fn plan(current: &[Self::Current], desired: &[Self::Desired]) -> Plan<Self::Desired> {
        diff::wireguard_peers(current, desired)
    }
}

pub(crate) struct IpAddresses;

impl Table for IpAddresses {
    type Desired = DesiredIpAddress;
    const PATH: &'static str = "/ip/address";
    const NAME: &'static str = "ip address";

    fn add_attributes(d: &Self::Desired) -> Attributes {
        vec![
            ("address", d.address.clone()),
            ("interface", d.interface.clone()),
            ("disabled", yes_no(d.disabled)),
        ]
    }

    fn set_attributes(d: &Self::Desired) -> Attributes {
        vec![("disabled", yes_no(d.disabled))]
    }
}

impl Keyed for IpAddresses {
    type Current = CurrentIpAddress;

    fn parse(row: &Row) -> anyhow::Result<Self::Current> {
        let id = get_id(row)?;
        Ok(CurrentIpAddress {
            address: get_required(row, "address", &id)?.to_string(),
            interface: get_required(row, "interface", &id)?.to_string(),
            disabled: get_bool_flag(row, "disabled"),
            id,
        })
    }

    /// The addresses on the interfaces this tool creates and the loopback bridge.
    fn is_ours(a: &Self::Current, ours: &[String]) -> bool {
        diff::is_ours(&a.interface, ours)
    }

    fn plan(current: &[Self::Current], desired: &[Self::Desired]) -> Plan<Self::Desired> {
        diff::ip_addresses(current, desired)
    }
}

/// This device's own directly-connected subnets (every `ip address` row except an orphaned raw id
/// and the loopback bridge itself), normalized to network base - the BGP-announced prefix set is
/// computed fresh from this on every run, never configured. Candidates for
/// `config::desired_state`'s `direct_interfaces`/`learn` filtering, which owns the policy of what
/// actually gets announced - this function is a dumb reader, filtering nothing but our own
/// infrastructure's dead weight (the address of a link's interface is a legitimate candidate, since
/// `addressing.tunnel.ipv4` can give it a real one, not just a link-local).
pub async fn read_physically_connected_prefixes(
    device: &MikrotikDevice,
) -> anyhow::Result<Vec<(String, Ipv4Net)>> {
    physically_connected(&print(device, IpAddresses::PATH).await?)
}

/// The physically-connected subnets the `ip address` rows give, each by its interface.
fn physically_connected(rows: &[Row]) -> anyhow::Result<Vec<(String, Ipv4Net)>> {
    let mut prefixes = Vec::new();
    for row in rows {
        let a = IpAddresses::parse(row)?;
        // Unlike `IpAddresses::is_ours`, the links' interfaces are **not** excluded
        // here: `addressing.tunnel.ipv4` (see config.rs) can give one a real, non-link-local
        // address meant to be announced when the node's `direct_interfaces` hold the links'
        // pattern - config::desired_state's own direct_interfaces/learn matching is what actually
        // decides whether any given prefix gets announced, this is just the candidate list. Only a
        // raw internal id orphaned by a deleted interface (e.g. `*16`) and the loopback bridge
        // itself are excluded - neither is ever announce-worthy.
        if crate::diff::is_raw_orphan_id(&a.interface) || a.interface == ROUTER_LOOPBACK {
            continue;
        }
        match address_to_network(&a.address) {
            Ok(network) => prefixes.push((a.interface.clone(), network)),
            Err(e) => {
                tracing::warn!(address = %a.address, interface = %a.interface, error = %e, "skipping unparsable physically-connected address")
            }
        }
    }
    Ok(prefixes)
}

/// Normalizes a host address-with-prefix (as configured on an interface, e.g. `"203.0.113.1/27"`)
/// to its containing network base (`"203.0.113.0/27"`) - `ip address` rows carry the host
/// address, not the network, but a BGP-announced prefix must be the network itself.
fn address_to_network(address: &str) -> anyhow::Result<Ipv4Net> {
    Ok(sliplib_net::parse_ipv4(address)?.trunc())
}

pub(crate) struct ListMembers;

impl Table for ListMembers {
    type Desired = DesiredListMember;
    const PATH: &'static str = "/interface/list/member";
    const NAME: &'static str = "interface list member";

    fn add_attributes(d: &Self::Desired) -> Attributes {
        vec![
            ("list", d.list.clone()),
            ("interface", d.interface.clone()),
            ("disabled", yes_no(d.disabled)),
        ]
    }

    fn set_attributes(d: &Self::Desired) -> Attributes {
        vec![("disabled", yes_no(d.disabled))]
    }
}

impl Keyed for ListMembers {
    type Current = CurrentListMember;

    fn parse(row: &Row) -> anyhow::Result<Self::Current> {
        let id = get_id(row)?;
        Ok(CurrentListMember {
            list: get_required(row, "list", &id)?.to_string(),
            interface: get_required(row, "interface", &id)?.to_string(),
            disabled: get_bool_flag(row, "disabled"),
            id,
        })
    }

    /// The `LAN` list's members on the interfaces this tool creates.
    fn is_ours(m: &Self::Current, ours: &[String]) -> bool {
        m.list == crate::config::LAN_LIST && diff::is_ours(&m.interface, ours)
    }

    fn plan(current: &[Self::Current], desired: &[Self::Desired]) -> Plan<Self::Desired> {
        diff::list_members(current, desired)
    }
}

pub(crate) struct LoopbackBridge;

impl Table for LoopbackBridge {
    type Desired = DesiredBridge;
    const PATH: &'static str = "/interface/bridge";
    const NAME: &'static str = "interface bridge";

    fn add_attributes(d: &Self::Desired) -> Attributes {
        vec![
            ("name", d.name.clone()),
            ("protocol-mode", "none".to_owned()),
            ("disabled", yes_no(d.disabled)),
        ]
    }

    fn set_attributes(d: &Self::Desired) -> Attributes {
        vec![("disabled", yes_no(d.disabled))]
    }
}

impl Singleton for LoopbackBridge {
    fn parse(row: &Row) -> Self::Desired {
        DesiredBridge {
            name: get(row, "name").unwrap_or_default().to_string(),
            disabled: get_bool_flag(row, "disabled"),
        }
    }
}

pub(crate) struct Ipv6Addresses;

impl Table for Ipv6Addresses {
    type Desired = DesiredIpv6Address;
    const PATH: &'static str = "/ipv6/address";
    const NAME: &'static str = "ipv6 address";

    fn add_attributes(d: &Self::Desired) -> Attributes {
        let mut attributes = vec![
            ("address", d.address.clone()),
            ("interface", d.interface.clone()),
        ];
        attributes.extend(Self::set_attributes(d));
        attributes
    }

    /// `auto-link-local` is sent only when set: RouterOS rejects it on an address that is not
    /// link-local, whatever the value.
    fn set_attributes(d: &Self::Desired) -> Attributes {
        let mut attributes = vec![("advertise", yes_no(d.advertise))];
        if let Some(auto_link_local) = d.auto_link_local {
            attributes.push(("auto-link-local", yes_no(auto_link_local)));
        }
        attributes.push(("disabled", yes_no(d.disabled)));
        attributes
    }
}

impl Keyed for Ipv6Addresses {
    type Current = CurrentIpv6Address;

    fn parse(row: &Row) -> anyhow::Result<Self::Current> {
        let id = get_id(row)?;
        Ok(CurrentIpv6Address {
            address: get_required(row, "address", &id)?.to_string(),
            interface: get_required(row, "interface", &id)?.to_string(),
            // Assumed boolean-flag-shaped exactly like `disabled` (explicit "true"/"false" on
            // read, "yes"/"no" accepted on write) - not confirmed on a device.
            advertise: get_bool_flag(row, "advertise"),
            auto_link_local: get_bool_flag(row, "auto-link-local"),
            disabled: get_bool_flag(row, "disabled"),
            id,
        })
    }

    /// The addresses on the interfaces this tool creates and the loopback bridge.
    ///
    /// Link-local (`fe80::/10`) rows are **not** specially excluded here - both `router-lo` and
    /// the links' interfaces are in scope, so any auto-generated link-local RouterOS puts on one of
    /// them ends up "in footprint but not desired" and gets cleaned up like any other stale row.
    /// This matters for two different reasons per interface type:
    /// - the links' interfaces (WireGuard): RouterOS's own auto-generation is broken - once a
    ///   second mesh link exists, every one of them gets the *identical* link-local, and RouterOS's
    ///   own duplicate address detection marks every one past the first `invalid`, breaking OSPFv3
    ///   adjacency on all of them. `config::desired_state` applies the address explicitly
    ///   (from `awg.interfaces[].addresses`), with
    ///   `auto-link-local=no` so that it replaces the generated one rather than sitting next to it
    ///   - see `config::own_ipv6_address`.
    /// - `router-lo`: its own auto-generated link-local isn't broken the same way (a bridge has a
    ///   real MAC), but once `routing ospf instance`'s `redistribute=connected` is set (see
    ///   [`OspfInstance`]), RouterOS redistributes *every* connected IPv6 route on that interface
    ///   into OSPF - a link-local prefix has no business being treated as a globally routable
    ///   destination, so nothing should be left there to redistribute by accident.
    fn is_ours(a: &Self::Current, ours: &[String]) -> bool {
        diff::is_ours(&a.interface, ours)
    }

    fn plan(current: &[Self::Current], desired: &[Self::Desired]) -> Plan<Self::Desired> {
        diff::ipv6_addresses(current, desired)
    }
}

/// `set` also sends `version`, attempting an in-place `2 -> 3` transition for a device migrating
/// from the pre-OSPFv3 scheme. Whether RouterOS allows changing an OSPF instance's `version` after
/// creation is not verified - if it rejects this, the pre-existing OSPFv2 instance needs a
/// one-time manual `/routing ospf instance remove [find name=default-v2]` during the migration
/// window. This table is a name-owned singleton by design, not something to build automatic
/// detection for.
pub(crate) struct OspfInstance;

impl Table for OspfInstance {
    type Desired = DesiredOspfInstance;
    const PATH: &'static str = "/routing/ospf/instance";
    const NAME: &'static str = "routing ospf instance";

    fn add_attributes(d: &Self::Desired) -> Attributes {
        let mut attributes = vec![("name", d.name.clone())];
        attributes.extend(Self::set_attributes(d));
        attributes
    }

    fn set_attributes(d: &Self::Desired) -> Attributes {
        let redistribute = if d.redistribute_connected {
            "connected"
        } else {
            ""
        };
        vec![
            ("version", d.version.to_string()),
            ("router-id", d.router_id.to_string()),
            ("redistribute", redistribute.to_owned()),
        ]
    }
}

impl Singleton for OspfInstance {
    fn parse(row: &Row) -> Self::Desired {
        DesiredOspfInstance {
            name: get(row, "name").unwrap_or_default().to_string(),
            version: get(row, "version").unwrap_or("3").parse().unwrap_or(3),
            router_id: get(row, "router-id")
                .unwrap_or_default()
                .parse()
                .unwrap_or(Ipv4Addr::UNSPECIFIED),
            redistribute_connected: get(row, "redistribute")
                .is_some_and(|v| v.split(',').any(|s| s == "connected")),
            disabled: get_bool_flag(row, "disabled"),
        }
    }
}

pub(crate) struct OspfArea;

impl Table for OspfArea {
    type Desired = DesiredOspfArea;
    const PATH: &'static str = "/routing/ospf/area";
    const NAME: &'static str = "routing ospf area";

    fn add_attributes(d: &Self::Desired) -> Attributes {
        vec![
            ("name", d.name.clone()),
            ("area-id", d.area_id.clone()),
            ("instance", d.instance.clone()),
        ]
    }

    fn set_attributes(d: &Self::Desired) -> Attributes {
        vec![("instance", d.instance.clone())]
    }
}

impl Singleton for OspfArea {
    fn parse(row: &Row) -> Self::Desired {
        DesiredOspfArea {
            name: get(row, "name").unwrap_or_default().to_string(),
            area_id: get(row, "area-id").unwrap_or_default().to_string(),
            instance: get(row, "instance").unwrap_or_default().to_string(),
            disabled: get_bool_flag(row, "disabled"),
        }
    }
}

pub(crate) struct BfdConfigurations;

impl Table for BfdConfigurations {
    type Desired = DesiredBfdConfiguration;
    const PATH: &'static str = "/routing/bfd/configuration";
    const NAME: &'static str = "routing bfd configuration";

    fn add_attributes(d: &Self::Desired) -> Attributes {
        vec![
            ("interfaces", d.interfaces.clone()),
            ("min-rx", d.min_rx.clone()),
            ("min-tx", d.min_tx.clone()),
            ("multiplier", d.multiplier.to_string()),
        ]
    }
}

impl Keyed for BfdConfigurations {
    type Current = CurrentBfdConfiguration;

    fn parse(row: &Row) -> anyhow::Result<Self::Current> {
        let id = get_id(row)?;
        Ok(CurrentBfdConfiguration {
            interfaces: get_required(row, "interfaces", &id)?.to_string(),
            min_rx: get(row, "min-rx").map(str::to_string),
            min_tx: get(row, "min-tx").map(str::to_string),
            multiplier: get_opt_u16(row, "multiplier")?,
            id,
        })
    }

    fn plan(current: &[Self::Current], desired: &[Self::Desired]) -> Plan<Self::Desired> {
        diff::bfd_configurations(current, desired)
    }
}

pub(crate) struct OspfInterfaceTemplates;

impl Table for OspfInterfaceTemplates {
    type Desired = DesiredOspfInterfaceTemplate;
    const PATH: &'static str = "/routing/ospf/interface-template";
    const NAME: &'static str = "routing ospf interface-template";

    fn add_attributes(d: &Self::Desired) -> Attributes {
        let mut attributes = vec![
            ("interfaces", d.interfaces.clone()),
            ("area", d.area.clone()),
        ];
        attributes.extend(d.type_.clone().map(|t| ("type", t)));
        attributes.extend(d.hello_interval.clone().map(|h| ("hello-interval", h)));
        attributes.extend(d.dead_interval.clone().map(|dead| ("dead-interval", dead)));
        if d.passive {
            attributes.push(("passive", String::new()));
        }
        attributes.push(("use-bfd", yes_no(d.use_bfd)));
        attributes.push(("disabled", yes_no(d.disabled)));
        attributes.extend(d.cost.map(|c| ("cost", c.to_string())));
        attributes
    }
}

impl Keyed for OspfInterfaceTemplates {
    type Current = CurrentOspfInterfaceTemplate;

    fn parse(row: &Row) -> anyhow::Result<Self::Current> {
        let id = get_id(row)?;
        Ok(CurrentOspfInterfaceTemplate {
            interfaces: get_required(row, "interfaces", &id)?.to_string(),
            area: get(row, "area").unwrap_or_default().to_string(),
            type_: get(row, "type").map(str::to_string),
            cost: get_opt_u16(row, "cost")?,
            hello_interval: get(row, "hello-interval").map(str::to_string),
            dead_interval: get(row, "dead-interval").map(str::to_string),
            passive_raw: get_flag_presence(row, "passive"),
            use_bfd: get_bool_flag(row, "use-bfd"),
            disabled: get_bool_flag(row, "disabled"),
            id,
        })
    }

    fn plan(current: &[Self::Current], desired: &[Self::Desired]) -> Plan<Self::Desired> {
        diff::ospf_interface_templates(current, desired)
    }

    /// The `set` of a template that drops `passive` leaves the flag on, so it is unset after.
    fn commands(current: &[Self::Current], plan: &Plan<Self::Desired>) -> Vec<Command> {
        let unsets = diff::passive_to_unset(current, plan)
            .into_iter()
            .map(|id| Command::Unset(id, "passive"));
        commands::<Self>(plan).into_iter().chain(unsets).collect()
    }
}

pub(crate) struct BgpNetworks;

impl Table for BgpNetworks {
    type Desired = DesiredAddressListEntry;
    const PATH: &'static str = "/ip/firewall/address-list";
    const NAME: &'static str = "ip firewall address-list";

    fn add_attributes(d: &Self::Desired) -> Attributes {
        vec![
            ("list", d.list.clone()),
            ("address", d.address.clone()),
            ("disabled", yes_no(d.disabled)),
        ]
    }

    fn set_attributes(d: &Self::Desired) -> Attributes {
        vec![("disabled", yes_no(d.disabled))]
    }
}

impl Keyed for BgpNetworks {
    type Current = CurrentAddressListEntry;

    fn parse(row: &Row) -> anyhow::Result<Self::Current> {
        let id = get_id(row)?;
        Ok(CurrentAddressListEntry {
            list: get_required(row, "list", &id)?.to_string(),
            address: get_required(row, "address", &id)?.to_string(),
            disabled: get_bool_flag(row, "disabled"),
            id,
        })
    }

    /// The entries of the `bgp-networks` list; the table holds every other list too.
    fn is_ours(e: &Self::Current, _ours: &[String]) -> bool {
        e.list == crate::config::BGP_NETWORKS_LIST
    }

    fn plan(current: &[Self::Current], desired: &[Self::Desired]) -> Plan<Self::Desired> {
        diff::bgp_networks(current, desired)
    }
}

pub(crate) struct BgpInstance;

impl Table for BgpInstance {
    type Desired = DesiredBgpInstance;
    const PATH: &'static str = "/routing/bgp/instance";
    const NAME: &'static str = "routing bgp instance";

    fn add_attributes(d: &Self::Desired) -> Attributes {
        vec![
            ("name", d.name.clone()),
            ("as", d.as_number.to_string()),
            ("router-id", d.router_id.to_string()),
            ("routing-table", d.routing_table.clone()),
        ]
    }

    fn set_attributes(d: &Self::Desired) -> Attributes {
        vec![
            ("as", d.as_number.to_string()),
            ("router-id", d.router_id.to_string()),
        ]
    }
}

impl Singleton for BgpInstance {
    fn parse(row: &Row) -> Self::Desired {
        DesiredBgpInstance {
            name: get(row, "name").unwrap_or_default().to_string(),
            as_number: get(row, "as").unwrap_or("0").parse().unwrap_or(0),
            router_id: get(row, "router-id")
                .unwrap_or_default()
                .parse()
                .unwrap_or(Ipv4Addr::UNSPECIFIED),
            routing_table: get(row, "routing-table").unwrap_or_default().to_string(),
            disabled: get_bool_flag(row, "disabled"),
        }
    }
}

pub(crate) struct BgpConnections;

impl Table for BgpConnections {
    type Desired = DesiredBgpConnection;
    const PATH: &'static str = "/routing/bgp/connection";
    const NAME: &'static str = "routing bgp connection";

    fn add_attributes(d: &Self::Desired) -> Attributes {
        vec![
            ("name", d.name.clone()),
            ("instance", d.instance.clone()),
            ("local.role", d.local_role.clone()),
            ("multihop", yes_no(d.multihop)),
            ("afi", d.afi.clone()),
            ("output.network", d.output_network.clone()),
            ("disabled", yes_no(d.disabled)),
            ("local.address", d.local_address.to_string()),
            ("remote.address", d.remote_address.to_string()),
        ]
    }
}

impl Keyed for BgpConnections {
    type Current = CurrentBgpConnection;

    fn parse(row: &Row) -> anyhow::Result<Self::Current> {
        let id = get_id(row)?;
        Ok(CurrentBgpConnection {
            name: get_required(row, "name", &id)?.to_string(),
            instance: get(row, "instance").unwrap_or_default().to_string(),
            local_address: get(row, "local.address")
                .unwrap_or_default()
                .parse()
                .unwrap_or(Ipv6Addr::UNSPECIFIED),
            local_role: get(row, "local.role").unwrap_or_default().to_string(),
            remote_address: get(row, "remote.address")
                .unwrap_or_default()
                .parse()
                .unwrap_or(Ipv6Addr::UNSPECIFIED),
            // `multihop`/`afi` are top-level connection properties, not under
            // `local.`/`remote.`/`output.` - not confirmed on a device.
            multihop: get_bool_flag(row, "multihop"),
            afi: get(row, "afi").unwrap_or_default().to_string(),
            output_network: get(row, "output.network").unwrap_or_default().to_string(),
            disabled: get_bool_flag(row, "disabled"),
            id,
        })
    }

    fn plan(current: &[Self::Current], desired: &[Self::Desired]) -> Plan<Self::Desired> {
        diff::bgp_connections(current, desired)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::wg_key;

    fn row(pairs: &[(&str, &str)]) -> Row {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), Some(v.to_string())))
            .collect()
    }

    #[test]
    fn keepalive_seconds_strips_the_time_unit_suffix() {
        for written in ["25s", "25"] {
            let r = row(&[(".id", "*1"), ("persistent-keepalive", written)]);
            assert_eq!(
                get_opt_keepalive_seconds(&r, "persistent-keepalive").unwrap(),
                Some(25),
                "{written}"
            );
        }
    }

    #[test]
    fn parses_wireguard_interface_row() {
        let mut r = row(&[
            (".id", "*1"),
            ("name", "mesh-east"),
            ("listen-port", "51820"),
            ("private-key", "abc="),
        ]);
        let iface = WireguardInterfaces::parse(&r).unwrap();
        assert_eq!(iface.id, "*1");
        assert_eq!(iface.name, "mesh-east");
        assert_eq!(iface.listen_port, 51820);
        assert_eq!(iface.private_key_b64.expose(), "abc=");
        assert!(!iface.disabled);
        assert_eq!(iface.mtu, None);

        r.insert("mtu".to_string(), Some("1420".to_string()));
        assert_eq!(WireguardInterfaces::parse(&r).unwrap().mtu, Some(1420));
    }

    #[test]
    fn wireguard_peer_uses_comment_as_the_label_field() {
        let r = row(&[
            (".id", "*2"),
            ("interface", "mesh-east"),
            ("comment", "east1"),
            ("public-key", "pub="),
            ("allowed-address", "0.0.0.0/0,::/0"),
        ]);
        let peer = WireguardPeers::parse(&r).unwrap();
        assert_eq!(peer.name, "east1");
    }

    #[test]
    fn an_ospf_template_is_passive_only_where_the_key_is_there() {
        let mut r = row(&[
            (".id", "*1"),
            ("interfaces", "router-lo"),
            ("area", "backbone"),
        ]);
        assert_eq!(OspfInterfaceTemplates::parse(&r).unwrap().passive_raw, None);

        // A real device sends a passive row as `=passive=`: the key with no value.
        r.insert("passive".to_string(), None);
        let t = OspfInterfaceTemplates::parse(&r).unwrap();
        assert!(crate::diff::passive_flag_is_true(t.passive_raw.as_deref()));
    }

    fn ipv6_address(address: &str, auto_link_local: Option<bool>) -> DesiredIpv6Address {
        DesiredIpv6Address {
            address: address.to_string(),
            interface: "router-lo".to_string(),
            advertise: false,
            auto_link_local,
            disabled: false,
        }
    }

    #[test]
    fn ipv6_address_settings_send_auto_link_local_only_when_set() {
        let settings = Ipv6Addresses::set_attributes(&ipv6_address("3fff::1/128", None));
        assert!(settings.iter().all(|(key, _)| *key != "auto-link-local"));
        let settings = Ipv6Addresses::set_attributes(&ipv6_address("fe80::1/64", Some(false)));
        assert!(settings.contains(&("auto-link-local", "no".to_owned())));
    }

    #[test]
    fn parses_ipv6_address_row() {
        let r = row(&[
            (".id", "*1"),
            ("address", "3fff::1/128"),
            ("interface", "router-lo"),
            ("advertise", "false"),
        ]);
        let a = Ipv6Addresses::parse(&r).unwrap();
        assert_eq!(a.address, "3fff::1/128");
        assert_eq!(a.interface, "router-lo");
        assert!(!a.advertise);
    }

    #[test]
    fn parses_bgp_connection_row_with_ipv6_addresses_and_multihop_afi() {
        let r = row(&[
            (".id", "*1"),
            ("name", "bgp-east"),
            ("instance", "default"),
            ("local.address", "3fff::1"),
            ("local.role", "ibgp"),
            ("remote.address", "3fff::2"),
            ("multihop", "true"),
            ("afi", "ip"),
            ("output.network", "bgp-networks"),
        ]);
        let c = BgpConnections::parse(&r).unwrap();
        assert_eq!(c.local_address, "3fff::1".parse::<Ipv6Addr>().unwrap());
        assert_eq!(c.remote_address, "3fff::2".parse::<Ipv6Addr>().unwrap());
        assert!(c.multihop);
        assert_eq!(c.afi, "ip");
    }

    /// Whether the encoded command carries `word` as one API word (one-byte length prefix).
    fn sends_word(cmd: CommandBuilder<Cmd>, word: &str) -> bool {
        let mut encoded = vec![u8::try_from(word.len()).unwrap()];
        encoded.extend_from_slice(word.as_bytes());
        cmd.build()
            .data()
            .windows(encoded.len())
            .any(|w| w == encoded)
    }

    #[test]
    fn passive_ospf_template_sends_the_valueless_passive_word() {
        let d = template("router-lo", true);
        let path = OspfInterfaceTemplates::PATH;
        let add = Command::Add(OspfInterfaceTemplates::add_attributes(&d));
        assert!(sends_word(add.build(path), "=passive="));
        let set = Command::Set("*1".to_owned(), OspfInterfaceTemplates::set_attributes(&d));
        assert!(sends_word(set.build(path), "=passive="));
    }

    #[test]
    fn peer_without_endpoint_clears_endpoint_address() {
        let d = DesiredWireguardPeer {
            interface: "mesh-a".to_string(),
            name: "node-a".to_string(),
            public_key_b64: wg_key("node-a"),
            allowed_address: "0.0.0.0/0".to_string(),
            endpoint_address: None,
            endpoint_port: None,
            persistent_keepalive: None,
            disabled: false,
        };
        let set = Command::Set("*1".to_owned(), WireguardPeers::set_attributes(&d));
        for word in [
            "=endpoint-address=",
            "=endpoint-port=0",
            "=persistent-keepalive=0",
        ] {
            assert!(sends_word(set.build(WireguardPeers::PATH), word), "{word}");
        }
    }

    #[test]
    fn a_peer_value_written_as_zero_reads_back_as_none() {
        for (key, written) in [
            ("endpoint-port", "0"),
            ("persistent-keepalive", "0"),
            ("persistent-keepalive", "0s"),
        ] {
            let r = row(&[(".id", "*1"), ("interface", "mesh-a"), (key, written)]);
            let peer = WireguardPeers::parse(&r).unwrap();
            assert_eq!(
                (peer.endpoint_port, peer.persistent_keepalive),
                (None, None),
                "{key}={written}"
            );
        }
    }

    #[test]
    fn passive_is_cleared_by_unset_on_numbers() {
        let unset = Command::Unset("*1".to_owned(), "passive");
        for word in [
            "/routing/ospf/interface-template/unset",
            "=numbers=*1",
            "=value-name=passive",
        ] {
            assert!(
                sends_word(unset.build(OspfInterfaceTemplates::PATH), word),
                "{word}"
            );
        }
    }

    #[test]
    fn an_ospf_instance_redistributes_connected_only_when_its_list_holds_it() {
        for (redistribute, connected) in [("static,connected", true), ("static", false)] {
            let r = row(&[
                (".id", "*1"),
                ("name", "default"),
                ("redistribute", redistribute),
            ]);
            assert_eq!(
                OspfInstance::parse(&r).redistribute_connected,
                connected,
                "{redistribute}"
            );
        }
    }

    /// Rows on an interface `interface wireguard` holds, on one the tool asks for by name, on one
    /// that is nobody's of ours, on one named like the links' interfaces and not among them, and
    /// on the raw id a deleted interface leaves behind; each with `address`.
    fn rows_on_interfaces(address: &str) -> Vec<Row> {
        ["wg-east", "router-lo", "ether1", "wg-west", "*16"]
            .iter()
            .zip(1..)
            .map(|(interface, id)| {
                row(&[
                    (".id", &format!("*{id}")),
                    ("address", address),
                    ("interface", interface),
                    ("list", crate::config::LAN_LIST),
                ])
            })
            .collect()
    }

    fn ours() -> Vec<String> {
        vec!["wg-east".to_owned(), "router-lo".to_owned()]
    }

    const OURS: [&str; 3] = ["wg-east", "router-lo", "*16"];

    #[test]
    fn the_ip_addresses_read_are_those_on_this_tools_interfaces() {
        let read = footprint::<IpAddresses>(&rows_on_interfaces("192.0.2.1/32"), &ours()).unwrap();
        let interfaces: Vec<&str> = read.iter().map(|a| a.interface.as_str()).collect();
        assert_eq!(interfaces, OURS);
    }

    #[test]
    fn the_ipv6_addresses_read_are_those_on_this_tools_interfaces() {
        let read = footprint::<Ipv6Addresses>(&rows_on_interfaces("fe80::1/64"), &ours()).unwrap();
        let interfaces: Vec<&str> = read.iter().map(|a| a.interface.as_str()).collect();
        assert_eq!(interfaces, OURS);
    }

    #[test]
    fn the_list_members_read_are_those_of_the_lan_list_on_this_tools_interfaces() {
        let mut rows = rows_on_interfaces("192.0.2.1/32");
        // On an interface of ours, in a list that is not.
        rows.push(row(&[
            (".id", "*9"),
            ("interface", "wg-east"),
            ("list", "WAN"),
        ]));
        let read = footprint::<ListMembers>(&rows, &ours()).unwrap();
        let interfaces: Vec<&str> = read.iter().map(|m| m.interface.as_str()).collect();
        assert_eq!(interfaces, OURS);
    }

    #[test]
    fn a_row_that_does_not_parse_is_an_error_and_not_passed_over() {
        let unparsed = vec![row(&[(".id", "*1")])];
        assert!(footprint::<IpAddresses>(&unparsed, &[]).is_err());
        assert!(footprint::<Ipv6Addresses>(&unparsed, &[]).is_err());
        assert!(footprint::<ListMembers>(&unparsed, &[]).is_err());
        assert!(footprint::<BgpNetworks>(&unparsed, &[]).is_err());
        assert!(
            WireguardInterfaces::parse(&row(&[(".id", "*1"), ("listen-port", "51820")])).is_err()
        );
    }

    #[test]
    fn the_physically_connected_subnets_are_every_address_but_the_loopback_and_an_orphan() {
        let rows: Vec<Row> = [
            ("ether1", "203.0.113.1/27"),
            ("wg-east", "198.51.100.129/32"),
            ("router-lo", "198.51.100.2/32"),
            ("*16", "203.0.113.33/27"),
            ("ether2", "not an address"),
        ]
        .iter()
        .zip(1..)
        .map(|((interface, address), id)| {
            row(&[
                (".id", &format!("*{id}")),
                ("address", address),
                ("interface", interface),
            ])
        })
        .collect();
        let connected: Vec<(String, String)> = physically_connected(&rows)
            .unwrap()
            .into_iter()
            .map(|(iface, net)| (iface, net.to_string()))
            .collect();
        assert_eq!(
            connected,
            [
                ("ether1".to_owned(), "203.0.113.0/27".to_owned()),
                ("wg-east".to_owned(), "198.51.100.129/32".to_owned()),
            ]
        );
        assert!(physically_connected(&[row(&[(".id", "*1")])]).is_err());
    }

    /// Each command as its kind and the row it acts on.
    fn kinds(commands: &[Command]) -> Vec<String> {
        commands
            .iter()
            .map(|command| match command {
                Command::Remove(id) => format!("remove {id}"),
                Command::Add(_) => "add".to_owned(),
                Command::Set(id, _) => format!("set {id}"),
                Command::Unset(id, property) => format!("unset {id} {property}"),
            })
            .collect()
    }

    fn ip_address(address: &str) -> DesiredIpAddress {
        DesiredIpAddress {
            address: address.to_owned(),
            interface: "router-lo".to_owned(),
            disabled: false,
        }
    }

    #[test]
    fn a_plan_is_applied_as_its_removals_then_its_adds_then_its_updates() {
        let plan = Plan {
            add: vec![ip_address("192.0.2.1/32")],
            update: vec![("*2".to_owned(), ip_address("192.0.2.2/32"))],
            remove: vec!["*3".to_owned()],
        };
        assert_eq!(
            kinds(&IpAddresses::commands(&[], &plan)),
            ["remove *3", "add", "set *2"]
        );
    }

    fn template(interfaces: &str, passive: bool) -> DesiredOspfInterfaceTemplate {
        DesiredOspfInterfaceTemplate {
            interfaces: interfaces.to_owned(),
            use_bfd: false,
            area: "backbone".to_owned(),
            type_: None,
            cost: None,
            hello_interval: None,
            dead_interval: None,
            passive,
            disabled: false,
        }
    }

    #[test]
    fn a_templates_passive_is_unset_after_every_other_command() {
        let mut current = OspfInterfaceTemplates::parse(&row(&[
            (".id", "*1"),
            ("interfaces", "router-lo"),
            ("area", "backbone"),
        ]))
        .unwrap();
        current.passive_raw = Some(String::new());
        let plan = Plan {
            add: vec![template("wg-east", false)],
            update: vec![("*1".to_owned(), template("router-lo", false))],
            remove: vec!["*4".to_owned()],
        };
        assert_eq!(
            kinds(&OspfInterfaceTemplates::commands(&[current], &plan)),
            ["remove *4", "add", "set *1", "unset *1 passive"]
        );
    }

    #[test]
    fn the_bgp_networks_read_are_those_of_their_own_list() {
        let rows: Vec<Row> = [
            crate::config::BGP_NETWORKS_LIST,
            "other",
            crate::config::BGP_NETWORKS_LIST,
        ]
        .iter()
        .zip(1..)
        .map(|(list, id)| {
            row(&[
                (".id", &format!("*{id}")),
                ("list", list),
                ("address", "192.0.2.0/24"),
            ])
        })
        .collect();
        let read = footprint::<BgpNetworks>(&rows, &[]).unwrap();
        let ids: Vec<&str> = read.iter().map(|e| e.id.as_str()).collect();
        assert_eq!(ids, ["*1", "*3"]);
    }

    #[test]
    fn every_row_of_a_table_only_this_tool_writes_is_read() {
        let rows: Vec<Row> = ["wg-east", "ether1"]
            .iter()
            .zip(1..)
            .map(|(name, id)| {
                row(&[
                    (".id", &format!("*{id}")),
                    ("name", name),
                    ("listen-port", "51820"),
                ])
            })
            .collect();
        assert_eq!(
            footprint::<WireguardInterfaces>(&rows, &[]).unwrap().len(),
            2
        );
    }

    #[test]
    fn a_singleton_is_the_row_of_its_name_and_every_row_before_it_has_an_id() {
        let rows = [
            row(&[(".id", "*1"), ("name", "other")]),
            row(&[(".id", "*2"), ("name", "router-lo")]),
        ];
        let (id, found) = by_name(&rows, "router-lo").unwrap().unwrap();
        assert_eq!((id.as_str(), get(found, "name")), ("*2", Some("router-lo")));
        assert!(by_name(&rows, "absent").unwrap().is_none());
        assert!(by_name(&[row(&[("name", "router-lo")])], "router-lo").is_err());
    }
}
