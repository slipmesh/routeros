//! Thin RouterOS device shim: TLS connection, and per-table `read_*`/`apply_*` functions whose
//! types are exactly `diff.rs`'s `Current*`/`Plan<Desired*>` - see AGENTS.md's "keep I/O thin,
//! test the pure layer" convention. Row-parsing sub-pieces are still plain functions with their
//! own unit tests; the actual socket I/O is verified manually against a real device instead (no
//! mocking framework exists anywhere in this ecosystem - see AGENTS.md).
//!
//! **Attribute-name/schema assumptions below are ported from the ansible `mesh`/`router` roles'
//! own RouterOS API usage and MikroTik's documented API property names - not independently
//! confirmed against a live device in this session. Verify against a real RouterOS device during
//! the manual test pass (see AGENTS.md) before trusting this against production hardware,
//! particularly `/interface/wireguard/peers`' `comment` field (used here as the peer-label
//! attribute, since that table has no dedicated `name` property).**

use crate::credentials::RouterCredentials;
use crate::diff::{
    CurrentAddressListEntry, CurrentBgpConnection, CurrentIpAddress, CurrentIpv6Address,
    CurrentListMember, CurrentOspfInterfaceTemplate, CurrentWireguardInterface,
    CurrentWireguardPeer, DesiredAddressListEntry, DesiredBgpConnection, DesiredBridge,
    DesiredIpAddress, DesiredIpv6Address, DesiredListMember, DesiredOspfArea, DesiredOspfInstance,
    DesiredOspfInterfaceTemplate, DesiredWireguardInterface, DesiredWireguardPeer, Plan,
};
use mikrotik_rs::{CommandBuilder, Event, MikrotikDevice};
use std::collections::HashMap;
use std::net::{Ipv4Addr, Ipv6Addr};

type Row = HashMap<String, Option<String>>;

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
/// against a real device (see AGENTS.md's note that this attribute's exact wire shape wasn't
/// independently verified before). `hello-interval`/`dead-interval` are stored as raw strings
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

/// Establishes a TLS connection using the host's own trusted CA store (`rustls-native-certs`) -
/// never `tls_insecure()`, see AGENTS.md. Panics only via `expect` on a missing crypto provider,
/// matching `mikrotik-rs`'s own documented requirement that the application install one before
/// any `tls_config()` call - `run.rs`/`main.rs` does this once at startup.
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

async fn execute(
    device: &MikrotikDevice,
    cmd: CommandBuilder<mikrotik_rs::proto::command::Cmd>,
) -> anyhow::Result<Vec<Row>> {
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

async fn add(
    device: &MikrotikDevice,
    path: &str,
    attrs: &[(&str, Option<&str>)],
) -> anyhow::Result<String> {
    let mut b = CommandBuilder::new().command(&format!("{path}/add"));
    for (k, v) in attrs {
        b = b.attribute(k, *v);
    }
    let rows = execute(device, b).await?;
    // `/add` typically replies with a single row carrying the new object's `.id` (`=ret=*1`) - not
    // load-bearing for callers here (every apply_* re-reads on the next run), so a missing id in
    // the reply is tolerated rather than treated as a hard error.
    Ok(rows
        .first()
        .and_then(|r| get(r, "ret"))
        .unwrap_or_default()
        .to_string())
}

async fn set(
    device: &MikrotikDevice,
    path: &str,
    id: &str,
    attrs: &[(&str, Option<&str>)],
) -> anyhow::Result<()> {
    let mut b = CommandBuilder::new()
        .command(&format!("{path}/set"))
        .attribute(".id", Some(id));
    for (k, v) in attrs {
        b = b.attribute(k, *v);
    }
    execute(device, b).await?;
    Ok(())
}

async fn remove(device: &MikrotikDevice, path: &str, id: &str) -> anyhow::Result<()> {
    execute(
        device,
        CommandBuilder::new()
            .command(&format!("{path}/remove"))
            .attribute(".id", Some(id)),
    )
    .await?;
    Ok(())
}

// ── interface wireguard ──

const WIREGUARD_PATH: &str = "/interface/wireguard";

fn parse_wireguard_interface(row: &Row) -> anyhow::Result<CurrentWireguardInterface> {
    let id = get_id(row)?;
    Ok(CurrentWireguardInterface {
        name: get_required(row, "name", &id)?.to_string(),
        listen_port: get_required(row, "listen-port", &id)?
            .parse()
            .map_err(|e| anyhow::anyhow!("listen-port is not a u16: {e}"))?,
        private_key_b64: get(row, "private-key").unwrap_or_default().to_string(),
        disabled: get_bool_flag(row, "disabled"),
        id,
    })
}

pub async fn read_wireguard_interfaces(
    device: &MikrotikDevice,
) -> anyhow::Result<Vec<CurrentWireguardInterface>> {
    print(device, WIREGUARD_PATH)
        .await?
        .iter()
        .map(parse_wireguard_interface)
        .collect()
}

/// Removals happen **before** adds - a renamed interface (same UDP `listen-port`, new name, e.g. a
/// mesh-* interface renamed to the OSPFv3/RFC 8950 migration's `short_id`-based naming) is a
/// remove+add pair, not an update (the diff key is `name`). Adding the new one first, while the
/// old one still holds the port, makes RouterOS refuse the bind and auto-disable the new interface
/// with a "Listen port already used" comment - confirmed on a real device (`hq`) during the
/// migration's live rollout, where every renamed link hit this. Removing first frees the port
/// before anything tries to claim it again.
pub async fn apply_wireguard_interfaces(
    device: &MikrotikDevice,
    plan: &Plan<DesiredWireguardInterface>,
) -> anyhow::Result<()> {
    for id in &plan.remove {
        remove(device, WIREGUARD_PATH, id).await?;
    }
    for d in &plan.add {
        add(
            device,
            WIREGUARD_PATH,
            &[
                ("name", Some(d.name.as_str())),
                ("listen-port", Some(&d.listen_port.to_string())),
                ("private-key", Some(d.private_key_b64.as_str())),
                ("disabled", Some(if d.disabled { "yes" } else { "no" })),
            ],
        )
        .await?;
    }
    for (id, d) in &plan.update {
        set(
            device,
            WIREGUARD_PATH,
            id,
            &[
                ("listen-port", Some(&d.listen_port.to_string())),
                ("private-key", Some(d.private_key_b64.as_str())),
                ("disabled", Some(if d.disabled { "yes" } else { "no" })),
            ],
        )
        .await?;
    }
    Ok(())
}

// ── interface wireguard peers ──

const WIREGUARD_PEERS_PATH: &str = "/interface/wireguard/peers";

fn parse_wireguard_peer(row: &Row) -> anyhow::Result<CurrentWireguardPeer> {
    let id = get_id(row)?;
    Ok(CurrentWireguardPeer {
        interface: get_required(row, "interface", &id)?.to_string(),
        // See the module doc comment: RouterOS's own peer table has no `name` property - `comment`
        // is used here to carry the peer's mesh_label.
        name: get(row, "comment").unwrap_or_default().to_string(),
        public_key_b64: get(row, "public-key").unwrap_or_default().to_string(),
        allowed_address: get(row, "allowed-address").unwrap_or_default().to_string(),
        endpoint_address: get(row, "endpoint-address").map(str::to_string),
        endpoint_port: get_opt_u16(row, "endpoint-port")?,
        persistent_keepalive: get_opt_keepalive_seconds(row, "persistent-keepalive")?,
        disabled: get_bool_flag(row, "disabled"),
        id,
    })
}

pub async fn read_wireguard_peers(
    device: &MikrotikDevice,
) -> anyhow::Result<Vec<CurrentWireguardPeer>> {
    print(device, WIREGUARD_PEERS_PATH)
        .await?
        .iter()
        .map(parse_wireguard_peer)
        .collect()
}

pub async fn apply_wireguard_peers(
    device: &MikrotikDevice,
    plan: &Plan<DesiredWireguardPeer>,
) -> anyhow::Result<()> {
    fn attrs(d: &DesiredWireguardPeer) -> Vec<(&str, Option<&str>)> {
        vec![
            ("interface", Some(d.interface.as_str())),
            ("comment", Some(d.name.as_str())),
            ("public-key", Some(d.public_key_b64.as_str())),
            ("allowed-address", Some(d.allowed_address.as_str())),
            ("endpoint-address", d.endpoint_address.as_deref()),
            ("disabled", Some(if d.disabled { "yes" } else { "no" })),
        ]
    }
    for d in &plan.add {
        let mut a = attrs(d);
        let port_s;
        let ka_s;
        if let Some(p) = d.endpoint_port {
            port_s = p.to_string();
            a.push(("endpoint-port", Some(&port_s)));
        }
        if let Some(k) = d.persistent_keepalive {
            ka_s = k.to_string();
            a.push(("persistent-keepalive", Some(&ka_s)));
        }
        add(device, WIREGUARD_PEERS_PATH, &a).await?;
    }
    for (id, d) in &plan.update {
        let mut a = attrs(d);
        let port_s;
        let ka_s;
        if let Some(p) = d.endpoint_port {
            port_s = p.to_string();
            a.push(("endpoint-port", Some(&port_s)));
        }
        if let Some(k) = d.persistent_keepalive {
            ka_s = k.to_string();
            a.push(("persistent-keepalive", Some(&ka_s)));
        }
        set(device, WIREGUARD_PEERS_PATH, id, &a).await?;
    }
    for id in &plan.remove {
        remove(device, WIREGUARD_PEERS_PATH, id).await?;
    }
    Ok(())
}

// ── ip address ──

const IP_ADDRESS_PATH: &str = "/ip/address";

fn parse_ip_address(row: &Row) -> anyhow::Result<CurrentIpAddress> {
    let id = get_id(row)?;
    Ok(CurrentIpAddress {
        address: get_required(row, "address", &id)?.to_string(),
        interface: get_required(row, "interface", &id)?.to_string(),
        disabled: get_bool_flag(row, "disabled"),
        id,
    })
}

/// Reads every `ip address` row, pre-filtered to this tool's own footprint (mesh-* interfaces and
/// the loopback bridge) - see `diff::ip_addresses`'s doc comment on why an unfiltered read must
/// never reach that function.
pub async fn read_ip_addresses(
    device: &MikrotikDevice,
    our_interfaces: &[String],
) -> anyhow::Result<Vec<CurrentIpAddress>> {
    let rows = print(device, IP_ADDRESS_PATH).await?;
    rows.iter()
        .map(parse_ip_address)
        .filter(|r| match r {
            // `is_our_interface_name` additionally catches an address orphaned on a raw internal
            // id (`*16`) left behind after this tool deleted the `mesh-*` interface it was on -
            // without this, such a row is invisible to diff::ip_addresses and never cleaned up.
            Ok(a) => {
                our_interfaces.iter().any(|i| i == &a.interface)
                    || crate::diff::is_our_interface_name(&a.interface)
            }
            Err(_) => true, // surface parse errors, don't silently swallow them
        })
        .collect()
}

pub async fn apply_ip_addresses(
    device: &MikrotikDevice,
    plan: &Plan<DesiredIpAddress>,
) -> anyhow::Result<()> {
    for d in &plan.add {
        add(
            device,
            IP_ADDRESS_PATH,
            &[
                ("address", Some(d.address.as_str())),
                ("interface", Some(d.interface.as_str())),
                ("disabled", Some(if d.disabled { "yes" } else { "no" })),
            ],
        )
        .await?;
    }
    for (id, d) in &plan.update {
        set(
            device,
            IP_ADDRESS_PATH,
            id,
            &[("disabled", Some(if d.disabled { "yes" } else { "no" }))],
        )
        .await?;
    }
    for id in &plan.remove {
        remove(device, IP_ADDRESS_PATH, id).await?;
    }
    Ok(())
}

/// This device's own physically-connected subnets (every `ip address` interface that isn't a
/// `mesh-*` tunnel or the loopback bridge), normalized to network base - the BGP-announced prefix
/// set is computed fresh from this on every run, never configured (see AGENTS.md).
pub async fn read_physically_connected_prefixes(
    device: &MikrotikDevice,
    loopback_bridge: &str,
) -> anyhow::Result<Vec<String>> {
    let rows = print(device, IP_ADDRESS_PATH).await?;
    let mut prefixes = Vec::new();
    for row in &rows {
        let a = parse_ip_address(row)?;
        // Same recognizer as read_ip_addresses: excludes both live mesh-* interfaces and an
        // address orphaned on a deleted one's raw internal id - neither is a real physically-
        // connected LAN prefix worth announcing.
        if crate::diff::is_our_interface_name(&a.interface) || a.interface == loopback_bridge {
            continue;
        }
        match address_to_network(&a.address) {
            Ok(network) => prefixes.push(network),
            Err(e) => {
                tracing::warn!(address = %a.address, interface = %a.interface, error = %e, "skipping unparsable physically-connected address")
            }
        }
    }
    Ok(prefixes)
}

/// Normalizes a host address-with-prefix (as configured on an interface, e.g. `"192.168.88.1/24"`)
/// to its containing network base (`"192.168.88.0/24"`) - `ip address` rows carry the host
/// address, not the network, but a BGP-announced prefix must be the network itself.
fn address_to_network(address: &str) -> anyhow::Result<String> {
    let (addr, prefix_len) = slipmesh_core::cidr::parse_cidr(address)?;
    let network = Ipv4Addr::from(slipmesh_core::cidr::network_addr(
        u32::from(addr),
        prefix_len,
    ));
    Ok(format!("{network}/{prefix_len}"))
}

// ── interface list member ──

const LIST_MEMBER_PATH: &str = "/interface/list/member";

fn parse_list_member(row: &Row) -> anyhow::Result<CurrentListMember> {
    let id = get_id(row)?;
    Ok(CurrentListMember {
        list: get_required(row, "list", &id)?.to_string(),
        interface: get_required(row, "interface", &id)?.to_string(),
        disabled: get_bool_flag(row, "disabled"),
        id,
    })
}

/// Pre-filtered via `diff::is_our_list_member_footprint` - see that function's and
/// `diff::list_members`'s doc comments.
pub async fn read_list_members(
    device: &MikrotikDevice,
    desired_interfaces: &[String],
) -> anyhow::Result<Vec<CurrentListMember>> {
    let rows = print(device, LIST_MEMBER_PATH).await?;
    rows.iter()
        .map(parse_list_member)
        .filter(|r| match r {
            Ok(m) => {
                m.list == crate::config::LAN_LIST
                    && crate::diff::is_our_list_member_footprint(&m.interface, desired_interfaces)
            }
            Err(_) => true,
        })
        .collect()
}

pub async fn apply_list_members(
    device: &MikrotikDevice,
    plan: &Plan<DesiredListMember>,
) -> anyhow::Result<()> {
    for d in &plan.add {
        add(
            device,
            LIST_MEMBER_PATH,
            &[
                ("list", Some(d.list.as_str())),
                ("interface", Some(d.interface.as_str())),
                ("disabled", Some(if d.disabled { "yes" } else { "no" })),
            ],
        )
        .await?;
    }
    for (id, d) in &plan.update {
        set(
            device,
            LIST_MEMBER_PATH,
            id,
            &[("disabled", Some(if d.disabled { "yes" } else { "no" }))],
        )
        .await?;
    }
    for id in &plan.remove {
        remove(device, LIST_MEMBER_PATH, id).await?;
    }
    Ok(())
}

// ── interface bridge (loopback, singleton) ──

const BRIDGE_PATH: &str = "/interface/bridge";

pub async fn read_loopback_bridge(
    device: &MikrotikDevice,
    name: &str,
) -> anyhow::Result<Option<(String, DesiredBridge)>> {
    let rows = print(device, BRIDGE_PATH).await?;
    for row in &rows {
        let id = get_id(row)?;
        if get(row, "name") == Some(name) {
            return Ok(Some((
                id,
                DesiredBridge {
                    name: name.to_string(),
                    disabled: get_bool_flag(row, "disabled"),
                },
            )));
        }
    }
    Ok(None)
}

pub async fn apply_loopback_bridge(
    device: &MikrotikDevice,
    op: crate::diff::SingletonOp<DesiredBridge>,
) -> anyhow::Result<()> {
    use crate::diff::SingletonOp;
    match op {
        SingletonOp::NoOp => Ok(()),
        SingletonOp::Create(d) => add(
            device,
            BRIDGE_PATH,
            &[
                ("name", Some(d.name.as_str())),
                ("protocol-mode", Some("none")),
                ("disabled", Some(if d.disabled { "yes" } else { "no" })),
            ],
        )
        .await
        .map(|_| ()),
        SingletonOp::Update(id, d) => {
            set(
                device,
                BRIDGE_PATH,
                &id,
                &[("disabled", Some(if d.disabled { "yes" } else { "no" }))],
            )
            .await
        }
    }
}

// ── ipv6 address ──

const IPV6_ADDRESS_PATH: &str = "/ipv6/address";

/// True if `address` (an `"<ip>/<prefix>"` string as stored in an `ipv6 address` row) falls in
/// `fe80::/10` - RouterOS auto-generates an EUI-64 link-local on *every* interface (including
/// `mesh-*` ones and `router-lo`, both inside this tool's naming footprint) the moment it comes
/// up, entirely on its own, never something `routeros` created (`v2-v3.md` ловушка №2 - see
/// `AGENTS.md`'s OSPFv3/RFC 8950 section). Without this exclusion, `read_ipv6_addresses`'s
/// interface-name-based footprint match would wrongly treat every such auto-generated address as
/// "ours but no longer desired" and propose deleting it on every single run - found via a real
/// `--check --diff` against `hq`, breaking OSPFv3 neighbor formation (RouterOS's own link-local is
/// what the OSPFv3 hello packets actually use).
fn is_link_local_ipv6(address: &str) -> bool {
    address
        .split('/')
        .next()
        .and_then(|ip| ip.parse::<Ipv6Addr>().ok())
        .is_some_and(|addr| addr.segments()[0] & 0xffc0 == 0xfe80)
}

fn parse_ipv6_address(row: &Row) -> anyhow::Result<CurrentIpv6Address> {
    let id = get_id(row)?;
    Ok(CurrentIpv6Address {
        address: get_required(row, "address", &id)?.to_string(),
        interface: get_required(row, "interface", &id)?.to_string(),
        // Assumed boolean-flag-shaped exactly like `disabled` (explicit "true"/"false" on read,
        // "yes"/"no" accepted on write) - not independently confirmed against a real device in
        // this session, same caveat as this module's other unverified property names (see the
        // module doc comment).
        advertise: get_bool_flag(row, "advertise"),
        disabled: get_bool_flag(row, "disabled"),
        id,
    })
}

/// Reads every `ipv6 address` row, pre-filtered to this tool's own footprint (the loopback bridge
/// only - mesh-* interfaces get no static IPv6, RouterOS generates their link-local on its own) -
/// see `diff::ipv6_addresses`'s doc comment on why an unfiltered read must never reach that
/// function. `fe80::/10` rows are dropped unconditionally first, before the footprint match - see
/// `is_link_local_ipv6`'s doc comment.
pub async fn read_ipv6_addresses(
    device: &MikrotikDevice,
    our_interfaces: &[String],
) -> anyhow::Result<Vec<CurrentIpv6Address>> {
    let rows = print(device, IPV6_ADDRESS_PATH).await?;
    rows.iter()
        .map(parse_ipv6_address)
        .filter(|r| match r {
            // Link-local rows are excluded unconditionally, before the footprint match - see
            // is_link_local_ipv6's doc comment. Never something this tool created, regardless of
            // which interface RouterOS put it on.
            Ok(a) if is_link_local_ipv6(&a.address) => false,
            Ok(a) => {
                our_interfaces.iter().any(|i| i == &a.interface)
                    || crate::diff::is_our_interface_name(&a.interface)
            }
            Err(_) => true, // surface parse errors, don't silently swallow them
        })
        .collect()
}

pub async fn apply_ipv6_addresses(
    device: &MikrotikDevice,
    plan: &Plan<DesiredIpv6Address>,
) -> anyhow::Result<()> {
    for d in &plan.add {
        add(
            device,
            IPV6_ADDRESS_PATH,
            &[
                ("address", Some(d.address.as_str())),
                ("interface", Some(d.interface.as_str())),
                ("advertise", Some(if d.advertise { "yes" } else { "no" })),
                ("disabled", Some(if d.disabled { "yes" } else { "no" })),
            ],
        )
        .await?;
    }
    for (id, d) in &plan.update {
        set(
            device,
            IPV6_ADDRESS_PATH,
            id,
            &[
                ("advertise", Some(if d.advertise { "yes" } else { "no" })),
                ("disabled", Some(if d.disabled { "yes" } else { "no" })),
            ],
        )
        .await?;
    }
    for id in &plan.remove {
        remove(device, IPV6_ADDRESS_PATH, id).await?;
    }
    Ok(())
}

// ── routing ospf instance (singleton) ──

const OSPF_INSTANCE_PATH: &str = "/routing/ospf/instance";

pub async fn read_ospf_instance(
    device: &MikrotikDevice,
    name: &str,
) -> anyhow::Result<Option<(String, DesiredOspfInstance)>> {
    let rows = print(device, OSPF_INSTANCE_PATH).await?;
    for row in &rows {
        let id = get_id(row)?;
        if get(row, "name") == Some(name) {
            return Ok(Some((
                id,
                DesiredOspfInstance {
                    name: name.to_string(),
                    version: get(row, "version").unwrap_or("3").parse().unwrap_or(3),
                    router_id: get(row, "router-id")
                        .unwrap_or_default()
                        .parse()
                        .unwrap_or(Ipv4Addr::UNSPECIFIED),
                    disabled: get_bool_flag(row, "disabled"),
                },
            )));
        }
    }
    Ok(None)
}

/// `Update` now also sets `version` (not just `router-id`), attempting an in-place `2 -> 3`
/// transition for a device migrating from the pre-OSPFv3 scheme. Not independently confirmed
/// against a real device in this session whether RouterOS actually allows changing an OSPF
/// instance's `version` after creation - if it rejects this, the pre-existing OSPFv2 instance
/// needs a one-time manual `/routing ospf instance remove [find name=default-v2]` during the
/// migration window (mirrors `v2-v3.md`'s own explicit manual "disable OSPFv2" step - this table
/// is a name-owned singleton by design, not something to build automatic detection for).
pub async fn apply_ospf_instance(
    device: &MikrotikDevice,
    op: crate::diff::SingletonOp<DesiredOspfInstance>,
) -> anyhow::Result<()> {
    use crate::diff::SingletonOp;
    match op {
        SingletonOp::NoOp => Ok(()),
        SingletonOp::Create(d) => add(
            device,
            OSPF_INSTANCE_PATH,
            &[
                ("name", Some(d.name.as_str())),
                ("version", Some(&d.version.to_string())),
                ("router-id", Some(&d.router_id.to_string())),
            ],
        )
        .await
        .map(|_| ()),
        SingletonOp::Update(id, d) => {
            set(
                device,
                OSPF_INSTANCE_PATH,
                &id,
                &[
                    ("version", Some(&d.version.to_string())),
                    ("router-id", Some(&d.router_id.to_string())),
                ],
            )
            .await
        }
    }
}

// ── routing ospf area (singleton) ──

const OSPF_AREA_PATH: &str = "/routing/ospf/area";

pub async fn read_ospf_area(
    device: &MikrotikDevice,
    name: &str,
) -> anyhow::Result<Option<(String, DesiredOspfArea)>> {
    let rows = print(device, OSPF_AREA_PATH).await?;
    for row in &rows {
        let id = get_id(row)?;
        if get(row, "name") == Some(name) {
            return Ok(Some((
                id,
                DesiredOspfArea {
                    name: name.to_string(),
                    area_id: get(row, "area-id").unwrap_or_default().to_string(),
                    instance: get(row, "instance").unwrap_or_default().to_string(),
                    disabled: get_bool_flag(row, "disabled"),
                },
            )));
        }
    }
    Ok(None)
}

pub async fn apply_ospf_area(
    device: &MikrotikDevice,
    op: crate::diff::SingletonOp<DesiredOspfArea>,
) -> anyhow::Result<()> {
    use crate::diff::SingletonOp;
    match op {
        SingletonOp::NoOp => Ok(()),
        SingletonOp::Create(d) => add(
            device,
            OSPF_AREA_PATH,
            &[
                ("name", Some(d.name.as_str())),
                ("area-id", Some(d.area_id.as_str())),
                ("instance", Some(d.instance.as_str())),
            ],
        )
        .await
        .map(|_| ()),
        SingletonOp::Update(id, d) => {
            set(
                device,
                OSPF_AREA_PATH,
                &id,
                &[("instance", Some(d.instance.as_str()))],
            )
            .await
        }
    }
}

// ── routing ospf interface-template ──

const OSPF_TEMPLATE_PATH: &str = "/routing/ospf/interface-template";

fn parse_ospf_template(row: &Row) -> anyhow::Result<CurrentOspfInterfaceTemplate> {
    let id = get_id(row)?;
    Ok(CurrentOspfInterfaceTemplate {
        interfaces: get_required(row, "interfaces", &id)?.to_string(),
        area: get(row, "area").unwrap_or_default().to_string(),
        type_: get(row, "type").map(str::to_string),
        cost: get_opt_u16(row, "cost")?,
        hello_interval: get(row, "hello-interval").map(str::to_string),
        dead_interval: get(row, "dead-interval").map(str::to_string),
        passive_raw: get_flag_presence(row, "passive"),
        disabled: get_bool_flag(row, "disabled"),
        id,
    })
}

pub async fn read_ospf_interface_templates(
    device: &MikrotikDevice,
) -> anyhow::Result<Vec<CurrentOspfInterfaceTemplate>> {
    let rows = print(device, OSPF_TEMPLATE_PATH).await?;
    rows.iter().map(parse_ospf_template).collect()
}

pub async fn apply_ospf_interface_templates(
    device: &MikrotikDevice,
    plan: &Plan<DesiredOspfInterfaceTemplate>,
) -> anyhow::Result<()> {
    fn attrs(d: &DesiredOspfInterfaceTemplate) -> Vec<(&str, Option<&str>)> {
        let mut a = vec![
            ("interfaces", Some(d.interfaces.as_str())),
            ("area", Some(d.area.as_str())),
        ];
        if let Some(t) = &d.type_ {
            a.push(("type", Some(t.as_str())));
        }
        if let Some(h) = &d.hello_interval {
            a.push(("hello-interval", Some(h.as_str())));
        }
        if let Some(dead) = &d.dead_interval {
            a.push(("dead-interval", Some(dead.as_str())));
        }
        if d.passive {
            a.push(("passive", None));
        }
        a.push(("disabled", Some(if d.disabled { "yes" } else { "no" })));
        a
    }
    for d in &plan.add {
        let mut a = attrs(d);
        let cost_s;
        if let Some(c) = d.cost {
            cost_s = c.to_string();
            a.push(("cost", Some(&cost_s)));
        }
        add(device, OSPF_TEMPLATE_PATH, &a).await?;
    }
    for (id, d) in &plan.update {
        let mut a = attrs(d);
        let cost_s;
        if let Some(c) = d.cost {
            cost_s = c.to_string();
            a.push(("cost", Some(&cost_s)));
        }
        set(device, OSPF_TEMPLATE_PATH, id, &a).await?;
    }
    for id in &plan.remove {
        remove(device, OSPF_TEMPLATE_PATH, id).await?;
    }
    Ok(())
}

// ── ip firewall address-list (bgp-networks) ──

const ADDRESS_LIST_PATH: &str = "/ip/firewall/address-list";

fn parse_address_list_entry(row: &Row) -> anyhow::Result<CurrentAddressListEntry> {
    let id = get_id(row)?;
    Ok(CurrentAddressListEntry {
        list: get_required(row, "list", &id)?.to_string(),
        address: get_required(row, "address", &id)?.to_string(),
        disabled: get_bool_flag(row, "disabled"),
        id,
    })
}

pub async fn read_bgp_networks(
    device: &MikrotikDevice,
    list: &str,
) -> anyhow::Result<Vec<CurrentAddressListEntry>> {
    let rows = print(device, ADDRESS_LIST_PATH).await?;
    rows.iter()
        .map(parse_address_list_entry)
        .filter(|r| matches!(r, Ok(e) if e.list == list) || r.is_err())
        .collect()
}

pub async fn apply_bgp_networks(
    device: &MikrotikDevice,
    plan: &Plan<DesiredAddressListEntry>,
) -> anyhow::Result<()> {
    for d in &plan.add {
        add(
            device,
            ADDRESS_LIST_PATH,
            &[
                ("list", Some(d.list.as_str())),
                ("address", Some(d.address.as_str())),
                ("disabled", Some(if d.disabled { "yes" } else { "no" })),
            ],
        )
        .await?;
    }
    for (id, d) in &plan.update {
        set(
            device,
            ADDRESS_LIST_PATH,
            id,
            &[("disabled", Some(if d.disabled { "yes" } else { "no" }))],
        )
        .await?;
    }
    for id in &plan.remove {
        remove(device, ADDRESS_LIST_PATH, id).await?;
    }
    Ok(())
}

// ── routing bgp instance (singleton) ──

const BGP_INSTANCE_PATH: &str = "/routing/bgp/instance";

pub async fn read_bgp_instance(
    device: &MikrotikDevice,
    name: &str,
) -> anyhow::Result<Option<(String, crate::diff::DesiredBgpInstance)>> {
    let rows = print(device, BGP_INSTANCE_PATH).await?;
    for row in &rows {
        let id = get_id(row)?;
        if get(row, "name") == Some(name) {
            return Ok(Some((
                id,
                crate::diff::DesiredBgpInstance {
                    name: name.to_string(),
                    as_number: get(row, "as").unwrap_or("0").parse().unwrap_or(0),
                    router_id: get(row, "router-id")
                        .unwrap_or_default()
                        .parse()
                        .unwrap_or(Ipv4Addr::UNSPECIFIED),
                    routing_table: get(row, "routing-table").unwrap_or_default().to_string(),
                    disabled: get_bool_flag(row, "disabled"),
                },
            )));
        }
    }
    Ok(None)
}

pub async fn apply_bgp_instance(
    device: &MikrotikDevice,
    op: crate::diff::SingletonOp<crate::diff::DesiredBgpInstance>,
) -> anyhow::Result<()> {
    use crate::diff::SingletonOp;
    match op {
        SingletonOp::NoOp => Ok(()),
        SingletonOp::Create(d) => add(
            device,
            BGP_INSTANCE_PATH,
            &[
                ("name", Some(d.name.as_str())),
                ("as", Some(&d.as_number.to_string())),
                ("router-id", Some(&d.router_id.to_string())),
                ("routing-table", Some(d.routing_table.as_str())),
            ],
        )
        .await
        .map(|_| ()),
        SingletonOp::Update(id, d) => {
            set(
                device,
                BGP_INSTANCE_PATH,
                &id,
                &[
                    ("as", Some(&d.as_number.to_string())),
                    ("router-id", Some(&d.router_id.to_string())),
                ],
            )
            .await
        }
    }
}

// ── routing bgp connection ──

const BGP_CONNECTION_PATH: &str = "/routing/bgp/connection";

fn parse_bgp_connection(row: &Row) -> anyhow::Result<CurrentBgpConnection> {
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
        // `multihop`/`afi` are top-level connection properties, not nested under
        // `local.`/`remote.`/`output.` - confirmed against v2-v3.md's worked RouterOS config
        // (§4), not independently confirmed against a live device in this session.
        multihop: get_bool_flag(row, "multihop"),
        afi: get(row, "afi").unwrap_or_default().to_string(),
        output_network: get(row, "output.network").unwrap_or_default().to_string(),
        disabled: get_bool_flag(row, "disabled"),
        id,
    })
}

pub async fn read_bgp_connections(
    device: &MikrotikDevice,
) -> anyhow::Result<Vec<CurrentBgpConnection>> {
    print(device, BGP_CONNECTION_PATH)
        .await?
        .iter()
        .map(parse_bgp_connection)
        .collect()
}

pub async fn apply_bgp_connections(
    device: &MikrotikDevice,
    plan: &Plan<DesiredBgpConnection>,
) -> anyhow::Result<()> {
    fn attrs(d: &DesiredBgpConnection) -> Vec<(&str, Option<&str>)> {
        vec![
            ("name", Some(d.name.as_str())),
            ("instance", Some(d.instance.as_str())),
            ("local.role", Some(d.local_role.as_str())),
            ("multihop", Some(if d.multihop { "yes" } else { "no" })),
            ("afi", Some(d.afi.as_str())),
            ("output.network", Some(d.output_network.as_str())),
            ("disabled", Some(if d.disabled { "yes" } else { "no" })),
        ]
    }
    for d in &plan.add {
        let mut a = attrs(d);
        let local_s = d.local_address.to_string();
        let remote_s = d.remote_address.to_string();
        a.push(("local.address", Some(&local_s)));
        a.push(("remote.address", Some(&remote_s)));
        add(device, BGP_CONNECTION_PATH, &a).await?;
    }
    for (id, d) in &plan.update {
        // Full attrs(), not just the address pair: `multihop`/`afi` are now also part of the diff
        // comparison (see diff::bgp_connections) and must actually be pushed on a real drift, not
        // silently left stale.
        let mut a = attrs(d);
        let local_s = d.local_address.to_string();
        let remote_s = d.remote_address.to_string();
        a.push(("local.address", Some(&local_s)));
        a.push(("remote.address", Some(&remote_s)));
        set(device, BGP_CONNECTION_PATH, id, &a).await?;
    }
    for id in &plan.remove {
        remove(device, BGP_CONNECTION_PATH, id).await?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(pairs: &[(&str, &str)]) -> Row {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), Some(v.to_string())))
            .collect()
    }

    #[test]
    fn keepalive_seconds_strips_the_time_unit_suffix() {
        let r = row(&[(".id", "*1"), ("persistent-keepalive", "25s")]);
        assert_eq!(
            get_opt_keepalive_seconds(&r, "persistent-keepalive").unwrap(),
            Some(25)
        );
    }

    #[test]
    fn keepalive_seconds_accepts_a_bare_number_too() {
        let r = row(&[(".id", "*1"), ("persistent-keepalive", "25")]);
        assert_eq!(
            get_opt_keepalive_seconds(&r, "persistent-keepalive").unwrap(),
            Some(25)
        );
    }

    #[test]
    fn keepalive_seconds_absent_is_none() {
        let r = row(&[(".id", "*1")]);
        assert_eq!(
            get_opt_keepalive_seconds(&r, "persistent-keepalive").unwrap(),
            None
        );
    }

    #[test]
    fn parses_wireguard_interface_row() {
        let r = row(&[
            (".id", "*1"),
            ("name", "mesh-fra"),
            ("listen-port", "51820"),
            ("private-key", "abc="),
        ]);
        let iface = parse_wireguard_interface(&r).unwrap();
        assert_eq!(iface.id, "*1");
        assert_eq!(iface.name, "mesh-fra");
        assert_eq!(iface.listen_port, 51820);
        assert!(!iface.disabled);
    }

    #[test]
    fn missing_required_field_is_an_error() {
        let r = row(&[(".id", "*1"), ("listen-port", "51820")]);
        assert!(parse_wireguard_interface(&r).is_err());
    }

    #[test]
    fn wireguard_peer_uses_comment_as_the_label_field() {
        let r = row(&[
            (".id", "*2"),
            ("interface", "mesh-fra"),
            ("comment", "fra1"),
            ("public-key", "pub="),
            ("allowed-address", "0.0.0.0/0,::/0"),
        ]);
        let peer = parse_wireguard_peer(&r).unwrap();
        assert_eq!(peer.name, "fra1");
    }

    #[test]
    fn address_to_network_normalizes_host_address_to_network_base() {
        assert_eq!(
            address_to_network("192.168.88.5/24").unwrap(),
            "192.168.88.0/24"
        );
        assert_eq!(address_to_network("10.0.0.1/32").unwrap(), "10.0.0.1/32");
    }

    #[test]
    fn address_to_network_rejects_malformed_input() {
        assert!(address_to_network("not-an-address").is_err());
    }

    #[test]
    fn ospf_template_passive_raw_is_none_when_flag_absent() {
        let r = row(&[
            (".id", "*1"),
            ("interfaces", "mesh-fra"),
            ("area", "backbone"),
        ]);
        let t = parse_ospf_template(&r).unwrap();
        assert_eq!(t.passive_raw, None);
    }

    #[test]
    fn ospf_template_passive_raw_is_some_when_key_present_with_no_value() {
        // The exact wire shape confirmed against a real device: a passive row has the `passive`
        // key present with an empty/`None` inner value (`=passive=`), not a `"true"` string - a
        // plain `row.get("passive")` can't tell that apart from the key being absent entirely,
        // which is exactly the bug this regression test catches (see AGENTS.md/commit history).
        let mut r = row(&[
            (".id", "*1"),
            ("interfaces", "router-lo"),
            ("area", "backbone"),
        ]);
        r.insert("passive".to_string(), None);
        let t = parse_ospf_template(&r).unwrap();
        assert!(crate::diff::passive_flag_is_true(t.passive_raw.as_deref()));
    }

    #[test]
    fn parses_ipv6_address_row() {
        let r = row(&[
            (".id", "*1"),
            ("address", "fd00::1/128"),
            ("interface", "router-lo"),
            ("advertise", "false"),
        ]);
        let a = parse_ipv6_address(&r).unwrap();
        assert_eq!(a.address, "fd00::1/128");
        assert_eq!(a.interface, "router-lo");
        assert!(!a.advertise);
    }

    #[test]
    fn recognizes_link_local_addresses_regardless_of_prefix_length() {
        // Real fe80::/10 addresses RouterOS auto-generates via EUI-64 - confirmed against a real
        // device via --check --diff (see is_link_local_ipv6's doc comment).
        assert!(is_link_local_ipv6("fe80::bff6:4220:a333:c1d1/64"));
        assert!(is_link_local_ipv6("fe80::f044:89ff:fe2c:3247/64"));
        assert!(!is_link_local_ipv6("fd00::1/128"));
        assert!(!is_link_local_ipv6("fd3d:c741:faa9::a3e:ff/128"));
    }

    #[test]
    fn parses_bgp_connection_row_with_ipv6_addresses_and_multihop_afi() {
        let r = row(&[
            (".id", "*1"),
            ("name", "bgp-fra"),
            ("instance", "default"),
            ("local.address", "fd00::1"),
            ("local.role", "ibgp"),
            ("remote.address", "fd00::2"),
            ("multihop", "true"),
            ("afi", "ip"),
            ("output.network", "bgp-networks"),
        ]);
        let c = parse_bgp_connection(&r).unwrap();
        assert_eq!(c.local_address, "fd00::1".parse::<Ipv6Addr>().unwrap());
        assert_eq!(c.remote_address, "fd00::2".parse::<Ipv6Addr>().unwrap());
        assert!(c.multihop);
        assert_eq!(c.afi, "ip");
    }
}
