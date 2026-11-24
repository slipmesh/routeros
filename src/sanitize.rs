//! Allow-list validation of a WireGuard peer's `endpoint` host before it reaches a RouterOS command
//! attribute. `mikrotik-rs`'s `CommandBuilder` sends each attribute as its own length-prefixed API
//! word, so no separator can break out of it, but a malformed value still makes a confusing or
//! rejected command on the device. Interface and BGP connection names (`InterfaceEntry::name`,
//! `BgpPeerEntry::name`) reach the device as the config's checks leave them: non-empty, unique, an
//! interface name within 15 bytes.

/// The host part of a `PeerEntry::endpoint` (`"host:port"`, port already split off
/// by `config::parse_endpoint`), used directly as a RouterOS `endpoint-address`. Allows what a
/// hostname or IPv4/IPv6 literal can actually contain: alphanumerics, `.`, `-`, `:`.
pub fn validate_endpoint(endpoint: &str) -> anyhow::Result<()> {
    anyhow::ensure!(!endpoint.is_empty(), "endpoint must not be empty");
    anyhow::ensure!(
        endpoint
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == ':'),
        "endpoint {endpoint:?} contains characters outside [a-zA-Z0-9.:-]"
    );
    Ok(())
}

#[cfg(test)]
mod validate_endpoint_tests {
    use super::*;

    #[test]
    fn accepts_hostnames_and_addresses_and_nothing_else() {
        for (endpoint, accepted) in [
            ("router1.example.com", true),
            ("192.0.2.1", true),
            ("2001:db8::1", true),
            ("", false),
            ("router1.example.com;evil", false),
            ("router1.example.com evil", false),
            ("router1.example.com\"", false),
            ("router1.example.com\0", false),
        ] {
            assert_eq!(
                validate_endpoint(endpoint).is_ok(),
                accepted,
                "{endpoint:?}"
            );
        }
    }
}
