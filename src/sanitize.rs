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
    fn accepts_hostnames_and_addresses() {
        assert!(validate_endpoint("router1.example.com").is_ok());
        assert!(validate_endpoint("192.0.2.1").is_ok());
        assert!(validate_endpoint("2001:db8::1").is_ok());
    }

    #[test]
    fn rejects_empty() {
        assert!(validate_endpoint("").is_err());
    }

    #[test]
    fn rejects_embedded_semicolon_and_whitespace() {
        assert!(validate_endpoint("router1.example.com;evil").is_err());
        assert!(validate_endpoint("router1.example.com evil").is_err());
    }

    #[test]
    fn rejects_quotes_and_control_characters() {
        assert!(validate_endpoint("router1.example.com\"").is_err());
        assert!(validate_endpoint("router1.example.com\n").is_err());
        assert!(validate_endpoint("router1.example.com\0").is_err());
    }
}
