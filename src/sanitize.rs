//! Allow-list validation for any string sourced from the patch file (`awg`/`router` documents,
//! themselves already validated by `patches generate`/`awg::config::validate`/
//! `router::config::validate`) before it reaches a RouterOS command attribute. `mikrotik-rs`'s
//! `CommandBuilder` transmits each attribute as its own length-prefixed API word - there's no
//! single concatenated command line for an embedded separator to break out of the way there is for
//! BIRD config text or an nftables ruleset - but a malformed value can still produce a confusing or
//! outright rejected command on the device. Validate here, fail fast with a clear error, rather
//! than send an unvalidated value to a live device.
//!
//! Most identifiers `routeros` builds today are mesh-interface/BGP-connection names derived
//! straight from `AwgConfig`/`RouterConfig` fields that are already syntax-constrained upstream
//! (`InterfaceEntry::name`, `BgpPeerEntry::name`) - the one field with genuinely free-form syntax
//! is a WireGuard peer's `endpoint` host, hence the single validator below.

/// The host part of an `awg::config::PeerEntry::endpoint` (`"host:port"`, port already split off
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
        assert!(validate_endpoint("hq.int.example.com").is_ok());
        assert!(validate_endpoint("192.168.88.1").is_ok());
        assert!(validate_endpoint("2001:db8::1").is_ok());
    }

    #[test]
    fn rejects_empty() {
        assert!(validate_endpoint("").is_err());
    }

    #[test]
    fn rejects_embedded_semicolon_and_whitespace() {
        assert!(validate_endpoint("hq.example.com;evil").is_err());
        assert!(validate_endpoint("hq.example.com evil").is_err());
    }

    #[test]
    fn rejects_quotes_and_control_characters() {
        assert!(validate_endpoint("hq.example.com\"").is_err());
        assert!(validate_endpoint("hq.example.com\n").is_err());
        assert!(validate_endpoint("hq.example.com\0").is_err());
    }
}
