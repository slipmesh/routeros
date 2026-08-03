//! Allow-list validation for any string sourced from a CRD (`MeshNode`/`RouterNode`/`MeshLink`)
//! before it reaches a RouterOS command attribute. `mikrotik-rs`'s `CommandBuilder` transmits each
//! attribute as its own length-prefixed API word - there's no single concatenated command line for
//! an embedded separator to break out of the way there is for BIRD config text or an nftables
//! ruleset - but a malformed value can still produce a confusing or outright rejected command on
//! the device, and `slipmesh_core::desired_state::bgp_peers_from`'s own doc comment is explicit
//! that identifier sanitization is deliberately left to each consumer. Validate here, fail fast
//! with a clear error, rather than send an unvalidated value to a live device.

/// `mesh_label`/`router_label` - already constrained by the CRD schema
/// (`^[a-zA-Z0-9_-]+$`, length 1-10) but re-validated here as defense in depth: a schema can be
/// bypassed (disabled admission, an object created before the constraint existed), and this value
/// is about to become part of a RouterOS interface/connection name.
pub fn validate_label(label: &str) -> anyhow::Result<()> {
    anyhow::ensure!(!label.is_empty(), "label must not be empty");
    anyhow::ensure!(
        label.len() <= 10,
        "label {label:?} is too long (max 10 characters)"
    );
    anyhow::ensure!(
        label
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-'),
        "label {label:?} contains characters outside [a-zA-Z0-9_-]"
    );
    Ok(())
}

/// `MeshNode.spec.endpoint` - a free-form string with no CRD-level regex/length constraint (unlike
/// `mesh_label`/`router_label`), used directly as a RouterOS `endpoint-address`. Allows what a
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
mod validate_label_tests {
    use super::*;

    #[test]
    fn accepts_a_typical_label() {
        assert!(validate_label("hq").is_ok());
        assert!(validate_label("node-f").is_ok());
        assert!(validate_label("fra_1").is_ok());
    }

    #[test]
    fn rejects_empty() {
        assert!(validate_label("").is_err());
    }

    #[test]
    fn rejects_too_long() {
        assert!(validate_label("012345678901").is_err());
    }

    #[test]
    fn rejects_embedded_semicolon() {
        // Adversarial payload: an attacker-controlled mesh_label trying to break out of the
        // expected identifier shape - must be rejected outright, not passed through.
        assert!(validate_label("hq;evil").is_err());
    }

    #[test]
    fn rejects_embedded_whitespace_and_quotes() {
        assert!(validate_label("hq 1").is_err());
        assert!(validate_label("hq\"1").is_err());
        assert!(validate_label("hq\n1").is_err());
    }
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
