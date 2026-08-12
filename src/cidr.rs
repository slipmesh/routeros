//! Small local IPv4 CIDR helpers, replacing the `slipmesh_core::cidr` module that went away with
//! the Kubernetes/`slipmesh-core` dependency. Everything this tool announces over BGP
//! (`ip firewall address-list`, RouterOS's IPv4-only address-list mechanism) and everything
//! `router::config::RouterConfig::learn` describes is IPv4, so IPv6 support isn't needed here.

use std::net::Ipv4Addr;

pub fn parse_cidr(s: &str) -> anyhow::Result<(Ipv4Addr, u8)> {
    let (addr, prefix) = s
        .split_once('/')
        .ok_or_else(|| anyhow::anyhow!("{s:?} is not a CIDR (missing '/')"))?;
    let addr: Ipv4Addr = addr
        .parse()
        .map_err(|e| anyhow::anyhow!("{s:?}: invalid IPv4 address: {e}"))?;
    let prefix: u8 = prefix
        .parse()
        .map_err(|e| anyhow::anyhow!("{s:?}: invalid prefix length: {e}"))?;
    anyhow::ensure!(prefix <= 32, "{s:?}: prefix length {prefix} exceeds 32");
    Ok((addr, prefix))
}

pub fn network_addr(addr: Ipv4Addr, prefix_len: u8) -> Ipv4Addr {
    let mask = if prefix_len == 0 {
        0
    } else {
        u32::MAX << (32 - prefix_len)
    };
    Ipv4Addr::from(u32::from(addr) & mask)
}

/// True if `candidate` (an exact CIDR, typically a `/32` host route) falls entirely within
/// `range`. Used to match `physically_connected` prefixes against `RouterConfig::learn` ranges.
pub fn cidr_contains(range: &str, candidate: &str) -> anyhow::Result<bool> {
    let (range_addr, range_prefix) = parse_cidr(range)?;
    let (cand_addr, cand_prefix) = parse_cidr(candidate)?;
    if cand_prefix < range_prefix {
        return Ok(false);
    }
    Ok(network_addr(range_addr, range_prefix) == network_addr(cand_addr, range_prefix))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_cidr_splits_address_and_prefix() {
        let (addr, prefix) = parse_cidr("192.168.88.5/24").unwrap();
        assert_eq!(addr, Ipv4Addr::new(192, 168, 88, 5));
        assert_eq!(prefix, 24);
    }

    #[test]
    fn parse_cidr_rejects_missing_slash() {
        assert!(parse_cidr("192.168.88.5").is_err());
    }

    #[test]
    fn parse_cidr_rejects_prefix_over_32() {
        assert!(parse_cidr("192.168.88.5/33").is_err());
    }

    #[test]
    fn network_addr_masks_host_bits() {
        assert_eq!(
            network_addr(Ipv4Addr::new(192, 168, 88, 5), 24),
            Ipv4Addr::new(192, 168, 88, 0)
        );
        assert_eq!(
            network_addr(Ipv4Addr::new(10, 0, 0, 1), 32),
            Ipv4Addr::new(10, 0, 0, 1)
        );
        assert_eq!(
            network_addr(Ipv4Addr::new(10, 0, 0, 1), 0),
            Ipv4Addr::UNSPECIFIED
        );
    }

    #[test]
    fn cidr_contains_true_when_candidate_is_inside_range() {
        assert!(cidr_contains("10.99.0.0/24", "10.99.0.5/32").unwrap());
    }

    #[test]
    fn cidr_contains_false_when_candidate_is_outside_range() {
        assert!(!cidr_contains("10.99.0.0/24", "10.100.0.5/32").unwrap());
    }

    #[test]
    fn cidr_contains_false_when_candidate_is_broader_than_range() {
        assert!(!cidr_contains("10.99.0.5/32", "10.99.0.0/24").unwrap());
    }
}
