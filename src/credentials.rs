//! Parses RouterOS API connection credentials from the `mikrotik` YAML document embedded in a
//! `talos-extensions/patches`-generated patch file - a hand-authored, foreign (non-`OWNED_NAMES`)
//! `ExtensionServiceConfig` document that `patches generate` preserves byte-for-byte across
//! regeneration. Fully externally managed (a human edits/rotates it directly in the patch file),
//! `routeros` only ever reads it.

use serde::Deserialize;

const DEFAULT_PORT: u16 = 8729; // RouterOS API-SSL default - TLS is mandatory.

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouterCredentials {
    pub host: String,
    pub port: u16,
    pub username: String,
    /// `None` when the `password` key is absent from the document; `Some(String::new())` when
    /// it's present but empty - `mikrotik-rs` treats these differently (`Option<&str>`).
    pub password: Option<String>,
}

#[derive(Deserialize, Default)]
struct RawCredentials {
    host: Option<String>,
    port: Option<u16>,
    username: Option<String>,
    password: Option<String>,
}

pub fn parse_from_yaml(content: &str) -> anyhow::Result<RouterCredentials> {
    let raw: RawCredentials = serde_yaml::from_str(content)
        .map_err(|e| anyhow::anyhow!("mikrotik credentials document is not valid YAML: {e}"))?;

    let host = raw
        .host
        .filter(|s| !s.is_empty())
        .ok_or_else(|| anyhow::anyhow!("mikrotik credentials document is missing \"host\""))?;

    let username = raw
        .username
        .filter(|s| !s.is_empty())
        .ok_or_else(|| anyhow::anyhow!("mikrotik credentials document is missing \"username\""))?;

    Ok(RouterCredentials {
        host,
        port: raw.port.unwrap_or(DEFAULT_PORT),
        username,
        password: raw.password,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_all_fields() {
        let yaml = "host: 192.168.88.1\nport: 8729\nusername: ansible\npassword: hunter2\n";
        let creds = parse_from_yaml(yaml).unwrap();
        assert_eq!(creds.host, "192.168.88.1");
        assert_eq!(creds.port, 8729);
        assert_eq!(creds.username, "ansible");
        assert_eq!(creds.password, Some("hunter2".to_string()));
    }

    #[test]
    fn missing_host_is_an_error() {
        assert!(parse_from_yaml("username: ansible\n").is_err());
    }

    #[test]
    fn missing_username_is_an_error() {
        assert!(parse_from_yaml("host: 192.168.88.1\n").is_err());
    }

    #[test]
    fn missing_port_defaults_to_api_ssl_port() {
        let creds = parse_from_yaml("host: 192.168.88.1\nusername: ansible\n").unwrap();
        assert_eq!(creds.port, DEFAULT_PORT);
    }

    #[test]
    fn missing_password_is_none() {
        let creds = parse_from_yaml("host: 192.168.88.1\nusername: ansible\n").unwrap();
        assert_eq!(creds.password, None);
    }

    #[test]
    fn empty_password_is_some_empty_string() {
        let creds =
            parse_from_yaml("host: 192.168.88.1\nusername: ansible\npassword: \"\"\n").unwrap();
        assert_eq!(creds.password, Some(String::new()));
    }

    #[test]
    fn malformed_yaml_is_an_error() {
        assert!(parse_from_yaml("host: [unterminated\n").is_err());
    }

    #[test]
    fn empty_document_is_an_error() {
        assert!(parse_from_yaml("").is_err());
    }
}
