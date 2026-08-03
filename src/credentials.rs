//! Parses RouterOS API connection credentials from a Kubernetes `Secret` - fully externally
//! managed (a human/other process creates and rotates it), `routeros` only ever reads it.

use k8s_openapi::api::core::v1::Secret;

const DEFAULT_PORT: u16 = 8729; // RouterOS API-SSL default - TLS is mandatory, see AGENTS.md.

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouterCredentials {
    pub host: String,
    pub port: u16,
    pub username: String,
    /// `None` when the `password` key is absent from the Secret; `Some(String::new())` when it's
    /// present but empty - `mikrotik-rs` treats these differently (`Option<&str>`).
    pub password: Option<String>,
}

fn field(secret: &Secret, key: &str) -> anyhow::Result<Option<String>> {
    let Some(data) = secret.data.as_ref() else {
        return Ok(None);
    };
    let Some(value) = data.get(key) else {
        return Ok(None);
    };
    Ok(Some(
        std::str::from_utf8(&value.0)
            .map_err(|e| anyhow::anyhow!("Secret field {key:?} is not valid UTF-8: {e}"))?
            .to_string(),
    ))
}

pub fn parse_from_secret(secret: &Secret) -> anyhow::Result<RouterCredentials> {
    let host = field(secret, "host")?
        .filter(|s| !s.is_empty())
        .ok_or_else(|| anyhow::anyhow!("Secret is missing required field \"host\""))?;

    let port = match field(secret, "port")? {
        Some(raw) => raw
            .parse::<u16>()
            .map_err(|e| anyhow::anyhow!("Secret field \"port\" ({raw:?}) is invalid: {e}"))?,
        None => DEFAULT_PORT,
    };

    let username = field(secret, "username")?
        .filter(|s| !s.is_empty())
        .ok_or_else(|| anyhow::anyhow!("Secret is missing required field \"username\""))?;

    let password = field(secret, "password")?;

    Ok(RouterCredentials {
        host,
        port,
        username,
        password,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use k8s_openapi::ByteString;
    use std::collections::BTreeMap;

    fn secret(fields: &[(&str, &str)]) -> Secret {
        let data: BTreeMap<String, ByteString> = fields
            .iter()
            .map(|(k, v)| (k.to_string(), ByteString(v.as_bytes().to_vec())))
            .collect();
        Secret {
            data: Some(data),
            ..Default::default()
        }
    }

    #[test]
    fn parses_all_fields() {
        let s = secret(&[
            ("host", "192.168.88.1"),
            ("port", "8729"),
            ("username", "ansible"),
            ("password", "hunter2"),
        ]);
        let creds = parse_from_secret(&s).unwrap();
        assert_eq!(creds.host, "192.168.88.1");
        assert_eq!(creds.port, 8729);
        assert_eq!(creds.username, "ansible");
        assert_eq!(creds.password, Some("hunter2".to_string()));
    }

    #[test]
    fn missing_host_is_an_error() {
        let s = secret(&[("username", "ansible")]);
        assert!(parse_from_secret(&s).is_err());
    }

    #[test]
    fn missing_username_is_an_error() {
        let s = secret(&[("host", "192.168.88.1")]);
        assert!(parse_from_secret(&s).is_err());
    }

    #[test]
    fn missing_port_defaults_to_api_ssl_port() {
        let s = secret(&[("host", "192.168.88.1"), ("username", "ansible")]);
        let creds = parse_from_secret(&s).unwrap();
        assert_eq!(creds.port, DEFAULT_PORT);
    }

    #[test]
    fn invalid_port_is_an_error() {
        let s = secret(&[
            ("host", "192.168.88.1"),
            ("username", "ansible"),
            ("port", "not-a-number"),
        ]);
        assert!(parse_from_secret(&s).is_err());
    }

    #[test]
    fn missing_password_is_none() {
        let s = secret(&[("host", "192.168.88.1"), ("username", "ansible")]);
        let creds = parse_from_secret(&s).unwrap();
        assert_eq!(creds.password, None);
    }

    #[test]
    fn empty_password_is_some_empty_string() {
        let s = secret(&[
            ("host", "192.168.88.1"),
            ("username", "ansible"),
            ("password", ""),
        ]);
        let creds = parse_from_secret(&s).unwrap();
        assert_eq!(creds.password, Some(String::new()));
    }

    #[test]
    fn no_data_at_all_is_an_error() {
        let s = Secret {
            data: None,
            ..Default::default()
        };
        assert!(parse_from_secret(&s).is_err());
    }
}
