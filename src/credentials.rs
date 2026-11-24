//! RouterOS API connection credentials, from the environment of the process. They are not part of
//! the mesh's desired state, and an environment variable never shows up in a process listing the
//! way a command-line flag does.

use anyhow::{Context, bail};
use std::env::VarError;

const DEFAULT_PORT: u16 = 8729; // RouterOS API-SSL default - TLS is mandatory.

pub const HOST: &str = "SLIPMESH_ROUTEROS_HOST";
pub const PORT: &str = "SLIPMESH_ROUTEROS_PORT";
pub const USERNAME: &str = "SLIPMESH_ROUTEROS_USERNAME";
pub const PASSWORD: &str = "SLIPMESH_ROUTEROS_PASSWORD";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouterCredentials {
    pub host: String,
    pub port: u16,
    pub username: String,
    /// `None` when `SLIPMESH_ROUTEROS_PASSWORD` is unset; `Some(String::new())` when it is set
    /// but empty - `mikrotik-rs` treats these differently (`Option<&str>`).
    pub password: Option<String>,
}

pub fn from_env() -> anyhow::Result<RouterCredentials> {
    from_lookup(|name| std::env::var(name))
}

/// `var` answers the way `std::env::var` does.
pub fn from_lookup(
    var: impl Fn(&str) -> Result<String, VarError>,
) -> anyhow::Result<RouterCredentials> {
    let optional = |name: &str| match var(name) {
        Ok(value) => Ok(Some(value)),
        Err(VarError::NotPresent) => Ok(None),
        Err(VarError::NotUnicode(_)) => bail!("{name} is not valid unicode"),
    };
    let required = |name: &str| match optional(name)? {
        Some(value) if !value.is_empty() => Ok(value),
        _ => bail!("{name} is not set"),
    };

    let host = required(HOST)?;
    let username = required(USERNAME)?;
    let port = match optional(PORT)? {
        Some(port) => port
            .parse()
            .with_context(|| format!("{PORT} is not a port number: {port:?}"))?,
        None => DEFAULT_PORT,
    };
    Ok(RouterCredentials {
        host,
        port,
        username,
        password: optional(PASSWORD)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::ffi::OsString;

    fn lookup(vars: &[(&str, &str)]) -> impl Fn(&str) -> Result<String, VarError> {
        let vars: HashMap<String, String> = vars
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect();
        move |name| vars.get(name).cloned().ok_or(VarError::NotPresent)
    }

    fn error(vars: &[(&str, &str)]) -> String {
        format!("{:#}", from_lookup(lookup(vars)).unwrap_err())
    }

    #[test]
    fn reads_all_four_variables() {
        let creds = from_lookup(lookup(&[
            (HOST, "203.0.113.1"),
            (PORT, "8730"),
            (USERNAME, "automation"),
            (PASSWORD, "example-password"),
        ]))
        .unwrap();
        assert_eq!(
            creds,
            RouterCredentials {
                host: "203.0.113.1".to_owned(),
                port: 8730,
                username: "automation".to_owned(),
                password: Some("example-password".to_owned()),
            }
        );
    }

    #[test]
    fn a_missing_empty_or_malformed_variable_is_an_error_naming_it() {
        let host = (HOST, "203.0.113.1");
        let username = (USERNAME, "automation");
        let cases: &[(&[(&str, &str)], &str)] = &[
            (&[username], HOST),
            (&[(HOST, ""), username], HOST),
            (&[host], USERNAME),
            (&[host, (USERNAME, "")], USERNAME),
            (&[host, username, (PORT, "")], PORT),
            (&[host, username, (PORT, "x")], PORT),
            (&[host, username, (PORT, "65536")], PORT),
            (&[host, username, (PORT, "-1")], PORT),
        ];
        for (vars, named) in cases {
            let err = error(vars);
            assert!(err.contains(named), "{vars:?}: {err}");
        }
    }

    #[test]
    fn an_unset_port_is_the_api_ssl_port_and_an_unset_password_none() {
        let creds =
            from_lookup(lookup(&[(HOST, "203.0.113.1"), (USERNAME, "automation")])).unwrap();
        assert_eq!((creds.port, creds.password), (DEFAULT_PORT, None));
    }

    #[test]
    fn an_empty_password_is_some_empty_string() {
        let creds = from_lookup(lookup(&[
            (HOST, "203.0.113.1"),
            (USERNAME, "automation"),
            (PASSWORD, ""),
        ]));
        assert_eq!(creds.unwrap().password, Some(String::new()));
    }

    #[test]
    fn a_variable_that_is_not_unicode_is_an_error_naming_it() {
        for name in [HOST, PORT, USERNAME, PASSWORD] {
            let base = lookup(&[(HOST, "203.0.113.1"), (USERNAME, "automation")]);
            let var = |n: &str| {
                if n == name {
                    Err(VarError::NotUnicode(OsString::from("x")))
                } else {
                    base(n)
                }
            };
            let err = format!("{:#}", from_lookup(var).unwrap_err());
            assert!(err.contains(name), "{name}: {err}");
        }
    }
}
