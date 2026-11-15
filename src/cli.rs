//! CLI surface: `slipmesh-routeros --node=router1 [--check] [--diff] [--config slipmesh.yaml]`,
//! modeled on `ansible-playbook --check --diff`.

use clap::Parser;
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(
    name = env!("CARGO_BIN_NAME"),
    bin_name = env!("CARGO_BIN_NAME"),
    version,
    about = "Converges a MikroTik RouterOS device to the desired state of its node in slipmesh.yaml"
)]
pub struct Cli {
    /// The device's node in slipmesh.yaml.
    #[arg(long)]
    pub node: String,

    /// Compute the diff against the device's current state but never apply it.
    #[arg(long)]
    pub check: bool,

    /// Print the computed add/update/remove plan to stdout - independent of --check.
    #[arg(long)]
    pub diff: bool,

    /// slipmesh.yaml as plain text; a wrapper that decrypts it passes its path here.
    #[arg(long, default_value = "slipmesh.yaml")]
    pub config: PathBuf,
}

impl Cli {
    pub fn applies(&self) -> bool {
        !self.check
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parsed(args: &[&str]) -> Cli {
        Cli::try_parse_from([&["slipmesh-routeros", "--node", "router1"], args].concat()).unwrap()
    }

    #[test]
    fn a_check_run_never_applies_and_any_other_run_does() {
        assert!(!parsed(&["--check"]).applies());
        assert!(!parsed(&["--check", "--diff"]).applies());
        assert!(parsed(&[]).applies());
        assert!(parsed(&["--diff"]).applies());
    }
}
