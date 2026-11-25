//! CLI surface: `slipmesh-routeros --node=router1 [--check] [--diff] --in <files>...`, modeled on
//! `ansible-playbook --check --diff`.

use clap::Parser;
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(
    name = env!("CARGO_BIN_NAME"),
    bin_name = env!("CARGO_BIN_NAME"),
    version,
    about = "Converges a MikroTik RouterOS device to its node's desired state in slipmesh.yaml"
)]
pub struct Cli {
    /// The device's node in the files.
    #[arg(long)]
    pub node: String,

    /// Compute the diff against the device's current state but never apply it.
    #[arg(long)]
    pub check: bool,

    /// Print the computed add/update/remove plan to stdout - independent of --check.
    #[arg(long)]
    pub diff: bool,

    /// The files of slipmesh.yaml as plain text, laid over each other; may be repeated. A wrapper
    /// that decrypts them passes their paths here.
    #[arg(long = "in", num_args = 1.., required = true)]
    pub inputs: Vec<PathBuf>,
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
        let base = [
            "slipmesh-routeros",
            "--node",
            "router1",
            "--in",
            "slipmesh.yaml",
        ];
        Cli::try_parse_from([&base[..], args].concat()).unwrap()
    }

    #[test]
    fn a_check_run_never_applies_and_any_other_run_does() {
        assert!(!parsed(&["--check"]).applies());
        assert!(!parsed(&["--check", "--diff"]).applies());
        assert!(parsed(&[]).applies());
        assert!(parsed(&["--diff"]).applies());
    }
}
