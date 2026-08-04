//! CLI surface - see AGENTS.md: `routeros --node=hq [--check] [--diff]`, modeled on
//! `ansible-playbook --check --diff`.

use clap::Parser;

#[derive(Parser, Debug)]
#[command(
    name = "routeros",
    version,
    about = "Converges a MikroTik RouterOS device to the slipmesh mesh's desired state"
)]
pub struct Cli {
    /// Name of the MeshNode/RouterNode pair identifying this physical router - both must already
    /// exist in the slipmesh namespace (created by a human/GitOps ahead of time).
    #[arg(long)]
    pub node: String,

    /// Compute the diff against the device's current state but never apply it.
    #[arg(long)]
    pub check: bool,

    /// Print the computed add/update/remove plan to stdout - independent of --check.
    #[arg(long)]
    pub diff: bool,
}
