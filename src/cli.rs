//! CLI surface: `slipmesh-routeros --node=router1 [--patches-dir=patches] [--check] [--diff]`,
//! modeled on `ansible-playbook --check --diff`.

use clap::Parser;

#[derive(Parser, Debug)]
#[command(
    name = env!("CARGO_BIN_NAME"),
    bin_name = env!("CARGO_BIN_NAME"),
    version,
    about = "Converges a MikroTik RouterOS device to the desired state computed by slipmesh-taloscfg"
)]
pub struct Cli {
    /// Node name - reads `<patches-dir>/<node>.yaml`, the patch file `slipmesh-taloscfg generate`
    /// produces for this node from `slipmesh.yaml`.
    #[arg(long)]
    pub node: String,

    /// Directory containing `slipmesh-taloscfg generate`'s output - same default as that tool's
    /// own `--patches-dir`.
    #[arg(long, default_value = "patches")]
    pub patches_dir: String,

    /// Compute the diff against the device's current state but never apply it.
    #[arg(long)]
    pub check: bool,

    /// Print the computed add/update/remove plan to stdout - independent of --check.
    #[arg(long)]
    pub diff: bool,
}
