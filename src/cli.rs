//! CLI surface: `routeros --node=router1 [--patches-dir=patches] [--check] [--diff]`,
//! modeled on `ansible-playbook --check --diff`.

use clap::Parser;

#[derive(Parser, Debug)]
#[command(
    name = "routeros",
    version,
    about = "Converges a MikroTik RouterOS device to the desired state computed by talos-extensions/patches"
)]
pub struct Cli {
    /// Node name - reads `<patches-dir>/<node>.yaml`, the patch file `talos-extensions/patches
    /// generate` produces for this node from `mesh.yaml`.
    #[arg(long)]
    pub node: String,

    /// Directory containing `talos-extensions/patches generate`'s output - same default/
    /// convention as that tool's own `--patches-dir`.
    #[arg(long, default_value = "patches")]
    pub patches_dir: String,

    /// Compute the diff against the device's current state but never apply it.
    #[arg(long)]
    pub check: bool,

    /// Print the computed add/update/remove plan to stdout - independent of --check.
    #[arg(long)]
    pub diff: bool,
}
