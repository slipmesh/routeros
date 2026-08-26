//! The one-shot pipeline: read the patch file once, connect to the device once, converge, exit.
//! No Kubernetes, no reflectors/watch, no state carried between invocations.

use crate::cli::Cli;
use crate::config;
use crate::converge::{self, ConvergeReport};
use crate::patch;
use anyhow::Context;
use std::path::Path;

pub async fn run(cli: &Cli) -> anyhow::Result<ConvergeReport> {
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .map_err(|_| anyhow::anyhow!("failed to install default rustls crypto provider"))?;

    let path = Path::new(&cli.patches_dir).join(format!("{}.yaml", cli.node));
    let patch_file = patch::read_patch_file(&path)
        .with_context(|| format!("failed to read patch file {}", path.display()))?;

    let device = crate::mikrotik::connect(&patch_file.credentials)
        .await
        .context("failed to connect to the RouterOS device")?;

    let physically_connected =
        crate::mikrotik::read_physically_connected_prefixes(&device, config::LOOPBACK_BRIDGE)
            .await
            .context("failed to read physically-connected prefixes from the device")?;

    let desired =
        config::desired_state(&patch_file.awg, &patch_file.router, &physically_connected)?;

    converge::run(&device, &desired, !cli.check).await
}
