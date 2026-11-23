//! The one-shot pipeline: read slipmesh.yaml once, connect to the device once, converge, exit.
//! No state is carried between invocations.

use crate::cli::Cli;
use crate::config;
use crate::converge::{self, ConvergeReport};
use crate::credentials;
use crate::slipmesh;
use anyhow::Context;

pub async fn run(cli: &Cli) -> anyhow::Result<ConvergeReport> {
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .map_err(|_| anyhow::anyhow!("failed to install default rustls crypto provider"))?;

    let configs =
        slipmesh::read_node(&cli.config, &cli.node).context("failed to read the node's configs")?;

    let credentials = credentials::from_env()?;

    let device = crate::mikrotik::connect(&credentials)
        .await
        .context("failed to connect to the RouterOS device")?;

    let physically_connected =
        crate::mikrotik::read_physically_connected_prefixes(&device, config::LOOPBACK_BRIDGE)
            .await
            .context("failed to read physically-connected prefixes from the device")?;

    let desired = config::desired_state(&configs.awg, &configs.router, &physically_connected)?;

    converge::run(&device, &desired, cli.applies()).await
}
