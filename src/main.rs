mod allocation;
mod cli;
mod config;
mod converge;
mod credentials;
mod diff;
mod mikrotik;
mod run;
mod sanitize;

use clap::Parser;

#[tokio::main]
async fn main() -> std::process::ExitCode {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .without_time()
        .with_ansi(false)
        .init();

    let args = cli::Cli::parse();

    match run::run(&args).await {
        Ok(report) => {
            if args.diff {
                for line in &report.diff_lines {
                    println!("{line}");
                }
            }
            tracing::info!(
                added = report.added,
                updated = report.updated,
                removed = report.removed,
                check = args.check,
                "converge complete"
            );
            std::process::ExitCode::SUCCESS
        }
        Err(e) => {
            tracing::error!(error = format!("{e:#}"), "routeros failed");
            std::process::ExitCode::FAILURE
        }
    }
}
