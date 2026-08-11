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
use std::io::IsTerminal;

const ANSI_GREEN: &str = "\x1b[32m";
const ANSI_RED: &str = "\x1b[31m";
const ANSI_YELLOW: &str = "\x1b[33m";
const ANSI_RESET: &str = "\x1b[0m";

/// Colorizes one `--diff` line by its leading marker - matches `converge::ConvergeReport::
/// record`'s own `+`/`~`/`-` prefix convention (add/update/remove) exactly. Anything else (there
/// shouldn't be anything else) passes through unstyled rather than guessing.
fn colorize_diff_line(line: &str) -> String {
    let color = match line.chars().next() {
        Some('+') => ANSI_GREEN,
        Some('-') => ANSI_RED,
        Some('~') => ANSI_YELLOW,
        _ => return line.to_string(),
    };
    format!("{color}{line}{ANSI_RESET}")
}

/// Color only when stdout is a real terminal (never inject escape codes into a redirected/piped
/// log) and `NO_COLOR` isn't set (https://no-color.org/ - the same convention `git`/`ripgrep`/
/// most CLI tools already follow).
fn use_color() -> bool {
    std::io::stdout().is_terminal() && std::env::var_os("NO_COLOR").is_none()
}

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
                let color = use_color();
                for line in &report.diff_lines {
                    if color {
                        println!("{}", colorize_diff_line(line));
                    } else {
                        println!("{line}");
                    }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn colorizes_add_update_remove_by_leading_marker() {
        assert_eq!(
            colorize_diff_line("+ interface wireguard: foo"),
            format!("{ANSI_GREEN}+ interface wireguard: foo{ANSI_RESET}")
        );
        assert_eq!(
            colorize_diff_line("~ routing ospf area (*1): foo"),
            format!("{ANSI_YELLOW}~ routing ospf area (*1): foo{ANSI_RESET}")
        );
        assert_eq!(
            colorize_diff_line("- interface wireguard: foo"),
            format!("{ANSI_RED}- interface wireguard: foo{ANSI_RESET}")
        );
    }

    #[test]
    fn passes_through_unrecognized_lines_unstyled() {
        assert_eq!(colorize_diff_line("not a diff line"), "not a diff line");
        assert_eq!(colorize_diff_line(""), "");
    }
}
