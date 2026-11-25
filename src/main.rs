mod cli;
mod config;
mod converge;
mod credentials;
mod diff;
mod mikrotik;
mod run;
mod sanitize;
mod slipmesh;
#[cfg(test)]
mod test_support;

use clap::Parser;

fn style_of(line: &str) -> anstyle::Style {
    match line.as_bytes().first() {
        Some(b'+') => anstyle::AnsiColor::Green.on_default(),
        Some(b'-') => anstyle::AnsiColor::Red.on_default(),
        Some(b'~') => anstyle::AnsiColor::Yellow.on_default(),
        _ => anstyle::Style::new(),
    }
}

#[tokio::main]
async fn main() -> std::process::ExitCode {
    sliplib_runtime::init_tracing();

    let args = cli::Cli::parse();

    match run::run(&args).await {
        Ok(report) => {
            if args.diff {
                for line in &report.diff_lines {
                    let style = style_of(line);
                    anstream::println!("{style}{line}{style:#}");
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
    fn a_diff_line_is_coloured_by_its_first_character() {
        use anstyle::{AnsiColor, Style};
        assert_eq!(
            style_of("+ interface wireguard: foo"),
            AnsiColor::Green.on_default()
        );
        assert_eq!(
            style_of("~ routing ospf area (*1): foo"),
            AnsiColor::Yellow.on_default()
        );
        assert_eq!(
            style_of("- interface wireguard: foo"),
            AnsiColor::Red.on_default()
        );
        assert_eq!(style_of("not a diff line"), Style::new());
        assert_eq!(style_of(""), Style::new());
    }
}
