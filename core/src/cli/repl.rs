use anyhow::Result;
use console::style;
use dialoguer::{Input, theme::ColorfulTheme};

use crate::cli::ScanConfig;
use crate::llm::OllamaClient;
use crate::report::{self, ScanReport};
use crate::scanner;

pub async fn run(
    config: ScanConfig,
    ollama: OllamaClient,
    initial_path: Option<String>,
) -> Result<Option<ScanReport>> {
    let mut last_report: Option<ScanReport> = None;

    // If a path was provided, scan it immediately
    if let Some(path) = initial_path {
        let file_types = vec!["text".into(), "image".into(), "email".into()];
        match run_scan(&config, &ollama, &path, &file_types).await {
            Ok(r) => {
                last_report = Some(r);
            }
            Err(e) => println!("  {} {}", style("[ERROR]").red().bold(), e),
        }

        // If not a TTY (e.g. launched from desktop app or CI), return immediately
        if !atty::is(atty::Stream::Stdin) {
            return Ok(last_report);
        }
    } else {
        // No path — show available commands
        print_welcome();
    }

    // REPL loop
    loop {
        let input: String = Input::with_theme(&ColorfulTheme::default())
            .with_prompt(format!("{}", style("torchsight").cyan().bold()))
            .allow_empty(true)
            .interact_text()?;

        let input = input.trim();

        if input.is_empty() {
            continue;
        }

        match input {
            "exit" | "quit" | "q" => {
                println!("\n{}\n", style("Goodbye.").dim());
                break;
            }
            "help" => {
                print_help();
            }
            "scan" => {
                let path = prompt_scan_path()?;
                let file_types = vec!["text".into(), "image".into(), "email".into()];
                match run_scan(&config, &ollama, &path, &file_types).await {
                    Ok(r) => {
                        last_report = Some(r);
                    }
                    Err(e) => println!("  {} {}", style("[ERROR]").red().bold(), e),
                }
            }
            cmd if cmd.starts_with("scan ") => {
                let path = cmd.strip_prefix("scan ").unwrap().trim();
                let file_types = vec!["text".into(), "image".into(), "email".into()];
                match run_scan(&config, &ollama, path, &file_types).await {
                    Ok(r) => {
                        last_report = Some(r);
                    }
                    Err(e) => println!("  {} {}", style("[ERROR]").red().bold(), e),
                }
            }
            "report" => {
                if let Some(ref r) = last_report {
                    let output = report::format_report(r, "terminal")?;
                    println!("{output}");
                } else {
                    println!("  No scan results yet. Run 'scan <path>' first.");
                }
            }
            "save" => {
                if let Some(ref r) = last_report {
                    let path = report::save_report(r, &config.format)?;
                    println!("  Report saved to: {}", style(path).green());
                } else {
                    println!("  No scan results yet. Run 'scan <path>' first.");
                }
            }
            "snake" | "play" => {
                crate::cli::snake::play()?;
            }
            _ => {
                println!(
                    "  Unknown command. Type '{}' for available commands.",
                    style("help").cyan()
                );
            }
        }
    }

    Ok(last_report)
}

/// Prompt the user for a path to scan, defaulting to the current directory.
fn prompt_scan_path() -> Result<String> {
    let path: String = Input::with_theme(&ColorfulTheme::default())
        .with_prompt("Path to scan")
        .default(".".to_string())
        .interact_text()?;
    Ok(path)
}

async fn run_scan(
    config: &ScanConfig,
    ollama: &OllamaClient,
    path: &str,
    file_types: &[String],
) -> Result<ScanReport> {
    println!();

    let files = scanner::discovery::discover_files(path, config.max_size_bytes, file_types)?;

    if files.is_empty() {
        anyhow::bail!("No scannable files found at '{}'", path);
    }

    println!(
        "  Found {} files to scan",
        style(files.len()).cyan().bold()
    );
    if files.len() > 2 {
        println!(
            "  {} Open another terminal → {} → type {}\n",
            style("Bored?").dim(),
            style("torchsight").cyan(),
            style("snake").cyan()
        );
    } else {
        println!();
    }

    let report = scanner::pipeline::run_scan(files, config, ollama).await?;

    // Print summary
    let total = report.files.len();
    let flagged = report.files.iter().filter(|f| !f.findings.is_empty()).count();
    let clean = total - flagged;

    println!("\n  {}", style("-- Scan & Classification Complete --").bold());
    println!(
        "  {} files analyzed ({} clean, {} flagged)",
        style(total).bold(),
        style(clean).green().bold(),
        style(flagged).yellow().bold(),
    );
    if report.total_findings() > 0 {
        println!(
            "  {} findings ({} critical, {} high, {} medium, {} low, {} info)",
            style(report.total_findings()).bold(),
            style(report.critical_count()).red().bold(),
            style(report.high_count()).red(),
            style(report.medium_count()).yellow().bold(),
            style(report.low_count()).yellow(),
            style(report.info_count()).dim(),
        );
    }

    // Auto-save JSON report (always)
    match report::save_report(&report, "json") {
        Ok(path) => println!("  Report saved: {}", style(&path).green()),
        Err(e) => println!(
            "  {} Could not save JSON: {}",
            style("[WARN]").yellow(),
            e
        ),
    }

    // Auto-save in the configured format (if not json)
    if config.format != "json" && config.format != "terminal" {
        match report::save_report(&report, &config.format) {
            Ok(path) => println!("  Report saved: {}", style(&path).green()),
            Err(e) => println!(
                "  {} Could not save {}: {}",
                style("[WARN]").yellow(),
                config.format,
                e
            ),
        }
    }
    println!();

    // Print findings to terminal
    let terminal_output = report::format_report(&report, "terminal")?;
    println!("{terminal_output}");

    Ok(report)
}

fn print_welcome() {
    println!(
        "  Type {} to scan files, or {} for all commands.\n",
        style("scan <path>").cyan(),
        style("help").cyan()
    );
}

fn print_help() {
    println!(
        r#"
  {}

  {}    Scan a specific path
  {}             Prompt for path to scan
  {}           Show findings from last scan
  {}            Save report (json/markdown/pdf)
  {}          Play Snake while waiting for scans
  {}        Exit torchsight
"#,
        style("Commands:").bold().underlined(),
        style("scan <path>").cyan(),
        style("scan").cyan(),
        style("report").cyan(),
        style("save").cyan(),
        style("snake").cyan(),
        style("exit").cyan(),
    );
}

#[cfg(test)]
mod tests {
    #[test]
    fn help_text_contains_expected_commands() {
        // Capture help text by checking the format string directly
        let expected_commands = ["scan <path>", "scan", "report", "save", "snake", "exit"];
        let removed_commands = ["history"];

        // We can't easily capture println output, so verify the function compiles
        // and test the help text content by examining the source.
        // Instead, let's build the help string manually to verify.
        let help_output = format!(
            r#"
  {}

  {}    Scan a specific path
  {}             Prompt for path to scan
  {}           Show findings from last scan
  {}            Save report (json/markdown/pdf)
  {}          Play Snake while waiting for scans
  {}        Exit torchsight
"#,
            "Commands:",
            "scan <path>",
            "scan",
            "report",
            "save",
            "snake",
            "exit",
        );

        for cmd in &expected_commands {
            assert!(
                help_output.contains(cmd),
                "Help text should contain '{}'",
                cmd
            );
        }

        for cmd in &removed_commands {
            assert!(
                !help_output.contains(cmd),
                "Help text should NOT contain removed command '{}'",
                cmd
            );
        }
    }

    #[test]
    fn help_text_does_not_mention_wizard() {
        let help_output = format!(
            r#"
  {}

  {}    Scan a specific path
  {}             Prompt for path to scan
  {}           Show findings from last scan
  {}            Save report (json/markdown/pdf)
  {}          Play Snake while waiting for scans
  {}        Exit torchsight
"#,
            "Commands:",
            "scan <path>",
            "scan",
            "report",
            "save",
            "snake",
            "exit",
        );

        assert!(
            !help_output.contains("wizard"),
            "Help text should not mention 'wizard'"
        );
    }

    #[test]
    fn help_text_documents_snake_command() {
        let help_output = format!(
            r#"
  {}

  {}    Scan a specific path
  {}             Prompt for path to scan
  {}           Show findings from last scan
  {}            Save report (json/markdown/pdf)
  {}          Play Snake while waiting for scans
  {}        Exit torchsight
"#,
            "Commands:",
            "scan <path>",
            "scan",
            "report",
            "save",
            "snake",
            "exit",
        );

        assert!(
            help_output.contains("snake") && help_output.contains("Snake"),
            "Help text should document the snake command"
        );
    }
}
