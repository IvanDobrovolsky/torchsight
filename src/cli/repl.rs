use anyhow::Result;
use console::style;
use dialoguer::{Input, theme::ColorfulTheme};
use indicatif::{ProgressBar, ProgressStyle};

use crate::cli::ScanConfig;
use crate::llm::OllamaClient;
use crate::memory::SessionMemory;
use crate::report::{self, ScanReport};
use crate::scanner;

pub async fn run(
    config: ScanConfig,
    ollama: OllamaClient,
    initial_path: Option<String>,
) -> Result<()> {
    let mut session = SessionMemory::new();
    let mut last_report: Option<ScanReport> = None;

    if let Some(path) = initial_path {
        let file_types = vec!["text".into(), "image".into()];
        match run_scan(&config, &ollama, &path, &file_types).await {
            Ok(r) => {
                session.add_report_summary(&r);
                last_report = Some(r);
            }
            Err(e) => println!("  {} {}", style("[ERROR]").red().bold(), e),
        }
    }

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
                let request = crate::cli::prompts::gather_scan_request()?;
                match run_scan(&config, &ollama, &request.path, &request.file_types).await {
                    Ok(r) => {
                        session.add_report_summary(&r);
                        last_report = Some(r);
                    }
                    Err(e) => println!("  {} {}", style("[ERROR]").red().bold(), e),
                }
            }
            cmd if cmd.starts_with("scan ") => {
                let path = cmd.strip_prefix("scan ").unwrap().trim();
                let file_types = vec!["text".into(), "image".into()];
                match run_scan(&config, &ollama, path, &file_types).await {
                    Ok(r) => {
                        session.add_report_summary(&r);
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
                    println!("  No scan results yet. Run 'scan' first.");
                }
            }
            "save" => {
                if let Some(ref r) = last_report {
                    let path = report::save_report(r, &config.format)?;
                    println!("  Report saved to: {}", style(path).green());
                } else {
                    println!("  No scan results yet. Run 'scan' first.");
                }
            }
            "history" => {
                session.print_history();
            }
            _ => {
                if let Some(ref r) = last_report {
                    let context = serde_json::to_string_pretty(r)?;
                    let prompt = format!(
                        "You are a cybersecurity analyst. You have full access to the scan report data below, including all extracted_data fields with exact values (names, SSNs, emails, addresses, etc). Answer the user's question with specific details from the report. Be precise and quote exact values.\n\nScan Report:\n{}\n\nUser question: {}",
                        context, input
                    );

                    let spinner = ProgressBar::new_spinner();
                    spinner.set_style(
                        ProgressStyle::default_spinner()
                            .template("  {spinner:.cyan} {msg}")
                            .unwrap(),
                    );
                    spinner.set_message("Thinking...");
                    spinner.enable_steady_tick(std::time::Duration::from_millis(80));

                    // Use vision model for Q&A — beam is a classifier, not a chatbot
                    let result = ollama.generate_with_vision_model(&prompt).await;

                    match result {
                        Ok(response) => {
                            spinner.finish_and_clear();
                            println!("\n  {}\n", response);
                        }
                        Err(e) => {
                            spinner.finish_and_clear();
                            println!("  {} LLM error: {}", style("[ERROR]").red().bold(), e);
                        }
                    }
                } else {
                    println!(
                        "  Unknown command. Type '{}' for available commands.",
                        style("help").cyan()
                    );
                }
            }
        }
    }

    Ok(())
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
        "  Found {} files to scan\n",
        style(files.len()).cyan().bold()
    );

    let report = scanner::pipeline::run_scan(files, config, ollama).await?;

    // Print summary
    let total = report.files.len();
    let flagged = report.files.iter().filter(|f| !f.findings.is_empty()).count();
    let clean = total - flagged;

    println!("\n  {}", style("-- Scan Complete --").bold());
    println!(
        "  {} files scanned ({} flagged, {} clean)",
        style(total).bold(),
        style(flagged).yellow().bold(),
        style(clean).green().bold(),
    );
    println!(
        "  {} total findings ({} critical, {} warning, {} info)",
        style(report.total_findings()).bold(),
        style(report.critical_count()).red().bold(),
        style(report.warning_count()).yellow().bold(),
        style(report.info_count()).dim(),
    );

    // Auto-save PDF report
    match report::save_report(&report, "pdf") {
        Ok(path) => println!("  Report saved: {}\n", style(&path).green()),
        Err(e) => println!(
            "  {} Could not save PDF: {}. Use 'save' for JSON/Markdown.\n",
            style("[WARN]").yellow(),
            e
        ),
    }

    // Print findings to terminal
    let terminal_output = report::format_report(&report, "terminal")?;
    println!("{terminal_output}");

    println!(
        "  {}",
        style("Ask questions about the results, or type 'help' for commands.").dim()
    );

    Ok(report)
}

fn print_help() {
    println!(
        r#"
  {}

  {}             Start interactive scan wizard
  {}    Scan a specific path directly
  {}           Show findings summary
  {}            Save report (json/markdown)
  {}         Show scan history
  {}     Ask a question about the last scan
  {}        Exit torchsight

"#,
        style("Commands:").bold().underlined(),
        style("scan").cyan(),
        style("scan <path>").cyan(),
        style("report").cyan(),
        style("save").cyan(),
        style("history").cyan(),
        style("<question>").cyan(),
        style("exit").cyan(),
    );
}
