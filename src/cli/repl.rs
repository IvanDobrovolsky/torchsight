use anyhow::Result;
use console::style;
use dialoguer::{Confirm, Input, theme::ColorfulTheme};
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
    interactive: bool,
) -> Result<Option<ScanReport>> {
    let mut session = SessionMemory::new();
    let mut last_report: Option<ScanReport> = None;

    // If a path was provided, scan it immediately
    if let Some(path) = initial_path {
        let file_types = vec!["text".into(), "image".into()];
        match run_scan(&config, &ollama, &path, &file_types).await {
            Ok(r) => {
                session.add_report_summary(&r);
                last_report = Some(r);
            }
            Err(e) => println!("  {} {}", style("[ERROR]").red().bold(), e),
        }

        // In non-interactive mode, ask if user wants to explore
        if !interactive && last_report.is_some() {
            println!(
                "\n  {} Interactive mode loads {} (~4.9GB) for Q&A about results.",
                style("TIP:").cyan().bold(),
                style(&config.vision_model).cyan()
            );
            println!(
                "  {} You can also start with {} to skip this prompt.\n",
                style("").dim(),
                style("torchsight -i <path>").cyan()
            );
            let enter_interactive = Confirm::with_theme(&ColorfulTheme::default())
                .with_prompt("Explore results interactively?")
                .default(false)
                .interact()?;

            if !enter_interactive {
                println!("\n{}\n", style("Done.").dim());
                return Ok(last_report);
            }
        }
    } else {
        // No path — show available commands
        print_welcome(interactive);
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
                print_help(interactive);
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
            "history" => {
                session.print_history();
            }
            "snake" | "play" => {
                crate::cli::snake::play()?;
            }
            _ => {
                // In interactive mode, treat unknown input as a question for the LLM
                if interactive {
                    if let Some(ref r) = last_report {
                        ask_llm(&ollama, r, input).await;
                    } else {
                        // No report yet — maybe they're asking to scan something
                        try_natural_language(&config, &ollama, input, &mut session, &mut last_report).await;
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

    Ok(last_report)
}

/// In interactive mode, try to understand natural language commands
async fn try_natural_language(
    config: &ScanConfig,
    ollama: &OllamaClient,
    input: &str,
    session: &mut SessionMemory,
    last_report: &mut Option<ScanReport>,
) {
    let lower = input.to_lowercase();

    // Try to detect scan intent
    if lower.contains("scan") || lower.contains("check") || lower.contains("analyze") {
        // Extract path — look for quoted strings or words that look like paths
        let path = extract_path_from_input(input);
        if let Some(path) = path {
            let file_types = vec!["text".into(), "image".into()];
            match run_scan(config, ollama, &path, &file_types).await {
                Ok(r) => {
                    session.add_report_summary(&r);
                    *last_report = Some(r);
                }
                Err(e) => println!("  {} {}", style("[ERROR]").red().bold(), e),
            }
            return;
        }
    }

    // Try to detect report/save intent
    if lower.contains("save") || lower.contains("export") || lower.contains("report") {
        if let Some(r) = last_report.as_ref() {
            match report::save_report(r, &config.format) {
                Ok(path) => println!("  Report saved to: {}", style(path).green()),
                Err(e) => println!("  {} {}", style("[ERROR]").red().bold(), e),
            }
            return;
        }
    }

    // Fall back to LLM for understanding
    let prompt = format!(
        "You are TorchSight, a cybersecurity scanner assistant. The user said: \"{}\"\n\n\
         Available commands: scan <path>, report, save, history, help, exit.\n\n\
         If you can understand what they want, explain which command to use. Be brief.",
        input
    );

    let spinner = ProgressBar::new_spinner();
    spinner.set_style(
        ProgressStyle::default_spinner()
            .template("  {spinner:.cyan} {msg}")
            .unwrap(),
    );
    spinner.set_message("Thinking...");
    spinner.enable_steady_tick(std::time::Duration::from_millis(80));

    match ollama.generate_with_vision_model(&prompt).await {
        Ok(response) => {
            spinner.finish_and_clear();
            println!("\n  {}\n", response);
        }
        Err(e) => {
            spinner.finish_and_clear();
            println!("  {} LLM error: {}", style("[ERROR]").red().bold(), e);
        }
    }
}

/// Extract a file path from natural language input
fn extract_path_from_input(input: &str) -> Option<String> {
    // Check for quoted paths
    if let Some(start) = input.find('"') {
        if let Some(end) = input[start + 1..].find('"') {
            return Some(input[start + 1..start + 1 + end].to_string());
        }
    }
    if let Some(start) = input.find('\'') {
        if let Some(end) = input[start + 1..].find('\'') {
            return Some(input[start + 1..start + 1 + end].to_string());
        }
    }

    // Look for path-like tokens (starts with / or ./ or ~/ or contains / or \)
    for token in input.split_whitespace() {
        let t = token.trim_matches(|c: char| c == ',' || c == '.' || c == '?' || c == '!');
        if t.starts_with('/')
            || t.starts_with("./")
            || t.starts_with("~/")
            || t.starts_with("..")
            || (t.contains('/') && !t.starts_with("http"))
            || t.contains('\\')
        {
            return Some(t.to_string());
        }
    }

    None
}

/// Ask the LLM a question about scan results
async fn ask_llm(ollama: &OllamaClient, report: &ScanReport, question: &str) {
    let context = match serde_json::to_string_pretty(report) {
        Ok(c) => c,
        Err(e) => {
            println!("  {} {}", style("[ERROR]").red().bold(), e);
            return;
        }
    };

    let prompt = format!(
        "You are a cybersecurity analyst. You have full access to the scan report data below, \
         including all extracted_data fields with exact values (names, SSNs, emails, addresses, etc). \
         Answer the user's question with specific details from the report. Be precise and quote exact values.\n\n\
         Scan Report:\n{}\n\nUser question: {}",
        context, question
    );

    let spinner = ProgressBar::new_spinner();
    spinner.set_style(
        ProgressStyle::default_spinner()
            .template("  {spinner:.cyan} {msg}")
            .unwrap(),
    );
    spinner.set_message("Thinking...");
    spinner.enable_steady_tick(std::time::Duration::from_millis(80));

    match ollama.generate_with_vision_model(&prompt).await {
        Ok(response) => {
            spinner.finish_and_clear();
            println!("\n  {}\n", response);
        }
        Err(e) => {
            spinner.finish_and_clear();
            println!("  {} LLM error: {}", style("[ERROR]").red().bold(), e);
        }
    }
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
        "  {} total findings ({} critical, {} high, {} medium, {} low, {} info)",
        style(report.total_findings()).bold(),
        style(report.critical_count()).red().bold(),
        style(report.high_count()).red(),
        style(report.medium_count()).yellow().bold(),
        style(report.low_count()).yellow(),
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

    Ok(report)
}

fn print_welcome(interactive: bool) {
    if interactive {
        println!(
            "  {} Interactive mode — ask questions in natural language.\n",
            style(">>").cyan().bold(),
        );
    }
    println!(
        "  Type {} to scan files, or {} for all commands.\n",
        style("scan <path>").cyan(),
        style("help").cyan()
    );
}

fn print_help(interactive: bool) {
    println!(
        r#"
  {}

  {}    Scan a specific path
  {}             Start interactive scan wizard
  {}           Show findings from last scan
  {}            Save report (json/markdown/pdf)
  {}         Show scan history
  {}        Exit torchsight
"#,
        style("Commands:").bold().underlined(),
        style("scan <path>").cyan(),
        style("scan").cyan(),
        style("report").cyan(),
        style("save").cyan(),
        style("history").cyan(),
        style("exit").cyan(),
    );

    if interactive {
        println!(
            "  {} In interactive mode you can also ask questions in plain English:\n\
             \n    {}   {}\
             \n    {}   {}\
             \n    {}   {}\n",
            style("Interactive:").bold().underlined(),
            style(">>").dim(),
            style("What sensitive data was found?").dim(),
            style(">>").dim(),
            style("Are there any credentials exposed?").dim(),
            style(">>").dim(),
            style("Scan my downloads folder for PII").dim(),
        );
    }
}
