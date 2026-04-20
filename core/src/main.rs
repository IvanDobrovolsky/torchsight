use torchsight::analyzers;
use torchsight::cli;
use torchsight::config;
use torchsight::llm;
use torchsight::report;

use anyhow::Result;
use clap::Parser;
use console::style;

#[derive(Parser)]
#[command(name = "torchsight", version, about = "On-premise cybersecurity scanner")]
struct Args {
    /// Path to scan (if not provided, starts REPL)
    path: Option<String>,

    /// Text analysis model
    #[arg(long, default_value = "torchsight/beam")]
    text_model: String,

    /// Vision model (for image analysis)
    #[arg(long, default_value = "llama3.2-vision")]
    vision_model: String,

    /// Ollama server URL
    #[arg(long, default_value = "http://localhost:11434")]
    ollama_url: String,

    /// Max file size in MB
    #[arg(long, default_value = "1024")]
    max_size_mb: u64,

    /// Output report format (json, html, markdown, sarif, pdf). JSON is always saved; this controls the additional format.
    #[arg(long, default_value = "html")]
    format: String,

    /// Exit with code 1 if findings meet or exceed this severity (critical, high, medium, low, info)
    #[arg(long)]
    fail_on: Option<String>,

    /// Read content from stdin instead of files
    #[arg(long)]
    stdin: bool,

    /// Scan only changes since this git ref (e.g. HEAD~1, main)
    #[arg(long)]
    diff: Option<String>,

}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();

    let args = Args::parse();

    // When outputting structured formats via stdin/diff, suppress banner to keep stdout clean
    let quiet = (args.stdin || args.diff.is_some()) && args.format != "json";

    if !quiet {
        println!();
        for line in [
            r"   _                _         _       _     _   ",
            r"  | |_ ___  _ _ ___| |_  ___ (_) __ _| |_  | |_ ",
            r"  |  _/ _ \| '_/ __| ' \(_-< | |/ _` | ' \ |  _|",
            r"   \__\___/|_| \___|_||_/__/ |_|\__, |_||_|  \__|",
            r"                                |___/            ",
        ] {
            println!("{}", style(line).magenta());
        }
        println!(
            "   {} v{}\n",
            style("on-premise security scanner").dim(),
            env!("CARGO_PKG_VERSION")
        );
    }

    // Load config file (CLI args override config)
    let file_config = config::TorchsightConfig::load();
    let text_model = if args.text_model != "torchsight/beam" { args.text_model } else { file_config.model.text };
    let vision_model = if args.vision_model != "llama3.2-vision" { args.vision_model } else { file_config.model.vision };
    let ollama_url = if args.ollama_url != "http://localhost:11434" { args.ollama_url } else { file_config.model.ollama_url };
    let max_size_mb = if args.max_size_mb != 1024 { args.max_size_mb } else { file_config.scan.max_size_mb };
    let format_was_explicit = args.format != "html";
    let format = if format_was_explicit { args.format } else { file_config.report.format };
    let fail_on_str = args.fail_on.or(file_config.scan.fail_on);

    let ollama = llm::OllamaClient::new(&ollama_url, &text_model, &vision_model);

    // Health check — only require Ollama for scanning
    let ollama_ok = match ollama.health_check().await {
        Ok(true) => {
            if !quiet {
                println!(
                    "   {} Ollama connected (model: {})",
                    style("[OK]").green().bold(),
                    style(ollama.text_model()).cyan(),
                );
            }
            true
        }
        _ => {
            eprintln!(
                "   {} Ollama not reachable at {}",
                style("[ERR]").red().bold(),
                &ollama_url
            );
            eprintln!(
                "   {} Install: ollama serve && ollama pull {}\n",
                style(">>").dim(),
                &text_model,
            );
            false
        }
    };

    // Auto-pull models if Ollama is available
    if ollama_ok {
        ollama.ensure_model(ollama.text_model()).await.ok();
    }

    // Check Tesseract
    if !quiet {
        if analyzers::ocr::is_available() {
            println!(
                "   {} Tesseract OCR available",
                style("[OK]").green().bold()
            );
        } else {
            println!(
                "   {} Tesseract not found (image text extraction disabled)",
                style("[WARN]").yellow().bold()
            );
        }

        println!();
    }

    if !ollama_ok {
        eprintln!(
            "  TorchSight requires Ollama to scan files.\n\
             \n  Quick start:\n\
             \n    1. Install Ollama:   curl -fsSL https://ollama.com/install.sh | sh\
             \n    2. Pull the model:   ollama pull {}\
             \n    3. Run TorchSight:   torchsight <path>\n",
            &text_model
        );
        return Ok(());
    }

    let fail_on = fail_on_str.as_deref().and_then(parse_severity);

    let config = cli::ScanConfig {
        text_model,
        vision_model,
        ollama_url,
        max_size_bytes: max_size_mb * 1024 * 1024,
        format,
        quiet,
    };

    // For stdin/diff: use explicit --format if provided, else default to terminal
    let pipe_format = if format_was_explicit { &config.format } else { "terminal" };

    // Handle stdin mode
    if args.stdin {
        let report = cli::stdin::scan_stdin(&config, &ollama).await?;
        let output = report::format_report(&report, pipe_format)?;
        println!("{output}");
        return check_fail_on(&report, fail_on.as_ref());
    }

    // Handle diff mode
    if let Some(ref git_ref) = args.diff {
        let report = cli::stdin::scan_diff(git_ref, &config, &ollama).await?;
        let output = report::format_report(&report, pipe_format)?;
        println!("{output}");
        return check_fail_on(&report, fail_on.as_ref());
    }

    let report = cli::repl::run(config, ollama, args.path).await?;

    // Check --fail-on threshold
    if let Some(ref report) = report {
        check_fail_on(report, fail_on.as_ref())?;
    }

    Ok(())
}

fn check_fail_on(
    report: &report::ScanReport,
    fail_on: Option<&report::Severity>,
) -> Result<()> {
    if let Some(threshold) = fail_on
        && report.has_severity_at_or_above(threshold)
    {
        std::process::exit(1);
    }
    Ok(())
}

fn parse_severity(s: &str) -> Option<report::Severity> {
    match s.to_lowercase().as_str() {
        "critical" => Some(report::Severity::Critical),
        "high" => Some(report::Severity::High),
        "medium" => Some(report::Severity::Medium),
        "low" => Some(report::Severity::Low),
        "info" => Some(report::Severity::Info),
        _ => {
            eprintln!("Warning: Unknown severity '{}'. Valid: critical, high, medium, low, info", s);
            None
        }
    }
}
