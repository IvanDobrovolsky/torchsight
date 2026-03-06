mod analyzers;
mod cli;
mod llm;
mod memory;
mod report;
mod scanner;

use anyhow::Result;
use clap::Parser;
use console::style;

#[derive(Parser)]
#[command(name = "torchsight", version, about = "On-premise cybersecurity scanner")]
struct Args {
    /// Path to scan (if not provided, interactive mode)
    path: Option<String>,

    /// Ollama model to use
    #[arg(long, default_value = "llama3.2-vision")]
    model: String,

    /// Ollama server URL
    #[arg(long, default_value = "http://localhost:11434")]
    ollama_url: String,

    /// Max file size in MB
    #[arg(long, default_value = "1024")]
    max_size_mb: u64,

    /// Output report format (json, markdown)
    #[arg(long, default_value = "json")]
    format: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();

    let args = Args::parse();

    println!(
        "\n{}  {} v{}\n",
        style(">>").bold().cyan(),
        style("TorchSight").bold(),
        env!("CARGO_PKG_VERSION")
    );
    println!(
        "   {}\n",
        style("On-Premise Security Scanner | Fully Local | No Cloud").dim()
    );

    let ollama = llm::OllamaClient::new(&args.ollama_url, &args.model);

    match ollama.health_check().await {
        Ok(true) => {
            println!(
                "   {} Ollama connected (model: {})",
                style("[OK]").green().bold(),
                style(&args.model).cyan()
            );
        }
        _ => {
            println!(
                "   {} Ollama not reachable at {}. LLM analysis requires Ollama.",
                style("[ERR]").red().bold(),
                &args.ollama_url
            );
            println!(
                "   {} Install: ollama serve && ollama pull {}\n",
                style(">>").dim(),
                &args.model
            );
        }
    }

    // Check Tesseract
    if analyzers::ocr::is_available() {
        println!(
            "   {} Tesseract OCR available",
            style("[OK]").green().bold()
        );
    } else {
        println!(
            "   {} Tesseract not found. Install: pacman -S tesseract tesseract-data-eng",
            style("[WARN]").yellow().bold()
        );
    }

    println!();

    let config = cli::ScanConfig {
        model: args.model,
        ollama_url: args.ollama_url,
        max_size_bytes: args.max_size_mb * 1024 * 1024,
        format: args.format,
    };

    cli::repl::run(config, ollama, args.path).await
}
