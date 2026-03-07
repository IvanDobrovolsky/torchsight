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

    /// Text analysis model (fast reasoning)
    #[arg(long, default_value = "torchsight/beam-q8")]
    text_model: String,

    /// Vision model (image understanding)
    #[arg(long, default_value = "llama3.2-vision")]
    vision_model: String,

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

    let ollama = llm::OllamaClient::new(&args.ollama_url, &args.text_model, &args.vision_model);

    match ollama.health_check().await {
        Ok(true) => {
            println!(
                "   {} Ollama connected (text: {}, vision: {})",
                style("[OK]").green().bold(),
                style(ollama.text_model()).cyan(),
                style(ollama.vision_model()).cyan()
            );
        }
        _ => {
            println!(
                "   {} Ollama not reachable at {}. LLM analysis requires Ollama.",
                style("[ERR]").red().bold(),
                &args.ollama_url
            );
            println!(
                "   {} Install: ollama serve && ollama pull {} && ollama pull {}\n",
                style(">>").dim(),
                &args.text_model,
                &args.vision_model
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
        text_model: args.text_model,
        vision_model: args.vision_model,
        ollama_url: args.ollama_url,
        max_size_bytes: args.max_size_mb * 1024 * 1024,
        format: args.format,
    };

    cli::repl::run(config, ollama, args.path).await
}
