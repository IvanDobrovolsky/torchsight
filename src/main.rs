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
    /// Path to scan (if not provided, starts REPL)
    path: Option<String>,

    /// Text analysis model
    #[arg(long, default_value = "torchsight/beam")]
    text_model: String,

    /// Vision model (for image analysis and interactive Q&A)
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

    /// Interactive mode — enables LLM-powered Q&A after scan
    #[arg(short, long)]
    interactive: bool,
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

    // Health check — only require Ollama for scanning
    let ollama_ok = match ollama.health_check().await {
        Ok(true) => {
            println!(
                "   {} Ollama connected (model: {})",
                style("[OK]").green().bold(),
                style(ollama.text_model()).cyan(),
            );
            true
        }
        _ => {
            println!(
                "   {} Ollama not reachable at {}",
                style("[ERR]").red().bold(),
                &args.ollama_url
            );
            println!(
                "   {} Install: ollama serve && ollama pull {}\n",
                style(">>").dim(),
                &args.text_model,
            );
            false
        }
    };

    // Check Tesseract
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

    if !ollama_ok {
        println!(
            "  TorchSight requires Ollama to scan files.\n\
             \n  Quick start:\n\
             \n    1. Install Ollama:   curl -fsSL https://ollama.com/install.sh | sh\
             \n    2. Pull the model:   ollama pull {}\
             \n    3. Run TorchSight:   torchsight <path>\n",
            &args.text_model
        );
        return Ok(());
    }

    let config = cli::ScanConfig {
        text_model: args.text_model,
        vision_model: args.vision_model,
        ollama_url: args.ollama_url,
        max_size_bytes: args.max_size_mb * 1024 * 1024,
        format: args.format,
    };

    // Two modes:
    // 1. Command mode (default): scan, report, exit
    // 2. Interactive mode (-i): scan + LLM-powered Q&A about results
    cli::repl::run(config, ollama, args.path, args.interactive).await
}
