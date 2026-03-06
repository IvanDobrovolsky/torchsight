use anyhow::Result;
use console::style;
use indicatif::{ProgressBar, ProgressStyle};

use super::classifier::FileKind;
use super::discovery::ScannableFile;
use crate::analyzers;
use crate::cli::ScanConfig;
use crate::llm::OllamaClient;
use crate::report::ScanReport;

pub async fn run_scan(
    files: Vec<ScannableFile>,
    config: &ScanConfig,
    ollama: &OllamaClient,
) -> Result<ScanReport> {
    let total = files.len() as u64;
    let pb = ProgressBar::new(total);
    pb.set_style(
        ProgressStyle::default_bar()
            .template("  {spinner:.cyan} [{bar:40.cyan/dim}] {pos}/{len} | {msg}")?
            .progress_chars("##-"),
    );

    // Check OCR availability once
    let ocr_available = analyzers::ocr::is_available();
    if !ocr_available {
        pb.println(format!(
            "  {} Tesseract not found. Image text extraction disabled. Install: pacman -S tesseract tesseract-data-eng",
            style("[WARN]").yellow()
        ));
    }

    let mut report = ScanReport::new();

    for (i, file) in files.iter().enumerate() {
        pb.set_position(i as u64);
        let filename = file
            .path
            .file_name()
            .unwrap_or_default()
            .to_string_lossy();
        pb.set_message(format!("{} ({}/{})", filename, i + 1, total));

        let findings = match file.kind {
            FileKind::Text => {
                match analyzers::text::analyze_text_file(&file.path, ollama).await {
                    Ok(results) => results,
                    Err(e) => {
                        pb.println(format!(
                            "  {} Failed to analyze {}: {}",
                            style("[WARN]").yellow(),
                            filename,
                            e
                        ));
                        vec![]
                    }
                }
            }
            FileKind::Image => {
                match analyzers::image::analyze_image(&file.path, ollama).await {
                    Ok(findings) => findings,
                    Err(e) => {
                        pb.println(format!(
                            "  {} Failed to analyze {}: {}",
                            style("[WARN]").yellow(),
                            filename,
                            e
                        ));
                        vec![]
                    }
                }
            }
            FileKind::Unknown => vec![],
        };

        report.add_file_findings(
            file.path.to_string_lossy().to_string(),
            file.kind.clone(),
            file.size,
            findings,
        );
    }

    pb.set_position(total);
    pb.finish_with_message("done");

    Ok(report)
}
