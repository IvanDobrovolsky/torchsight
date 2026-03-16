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
    _config: &ScanConfig,
    ollama: &OllamaClient,
) -> Result<ScanReport> {
    let total = files.len() as u64;

    // Use progress bar for interactive terminals, plain text for redirected output
    let is_terminal = atty::is(atty::Stream::Stderr);
    let pb = if is_terminal {
        let pb = ProgressBar::new(total);
        pb.set_style(
            ProgressStyle::default_bar()
                .template("  {spinner:.cyan} [{bar:30.cyan/dim}] {msg}")?
                .progress_chars("##-"),
        );
        pb.enable_steady_tick(std::time::Duration::from_millis(120));
        Some(pb)
    } else {
        None
    };

    // Check OCR availability once
    let ocr_available = analyzers::ocr::is_available();
    if !ocr_available {
        let msg = format!(
            "  {} Tesseract not found. Image text extraction disabled. Install: pacman -S tesseract tesseract-data-eng",
            style("[WARN]").yellow()
        );
        if let Some(ref pb) = pb {
            pb.println(&msg);
        } else {
            eprintln!("{}", msg);
        }
    }

    let mut report = ScanReport::new();

    for (i, file) in files.iter().enumerate() {
        let filename = file
            .path
            .file_name()
            .unwrap_or_default()
            .to_string_lossy();
        if let Some(ref pb) = pb {
            pb.set_position(i as u64);
            pb.set_message(format!("{}/{} | {}", i + 1, total, filename));
        } else {
            eprintln!("  [{}/{}] Scanning: {}", i + 1, total, filename);
        }

        let findings = match file.kind {
            FileKind::Text => {
                match analyzers::text::analyze_text_file(&file.path, ollama).await {
                    Ok(results) => results,
                    Err(e) => {
                        let msg = format!(
                            "  {} Failed to analyze {}: {}",
                            style("[WARN]").yellow(),
                            filename,
                            e
                        );
                        if let Some(ref pb) = pb {
                            pb.println(&msg);
                        } else {
                            eprintln!("{}", msg);
                        }
                        vec![]
                    }
                }
            }
            FileKind::Image => {
                match analyzers::image::analyze_image(&file.path, ollama).await {
                    Ok(findings) => findings,
                    Err(e) => {
                        let msg = format!(
                            "  {} Failed to analyze {}: {}",
                            style("[WARN]").yellow(),
                            filename,
                            e
                        );
                        if let Some(ref pb) = pb {
                            pb.println(&msg);
                        } else {
                            eprintln!("{}", msg);
                        }
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

    if let Some(ref pb) = pb {
        pb.set_position(total);
        pb.finish_with_message("done");
    } else {
        eprintln!("  Scan complete: {} files processed", total);
    }

    Ok(report)
}
