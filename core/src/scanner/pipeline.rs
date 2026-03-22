use std::collections::HashMap;

use anyhow::Result;
use console::style;
use indicatif::{ProgressBar, ProgressStyle};

use super::classifier::FileKind;
use super::discovery::ScannableFile;
use crate::analyzers;
use crate::cli::ScanConfig;
use crate::llm::OllamaClient;
use crate::report::{FileFinding, ScanReport, Severity};

pub async fn run_scan(
    files: Vec<ScannableFile>,
    _config: &ScanConfig,
    ollama: &OllamaClient,
) -> Result<ScanReport> {
    let total = files.len() as u64;
    let start = std::time::Instant::now();

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

    // Check OCR availability once — only warn if there are image files to scan
    let has_images = files.iter().any(|f| matches!(f.kind, FileKind::Image));
    let _ocr_available = if has_images {
        let available = analyzers::ocr::is_available();
        if !available {
            let msg = format!(
                "  {} Tesseract not found. Image text extraction disabled. Install: {}",
                style("[WARN]").yellow(),
                crate::platform::install_hint("tesseract"),
            );
            if let Some(ref pb) = pb {
                pb.println(&msg);
            } else {
                eprintln!("{}", msg);
            }
        }
        available
    } else {
        false
    };

    let mut report = ScanReport::new();

    for (i, file) in files.iter().enumerate() {
        let filename = file
            .path
            .file_name()
            .unwrap_or_default()
            .to_string_lossy();
        let elapsed = start.elapsed().as_secs();
        let elapsed_str = if elapsed >= 60 {
            format!("{}m{}s", elapsed / 60, elapsed % 60)
        } else {
            format!("{}s", elapsed)
        };
        let stats = crate::platform::system_stats_oneliner();
        if let Some(ref pb) = pb {
            pb.set_position(i as u64);
            pb.set_message(format!("{}/{} | {} | {} | {}", i + 1, total, filename, stats, elapsed_str));
        } else {
            eprintln!("  [{}/{}] Scanning: {} | {} | {}", i + 1, total, filename, stats, elapsed_str);
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
            FileKind::Email => {
                match analyzers::email::analyze_email_archive(&file.path, ollama).await {
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

        // Print completed file summary above the progress bar
        let summary = format_file_summary(&filename, &findings);
        if let Some(ref pb) = pb {
            pb.println(&summary);
        } else {
            eprintln!("{}", summary);
        }

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

/// Format a one-line summary for a completed file scan.
fn format_file_summary(filename: &str, findings: &[FileFinding]) -> String {
    let non_safe: Vec<&FileFinding> = findings
        .iter()
        .filter(|f| f.category != "safe")
        .collect();

    if non_safe.is_empty() {
        return format!("  {} {} — clean", style("\u{2713}").green(), filename);
    }

    // Count findings by severity
    let mut counts: HashMap<&Severity, usize> = HashMap::new();
    for f in &non_safe {
        *counts.entry(&f.severity).or_insert(0) += 1;
    }

    // Build severity breakdown in descending order
    let mut parts = Vec::new();
    for sev in &[
        Severity::Critical,
        Severity::High,
        Severity::Medium,
        Severity::Low,
        Severity::Info,
    ] {
        if let Some(&count) = counts.get(sev) {
            parts.push(format!("{} {}", count, sev.to_string().to_lowercase()));
        }
    }

    let total = non_safe.len();
    let detail = parts.join(", ");
    format!(
        "  {} {} — {} {} ({})",
        style("\u{2717}").red(),
        filename,
        total,
        if total == 1 { "finding" } else { "findings" },
        detail,
    )
}
