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

    let mut report = ScanReport::new();

    for file in &files {
        let filename = file
            .path
            .file_name()
            .unwrap_or_default()
            .to_string_lossy();
        pb.set_message(filename.to_string());

        let findings = match file.kind {
            FileKind::Text => {
                let mut results = analyzers::text::analyze_text_file(&file.path)?;

                if !config.fast_only {
                    if let Ok(llm_findings) =
                        analyzers::text::analyze_text_with_llm(&file.path, ollama).await
                    {
                        results.extend(llm_findings);
                    }
                }

                results
            }
            FileKind::Image => {
                if config.fast_only {
                    vec![]
                } else {
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
            }
            FileKind::Unknown => vec![],
        };

        // Always add the file to the report, even if clean
        report.add_file_findings(
            file.path.to_string_lossy().to_string(),
            file.kind.clone(),
            file.size,
            findings,
        );

        pb.inc(1);
    }

    pb.finish_with_message("done");

    Ok(report)
}
