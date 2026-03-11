use anyhow::Result;
use console::style;
use std::io::Read;

use crate::analyzers;
use crate::cli::ScanConfig;
use crate::llm::OllamaClient;
use crate::report::ScanReport;
use crate::scanner;

/// Scan content from stdin
pub async fn scan_stdin(config: &ScanConfig, ollama: &OllamaClient) -> Result<ScanReport> {
    let mut content = String::new();
    std::io::stdin().read_to_string(&mut content)?;

    if content.trim().is_empty() {
        anyhow::bail!("No input received from stdin");
    }

    if !config.quiet {
        eprintln!(
            "\n  {} Scanning stdin ({} bytes)...\n",
            style("[STDIN]").cyan().bold(),
            content.len()
        );
    }

    let mut report = ScanReport::new();

    // Analyze as text content
    let findings = analyzers::text::analyze_text_content("<stdin>", &content, ollama).await?;

    report.add_file_findings(
        "<stdin>".to_string(),
        crate::scanner::classifier::FileKind::Text,
        content.len() as u64,
        findings,
    );

    Ok(report)
}

/// Scan git diff output
pub async fn scan_diff(
    git_ref: &str,
    config: &ScanConfig,
    ollama: &OllamaClient,
) -> Result<ScanReport> {
    // Get changed files
    let output = std::process::Command::new("git")
        .args(["diff", "--name-only", git_ref])
        .output()?;

    if !output.status.success() {
        anyhow::bail!(
            "git diff failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    let changed_files: Vec<String> = String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter(|l| !l.is_empty())
        .map(String::from)
        .collect();

    if changed_files.is_empty() {
        eprintln!("  No changed files since {}", git_ref);
        return Ok(ScanReport::new());
    }

    if !config.quiet {
        eprintln!(
            "\n  {} Scanning {} changed file(s) since {}...\n",
            style("[DIFF]").cyan().bold(),
            changed_files.len(),
            style(git_ref).cyan()
        );
    }

    let file_types = vec!["text".into(), "image".into()];
    let mut all_files = Vec::new();

    for path in &changed_files {
        if !std::path::Path::new(path).exists() {
            continue;
        }
        match scanner::discovery::discover_files(path, config.max_size_bytes, &file_types) {
            Ok(files) => all_files.extend(files),
            Err(_) => continue,
        }
    }

    if all_files.is_empty() {
        eprintln!("  No scannable files in diff.");
        return Ok(ScanReport::new());
    }

    scanner::pipeline::run_scan(all_files, config, ollama).await
}
