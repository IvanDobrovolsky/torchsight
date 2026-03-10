use anyhow::Result;
use chrono::Utc;
use console::style;

use super::builder::{ScanReport, Severity};

pub fn format_report(report: &ScanReport, format: &str) -> Result<String> {
    match format {
        "json" => Ok(serde_json::to_string_pretty(report)?),
        "markdown" => Ok(format_markdown(report)),
        _ => Ok(format_terminal(report)),
    }
}

pub fn save_report(report: &ScanReport, format: &str) -> Result<String> {
    let timestamp = Utc::now().format("%Y-%m-%d_%H%M%S");

    match format {
        "pdf" => save_pdf(report, &timestamp.to_string()),
        _ => {
            let ext = match format {
                "json" => "json",
                "markdown" => "md",
                _ => "txt",
            };
            let filename = format!("torchsight_report_{}.{}", timestamp, ext);
            let content = format_report(report, format)?;
            std::fs::write(&filename, &content)?;
            Ok(filename)
        }
    }
}


fn save_pdf(report: &ScanReport, timestamp: &str) -> Result<String> {
    let filename = format!("torchsight_report_{}.pdf", timestamp);

    // Write JSON to temp file
    let tmp_json = std::env::temp_dir().join(format!("torchsight_{}.json", timestamp));
    let json_content = serde_json::to_string_pretty(report)?;
    std::fs::write(&tmp_json, &json_content)?;

    // Find the report generator script relative to the executable
    let report_script = find_report_script()?;

    // Call Python report generator
    let output = std::process::Command::new("uv")
        .args([
            "run",
            "--project",
            report_script
                .parent()
                .unwrap()
                .to_str()
                .unwrap(),
            "python",
            report_script.to_str().unwrap(),
            tmp_json.to_str().unwrap(),
            "-o",
            &filename,
        ])
        .output()?;

    // Clean up temp file
    let _ = std::fs::remove_file(&tmp_json);

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!("PDF generator failed: {}", stderr.trim());
    }

    Ok(filename)
}

fn find_report_script() -> Result<std::path::PathBuf> {
    // Compile-time project root (works in dev builds)
    let project_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let from_manifest = project_root.join("report/generate.py");
    if from_manifest.exists() {
        return Ok(from_manifest.canonicalize()?);
    }

    // Try relative to executable (installed binary)
    if let Ok(exe) = std::env::current_exe() {
        let candidates = [
            exe.parent()
                .unwrap_or(std::path::Path::new("."))
                .join("../report/generate.py"),
            exe.parent()
                .unwrap_or(std::path::Path::new("."))
                .join("../../report/generate.py"),
            exe.parent()
                .unwrap_or(std::path::Path::new("."))
                .join("../share/torchsight/report/generate.py"),
        ];
        for c in &candidates {
            if c.exists() {
                return Ok(c.canonicalize()?);
            }
        }
    }

    // Try relative to cwd (fallback)
    let cwd_candidates = [
        std::path::PathBuf::from("report/generate.py"),
        std::path::PathBuf::from("../report/generate.py"),
    ];
    for c in &cwd_candidates {
        if c.exists() {
            return Ok(c.canonicalize()?);
        }
    }

    anyhow::bail!(
        "Could not find report/generate.py. Make sure the report directory is present."
    )
}

fn format_markdown(report: &ScanReport) -> String {
    let mut out = String::new();

    out.push_str(&format!(
        "# TorchSight Scan Report\n\n**Date:** {}\n\n",
        report.timestamp.format("%Y-%m-%d %H:%M:%S UTC")
    ));

    out.push_str(&format!(
        "**Summary:** {} findings ({} critical, {} high, {} medium, {} low, {} info)\n\n",
        report.total_findings(),
        report.critical_count(),
        report.high_count(),
        report.medium_count(),
        report.low_count(),
        report.info_count(),
    ));

    out.push_str("---\n\n");

    for file in &report.files {
        out.push_str(&format!("## {}\n\n", file.path));
        out.push_str(&format!(
            "- **Type:** {}\n- **Size:** {} bytes\n- **Findings:** {}\n\n",
            file.kind,
            file.size,
            file.findings.len()
        ));

        for finding in &file.findings {
            let icon = match finding.severity {
                Severity::Critical => "[CRITICAL]",
                Severity::High => "[HIGH]",
                Severity::Medium => "[MEDIUM]",
                Severity::Low => "[LOW]",
                Severity::Info => "[INFO]",
            };
            out.push_str(&format!(
                "- {} {} - {} (source: {})\n",
                icon, finding.category, finding.description, finding.source
            ));
            if !finding.evidence.is_empty() {
                out.push_str(&format!("  - Evidence: `{}`\n", finding.evidence));
            }

            if !finding.extracted_data.is_empty() {
                out.push_str("  - **Extracted Data:**\n");
                let mut keys: Vec<&String> = finding.extracted_data.keys().collect();
                keys.sort();
                for key in keys {
                    let label = key.replace('_', " ");
                    out.push_str(&format!(
                        "    - {}: `{}`\n",
                        label, finding.extracted_data[key]
                    ));
                }
            }
        }

        out.push('\n');
    }

    out
}

fn format_terminal(report: &ScanReport) -> String {
    let mut out = String::new();

    for file in &report.files {
        let has_issues = file.findings.iter().any(|f| f.category != "safe");

        if has_issues {
            out.push_str(&format!(
                "\n  {} ({})\n",
                style(&file.path).bold(),
                file.kind
            ));
        } else {
            out.push_str(&format!(
                "\n  {} ({}) {}\n",
                style(&file.path).dim(),
                file.kind,
                style("[CLEAN]").green().bold()
            ));
        }

        for finding in &file.findings {
            if finding.category == "safe" {
                // Show safe files with their summary
                let summary = finding
                    .extracted_data
                    .get("summary")
                    .or_else(|| finding.extracted_data.get("subject"))
                    .map(|s| s.as_str())
                    .unwrap_or(&finding.description);
                out.push_str(&format!("    {}\n", style(summary).dim()));
                continue;
            }

            let severity_str = match finding.severity {
                Severity::Critical => format!("{}", style("CRITICAL").red().bold()),
                Severity::High => format!("{}", style("HIGH").red()),
                Severity::Medium => format!("{}", style("MEDIUM").yellow().bold()),
                Severity::Low => format!("{}", style("LOW").yellow()),
                Severity::Info => format!("{}", style("INFO").dim()),
            };

            out.push_str(&format!(
                "    [{}] {} - {}\n",
                severity_str, finding.category, finding.description
            ));

            if !finding.evidence.is_empty() && finding.evidence != "[image content]" {
                out.push_str(&format!(
                    "           Evidence: {}\n",
                    style(&finding.evidence).dim()
                ));
            }

            if !finding.extracted_data.is_empty() {
                let mut keys: Vec<&String> = finding.extracted_data.keys().collect();
                keys.sort();
                for key in keys {
                    let label = key.replace('_', " ");
                    let value = &finding.extracted_data[key];
                    let colored_value = format!("{}", style(value).yellow());
                    out.push_str(&format!(
                        "           {}: {}\n",
                        style(label).dim(),
                        colored_value
                    ));
                }
            }
        }
    }

    out
}
