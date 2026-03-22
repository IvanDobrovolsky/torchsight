use anyhow::Result;
use std::collections::HashMap;
use std::path::Path;
use std::process::Command;

use crate::llm::OllamaClient;
use crate::report::{FileFinding, Severity};

/// Check if readpst (libpst) is available on the system.
pub fn is_available() -> bool {
    Command::new("readpst")
        .arg("--version")
        .output()
        .is_ok_and(|o| o.status.success() || !o.stderr.is_empty())
}

/// Platform-specific install hint for readpst.
pub fn install_hint() -> &'static str {
    if cfg!(target_os = "macos") {
        "brew install libpst"
    } else if cfg!(target_os = "windows") {
        "Download from https://www.five-ten-sg.com/libpst/ or use WSL: apt install pst-utils"
    } else {
        "apt install pst-utils (Debian/Ubuntu) or dnf install libpst (Fedora)"
    }
}

/// Represents a single extracted email.
pub struct ExtractedEmail {
    pub filename: String,
    pub content: String,
}

/// Extract emails from a PST file using readpst.
/// Extracts to a temp directory, then reads each .eml file.
fn extract_emails(path: &Path) -> Result<Vec<ExtractedEmail>> {
    let tmp_dir = tempfile::tempdir()?;
    let tmp_path = tmp_dir.path();

    // readpst -e: extract each email to its own file
    // readpst -o: output directory
    // readpst -b: don't save RTF body
    // readpst -S: write emails as .eml files (MIME format)
    let output = Command::new("readpst")
        .args([
            "-e",         // individual files per email
            "-o",
            &tmp_path.to_string_lossy(),
            "-b",         // skip RTF body
            &path.to_string_lossy(),
        ])
        .output()
        .map_err(|e| anyhow::anyhow!("Failed to run readpst: {}. Install: {}", e, install_hint()))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!("readpst failed: {}", stderr.trim());
    }

    // Collect all extracted files recursively
    let mut emails = Vec::new();
    collect_email_files(tmp_path, &mut emails)?;

    Ok(emails)
}

/// Recursively collect email content from extracted PST directory.
/// readpst creates subdirectories for each folder (Inbox, Sent, etc.)
fn collect_email_files(dir: &Path, emails: &mut Vec<ExtractedEmail>) -> Result<()> {
    let entries = std::fs::read_dir(dir)?;
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect_email_files(&path, emails)?;
        } else if path.is_file() {
            let filename = path
                .file_name()
                .unwrap_or_default()
                .to_string_lossy()
                .to_string();

            // Read the email content (readpst outputs plain text or MIME)
            if let Ok(content) = std::fs::read_to_string(&path) {
                if !content.trim().is_empty() {
                    emails.push(ExtractedEmail { filename, content });
                }
            }
        }
    }
    Ok(())
}

/// Parse email headers from content (best-effort).
fn parse_email_header<'a>(content: &'a str, header: &str) -> &'a str {
    for line in content.lines() {
        if let Some(value) = line.strip_prefix(header) {
            if let Some(value) = value.strip_prefix(": ") {
                return value.trim();
            }
        }
        // Headers end at first blank line
        if line.is_empty() {
            break;
        }
    }
    ""
}

/// Analyze a PST/OST email archive. Each email is scanned individually.
pub async fn analyze_email_archive(
    path: &Path,
    ollama: &OllamaClient,
) -> Result<Vec<FileFinding>> {
    let archive_name = path
        .file_name()
        .unwrap_or_default()
        .to_string_lossy()
        .to_string();

    if !is_available() {
        anyhow::bail!(
            "readpst not found. PST scanning requires libpst. Install: {}",
            install_hint()
        );
    }

    let emails = extract_emails(path)?;

    if emails.is_empty() {
        return Ok(vec![FileFinding {
            category: "safe".to_string(),
            description: format!("Email archive {} contains no extractable messages.", archive_name),
            evidence: String::new(),
            severity: Severity::Info,
            source: "scanner".to_string(),
            extracted_data: HashMap::new(),
        }]);
    }

    eprintln!(
        "  {} Extracted {} emails from {}",
        console::style("[PST]").cyan(),
        emails.len(),
        archive_name,
    );

    let mut all_findings = Vec::new();

    for (i, email) in emails.iter().enumerate() {
        // Extract headers for metadata
        let subject = parse_email_header(&email.content, "Subject");
        let from = parse_email_header(&email.content, "From");
        let to = parse_email_header(&email.content, "To");
        let date = parse_email_header(&email.content, "Date");

        // Truncate to LLM context limit
        let truncated: String = email.content.chars().take(6000).collect();

        if truncated.trim().is_empty() {
            continue;
        }

        let message = format!(
            "Analyze the following email for security threats, sensitive data, and policy violations.\n\n{}",
            truncated
        );

        let response = ollama.chat(&message).await;
        let mut findings = match response {
            Ok(resp) => {
                super::text::parse_beam_findings_public(&resp).unwrap_or_default()
            }
            Err(e) => {
                eprintln!(
                    "  {} Failed to analyze email {}/{}: {}",
                    console::style("[WARN]").yellow(),
                    i + 1,
                    emails.len(),
                    e
                );
                continue;
            }
        };

        // Enrich findings with email metadata
        let email_label = if subject.is_empty() {
            email.filename.clone()
        } else {
            subject.to_string()
        };

        for finding in &mut findings {
            finding.extracted_data.insert(
                "source_file".to_string(),
                archive_name.clone(),
            );
            finding.extracted_data.insert(
                "email_subject".to_string(),
                email_label.clone(),
            );
            if !from.is_empty() {
                finding.extracted_data.insert(
                    "email_from".to_string(),
                    from.to_string(),
                );
            }
            if !to.is_empty() {
                finding.extracted_data.insert(
                    "email_to".to_string(),
                    to.to_string(),
                );
            }
            if !date.is_empty() {
                finding.extracted_data.insert(
                    "email_date".to_string(),
                    date.to_string(),
                );
            }
            if finding.evidence.is_empty() && finding.category != "safe" {
                finding.evidence = format!(
                    "Email: \"{}\" from {}",
                    email_label, from
                );
            }
        }

        // Filter out safe findings for individual emails
        let non_safe: Vec<FileFinding> = findings
            .into_iter()
            .filter(|f| f.category != "safe")
            .collect();

        all_findings.extend(non_safe);
    }

    // If no findings across all emails, mark archive as clean
    if all_findings.is_empty() {
        all_findings.push(FileFinding {
            category: "safe".to_string(),
            description: format!(
                "Email archive analyzed ({} messages). No sensitive content detected.",
                emails.len()
            ),
            evidence: String::new(),
            severity: Severity::Info,
            source: "beam".to_string(),
            extracted_data: {
                let mut m = HashMap::new();
                m.insert("source_file".to_string(), archive_name);
                m.insert("message_count".to_string(), emails.len().to_string());
                m
            },
        });
    }

    Ok(all_findings)
}
