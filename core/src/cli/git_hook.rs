use anyhow::Result;
use console::style;
use std::path::PathBuf;

use crate::cli::ScanConfig;
use crate::llm::OllamaClient;
use crate::report::Severity;
use crate::scanner;

const HOOK_SCRIPT: &str = r#"#!/bin/sh
# TorchSight pre-commit hook — scans staged files for secrets, PII, and threats
# Installed by: torchsight git-hook install

exec torchsight git-hook scan
"#;

/// Install the pre-commit hook in the current git repo
pub fn install() -> Result<()> {
    let hooks_dir = find_git_hooks_dir()?;
    let hook_path = hooks_dir.join("pre-commit");

    if hook_path.exists() {
        let existing = std::fs::read_to_string(&hook_path)?;
        if existing.contains("torchsight") {
            println!(
                "  {} TorchSight pre-commit hook already installed at {}",
                style("[OK]").green().bold(),
                hook_path.display()
            );
            return Ok(());
        }
        // Existing non-torchsight hook — don't overwrite
        anyhow::bail!(
            "A pre-commit hook already exists at {}. \
             Back it up first, then re-run this command.",
            hook_path.display()
        );
    }

    std::fs::create_dir_all(&hooks_dir)?;
    std::fs::write(&hook_path, HOOK_SCRIPT)?;

    // Make executable
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&hook_path, std::fs::Permissions::from_mode(0o755))?;
    }

    println!(
        "  {} Pre-commit hook installed at {}",
        style("[OK]").green().bold(),
        style(hook_path.display()).cyan()
    );
    println!(
        "  {} Staged files will be scanned before each commit.",
        style(">>").dim()
    );
    println!(
        "  {} Critical/high findings will block the commit.",
        style(">>").dim()
    );

    Ok(())
}

/// Uninstall the pre-commit hook
pub fn uninstall() -> Result<()> {
    let hooks_dir = find_git_hooks_dir()?;
    let hook_path = hooks_dir.join("pre-commit");

    if !hook_path.exists() {
        println!("  No pre-commit hook found.");
        return Ok(());
    }

    let content = std::fs::read_to_string(&hook_path)?;
    if !content.contains("torchsight") {
        println!("  Pre-commit hook exists but was not installed by TorchSight. Skipping.");
        return Ok(());
    }

    std::fs::remove_file(&hook_path)?;
    println!(
        "  {} Pre-commit hook removed.",
        style("[OK]").green().bold()
    );

    Ok(())
}

/// Scan staged files (called by the pre-commit hook)
pub async fn scan_staged(ollama_url: &str, text_model: &str, vision_model: &str) -> Result<()> {
    // Get list of staged files
    let output = std::process::Command::new("git")
        .args(["diff", "--cached", "--name-only", "--diff-filter=ACM"])
        .output()?;

    if !output.status.success() {
        anyhow::bail!("Failed to get staged files from git");
    }

    let staged: Vec<String> = String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter(|l| !l.is_empty())
        .map(String::from)
        .collect();

    if staged.is_empty() {
        return Ok(());
    }

    println!(
        "\n  {} Scanning {} staged file(s)...\n",
        style("[torchsight]").cyan().bold(),
        staged.len()
    );

    let ollama = OllamaClient::new(ollama_url, text_model, vision_model);

    // Check Ollama is reachable
    if !ollama.health_check().await.unwrap_or(false) {
        eprintln!(
            "  {} Ollama not reachable — skipping pre-commit scan.",
            style("[WARN]").yellow().bold()
        );
        return Ok(());
    }

    let config = ScanConfig {
        text_model: text_model.to_string(),
        vision_model: vision_model.to_string(),
        ollama_url: ollama_url.to_string(),
        max_size_bytes: 50 * 1024 * 1024, // 50MB limit for pre-commit
        format: "terminal".to_string(),
        quiet: false,
    };

    // Discover and scan each staged file
    let mut all_files = Vec::new();
    let file_types = vec!["text".into(), "image".into(), "email".into()];

    for path in &staged {
        let p = std::path::Path::new(path);
        if !p.exists() {
            continue;
        }
        match scanner::discovery::discover_files(path, config.max_size_bytes, &file_types) {
            Ok(files) => all_files.extend(files),
            Err(_) => continue,
        }
    }

    if all_files.is_empty() {
        return Ok(());
    }

    let report = scanner::pipeline::run_scan(all_files, &config, &ollama).await?;

    // Print findings
    let terminal_output = crate::report::format_report(&report, "terminal")?;
    if !terminal_output.trim().is_empty() {
        println!("{terminal_output}");
    }

    // Block commit on critical or high findings
    if report.has_severity_at_or_above(&Severity::High) {
        let critical = report.critical_count();
        let high = report.high_count();
        println!(
            "\n  {} Commit blocked: {} critical, {} high severity finding(s).",
            style("[BLOCKED]").red().bold(),
            critical,
            high
        );
        println!(
            "  {} Fix the issues above or use {} to bypass.\n",
            style(">>").dim(),
            style("git commit --no-verify").yellow()
        );
        std::process::exit(1);
    }

    let total = report.total_findings();
    if total > 0 {
        println!(
            "\n  {} {} finding(s) (below blocking threshold). Proceeding with commit.\n",
            style("[PASS]").yellow().bold(),
            total
        );
    } else {
        println!(
            "\n  {} No security issues found. Proceeding with commit.\n",
            style("[PASS]").green().bold(),
        );
    }

    Ok(())
}

fn find_git_hooks_dir() -> Result<PathBuf> {
    let output = std::process::Command::new("git")
        .args(["rev-parse", "--git-dir"])
        .output()?;

    if !output.status.success() {
        anyhow::bail!("Not a git repository. Run this from inside a git repo.");
    }

    let git_dir = String::from_utf8_lossy(&output.stdout).trim().to_string();
    Ok(PathBuf::from(git_dir).join("hooks"))
}
