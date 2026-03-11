use anyhow::Result;
use console::style;
use notify_debouncer_mini::new_debouncer;
use std::path::PathBuf;
use std::sync::mpsc;
use std::time::Duration;

use crate::cli::ScanConfig;
use crate::llm::OllamaClient;
use crate::report;
use crate::scanner;

pub async fn watch_directory(
    path: &str,
    config: &ScanConfig,
    ollama: &OllamaClient,
    interval: Duration,
) -> Result<()> {
    let watch_path = PathBuf::from(path).canonicalize()?;

    if !watch_path.exists() {
        anyhow::bail!("Path does not exist: {}", watch_path.display());
    }

    println!(
        "\n  {} Watching {} (debounce: {:?})",
        style("[WATCH]").cyan().bold(),
        style(watch_path.display()).cyan(),
        interval,
    );
    println!(
        "  {} Press Ctrl+C to stop.\n",
        style(">>").dim()
    );

    let (tx, rx) = mpsc::channel();

    let mut debouncer = new_debouncer(interval, tx)?;

    debouncer
        .watcher()
        .watch(&watch_path, notify::RecursiveMode::Recursive)?;

    // Process events
    loop {
        match rx.recv() {
            Ok(Ok(events)) => {
                // Collect unique changed file paths
                let mut changed_paths: Vec<PathBuf> = events
                    .into_iter()
                    .map(|e| e.path)
                    .filter(|p| p.is_file())
                    .collect();
                changed_paths.sort();
                changed_paths.dedup();

                if changed_paths.is_empty() {
                    continue;
                }

                println!(
                    "\n  {} {} file(s) changed:",
                    style("[CHANGE]").yellow().bold(),
                    changed_paths.len()
                );
                for p in &changed_paths {
                    println!("    {}", style(p.display()).dim());
                }

                // Scan each changed file
                let file_types = vec!["text".into(), "image".into()];
                let mut all_files = Vec::new();

                for path in &changed_paths {
                    let path_str = path.to_string_lossy();
                    match scanner::discovery::discover_files(
                        &path_str,
                        config.max_size_bytes,
                        &file_types,
                    ) {
                        Ok(files) => all_files.extend(files),
                        Err(_) => continue,
                    }
                }

                if all_files.is_empty() {
                    println!(
                        "  {} No scannable files in changed set.\n",
                        style("[INFO]").dim()
                    );
                    continue;
                }

                match scanner::pipeline::run_scan(all_files, config, ollama).await {
                    Ok(scan_report) => {
                        let total = scan_report.total_findings();
                        if total > 0 {
                            let output = report::format_report(&scan_report, "terminal")?;
                            println!("{output}");
                            println!(
                                "  {} {} finding(s) detected.\n",
                                style("[ALERT]").red().bold(),
                                total
                            );
                        } else {
                            println!(
                                "  {} No issues found.\n",
                                style("[OK]").green().bold()
                            );
                        }
                    }
                    Err(e) => {
                        println!(
                            "  {} Scan error: {}\n",
                            style("[ERROR]").red().bold(),
                            e
                        );
                    }
                }
            }
            Ok(Err(errors)) => {
                println!(
                    "  {} Watch error: {:?}\n",
                    style("[ERROR]").red().bold(),
                    errors
                );
            }
            Err(_) => {
                // Channel disconnected
                break;
            }
        }
    }

    Ok(())
}
