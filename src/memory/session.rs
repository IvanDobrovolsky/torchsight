use chrono::{DateTime, Utc};
use console::style;
use serde::{Deserialize, Serialize};

use crate::report::ScanReport;

#[derive(Debug, Serialize, Deserialize)]
struct ScanSummary {
    timestamp: DateTime<Utc>,
    total_files: usize,
    total_findings: usize,
    critical: usize,
    high: usize,
    medium: usize,
    top_categories: Vec<String>,
}

pub struct SessionMemory {
    summaries: Vec<ScanSummary>,
}

impl SessionMemory {
    pub fn new() -> Self {
        Self {
            summaries: Vec::new(),
        }
    }

    pub fn add_report_summary(&mut self, report: &ScanReport) {
        let mut categories: std::collections::HashMap<String, usize> =
            std::collections::HashMap::new();

        for file in &report.files {
            for finding in &file.findings {
                *categories.entry(finding.category.clone()).or_default() += 1;
            }
        }

        let mut top: Vec<(String, usize)> = categories.into_iter().collect();
        top.sort_by(|a, b| b.1.cmp(&a.1));
        let top_categories: Vec<String> = top
            .into_iter()
            .take(5)
            .map(|(cat, count)| format!("{} ({})", cat, count))
            .collect();

        self.summaries.push(ScanSummary {
            timestamp: report.timestamp,
            total_files: report.files.len(),
            total_findings: report.total_findings(),
            critical: report.critical_count(),
            high: report.high_count(),
            medium: report.medium_count(),
            top_categories,
        });

        self.save_to_disk();
    }

    pub fn print_history(&self) {
        if self.summaries.is_empty() {
            println!("  No scan history in this session.");
            return;
        }

        println!("\n  {}\n", style("Scan History").bold().underlined());

        for (i, summary) in self.summaries.iter().enumerate() {
            println!(
                "  {}. {} | {} files | {} findings ({} critical)",
                i + 1,
                summary.timestamp.format("%H:%M:%S"),
                summary.total_files,
                summary.total_findings,
                summary.critical,
            );
            if !summary.top_categories.is_empty() {
                println!(
                    "     Categories: {}",
                    style(summary.top_categories.join(", ")).dim()
                );
            }
        }
        println!();
    }

    fn save_to_disk(&self) {
        let dir = dirs::home_dir()
            .map(|h| h.join(".torchsight").join("sessions"))
            .unwrap_or_default();

        if dir.as_os_str().is_empty() {
            return;
        }

        if std::fs::create_dir_all(&dir).is_err() {
            return;
        }

        let path = dir.join(format!(
            "session_{}.json",
            Utc::now().format("%Y%m%d_%H%M%S")
        ));

        let _ = std::fs::write(path, serde_json::to_string_pretty(&self.summaries).unwrap_or_default());
    }
}
