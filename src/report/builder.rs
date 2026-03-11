use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::scanner::classifier::FileKind;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Severity::Critical => write!(f, "CRITICAL"),
            Severity::High => write!(f, "HIGH"),
            Severity::Medium => write!(f, "MEDIUM"),
            Severity::Low => write!(f, "LOW"),
            Severity::Info => write!(f, "INFO"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileFinding {
    pub category: String,
    pub description: String,
    pub evidence: String,
    pub severity: Severity,
    pub source: String,
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub extracted_data: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileResult {
    pub path: String,
    pub kind: FileKind,
    pub size: u64,
    pub findings: Vec<FileFinding>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanReport {
    pub timestamp: DateTime<Utc>,
    pub files: Vec<FileResult>,
}

impl ScanReport {
    pub fn new() -> Self {
        Self {
            timestamp: Utc::now(),
            files: Vec::new(),
        }
    }

    pub fn add_file_findings(
        &mut self,
        path: String,
        kind: FileKind,
        size: u64,
        findings: Vec<FileFinding>,
    ) {
        self.files.push(FileResult {
            path,
            kind,
            size,
            findings,
        });
    }

    pub fn total_findings(&self) -> usize {
        self.files
            .iter()
            .flat_map(|f| &f.findings)
            .filter(|f| f.category != "safe")
            .count()
    }

    pub fn flagged_count(&self) -> usize {
        self.files
            .iter()
            .filter(|f| f.findings.iter().any(|finding| finding.category != "safe"))
            .count()
    }

    pub fn clean_count(&self) -> usize {
        self.files.len() - self.flagged_count()
    }

    pub fn critical_count(&self) -> usize {
        self.files
            .iter()
            .flat_map(|f| &f.findings)
            .filter(|f| f.severity == Severity::Critical)
            .count()
    }

    pub fn high_count(&self) -> usize {
        self.files
            .iter()
            .flat_map(|f| &f.findings)
            .filter(|f| f.severity == Severity::High)
            .count()
    }

    pub fn medium_count(&self) -> usize {
        self.files
            .iter()
            .flat_map(|f| &f.findings)
            .filter(|f| f.severity == Severity::Medium)
            .count()
    }

    pub fn low_count(&self) -> usize {
        self.files
            .iter()
            .flat_map(|f| &f.findings)
            .filter(|f| f.severity == Severity::Low)
            .count()
    }

    pub fn info_count(&self) -> usize {
        self.files
            .iter()
            .flat_map(|f| &f.findings)
            .filter(|f| f.severity == Severity::Info)
            .count()
    }

    /// Check if any finding meets or exceeds the given severity threshold
    pub fn has_severity_at_or_above(&self, threshold: &Severity) -> bool {
        self.files
            .iter()
            .flat_map(|f| &f.findings)
            .filter(|f| f.category != "safe")
            .any(|f| f.severity >= *threshold)
    }

    /// Get the highest severity found in the report
    pub fn max_severity(&self) -> Option<&Severity> {
        self.files
            .iter()
            .flat_map(|f| &f.findings)
            .filter(|f| f.category != "safe")
            .map(|f| &f.severity)
            .max()
    }
}
