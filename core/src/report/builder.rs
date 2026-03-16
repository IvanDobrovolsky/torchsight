use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::scanner::classifier::FileKind;

#[derive(Debug, Clone, Hash, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scanner::classifier::FileKind;

    fn make_finding(category: &str, severity: Severity) -> FileFinding {
        FileFinding {
            category: category.to_string(),
            description: format!("Test finding: {}", category),
            evidence: String::new(),
            severity,
            source: "test".to_string(),
            extracted_data: HashMap::new(),
        }
    }

    #[test]
    fn new_report_is_empty() {
        let report = ScanReport::new();
        assert!(report.files.is_empty());
        assert_eq!(report.total_findings(), 0);
        assert_eq!(report.flagged_count(), 0);
        assert_eq!(report.clean_count(), 0);
    }

    #[test]
    fn add_file_findings() {
        let mut report = ScanReport::new();
        report.add_file_findings(
            "test.txt".to_string(),
            FileKind::Text,
            100,
            vec![make_finding("pii", Severity::High)],
        );
        assert_eq!(report.files.len(), 1);
        assert_eq!(report.files[0].path, "test.txt");
        assert_eq!(report.files[0].kind, FileKind::Text);
        assert_eq!(report.files[0].size, 100);
        assert_eq!(report.files[0].findings.len(), 1);
    }

    #[test]
    fn total_findings_excludes_safe() {
        let mut report = ScanReport::new();
        report.add_file_findings(
            "a.txt".to_string(),
            FileKind::Text,
            100,
            vec![
                make_finding("pii", Severity::High),
                make_finding("safe", Severity::Info),
            ],
        );
        assert_eq!(report.total_findings(), 1);
    }

    #[test]
    fn flagged_and_clean_counts() {
        let mut report = ScanReport::new();
        // File with findings
        report.add_file_findings(
            "bad.txt".to_string(),
            FileKind::Text,
            100,
            vec![make_finding("pii", Severity::High)],
        );
        // Clean file
        report.add_file_findings(
            "good.txt".to_string(),
            FileKind::Text,
            50,
            vec![make_finding("safe", Severity::Info)],
        );
        assert_eq!(report.flagged_count(), 1);
        assert_eq!(report.clean_count(), 1);
    }

    #[test]
    fn severity_counts() {
        let mut report = ScanReport::new();
        report.add_file_findings(
            "mixed.txt".to_string(),
            FileKind::Text,
            500,
            vec![
                make_finding("malicious", Severity::Critical),
                make_finding("pii", Severity::High),
                make_finding("credentials", Severity::High),
                make_finding("financial", Severity::Medium),
                make_finding("medical", Severity::Low),
                make_finding("safe", Severity::Info),
            ],
        );
        assert_eq!(report.critical_count(), 1);
        assert_eq!(report.high_count(), 2);
        assert_eq!(report.medium_count(), 1);
        assert_eq!(report.low_count(), 1);
        assert_eq!(report.info_count(), 1);
    }

    #[test]
    fn has_severity_at_or_above_critical() {
        let mut report = ScanReport::new();
        report.add_file_findings(
            "a.txt".to_string(),
            FileKind::Text,
            100,
            vec![make_finding("malicious", Severity::Critical)],
        );
        assert!(report.has_severity_at_or_above(&Severity::Critical));
        assert!(report.has_severity_at_or_above(&Severity::High));
        assert!(report.has_severity_at_or_above(&Severity::Info));
    }

    #[test]
    fn has_severity_at_or_above_medium_only() {
        let mut report = ScanReport::new();
        report.add_file_findings(
            "a.txt".to_string(),
            FileKind::Text,
            100,
            vec![make_finding("pii", Severity::Medium)],
        );
        assert!(!report.has_severity_at_or_above(&Severity::Critical));
        assert!(!report.has_severity_at_or_above(&Severity::High));
        assert!(report.has_severity_at_or_above(&Severity::Medium));
        assert!(report.has_severity_at_or_above(&Severity::Low));
        assert!(report.has_severity_at_or_above(&Severity::Info));
    }

    #[test]
    fn has_severity_at_or_above_ignores_safe() {
        let mut report = ScanReport::new();
        report.add_file_findings(
            "a.txt".to_string(),
            FileKind::Text,
            100,
            vec![make_finding("safe", Severity::Info)],
        );
        // Even though Info >= Info, safe findings are excluded
        assert!(!report.has_severity_at_or_above(&Severity::Info));
    }

    #[test]
    fn has_severity_at_or_above_empty_report() {
        let report = ScanReport::new();
        assert!(!report.has_severity_at_or_above(&Severity::Info));
    }

    #[test]
    fn max_severity_returns_highest() {
        let mut report = ScanReport::new();
        report.add_file_findings(
            "a.txt".to_string(),
            FileKind::Text,
            100,
            vec![
                make_finding("pii", Severity::Low),
                make_finding("credentials", Severity::High),
                make_finding("financial", Severity::Medium),
            ],
        );
        assert_eq!(report.max_severity(), Some(&Severity::High));
    }

    #[test]
    fn max_severity_empty_report() {
        let report = ScanReport::new();
        assert_eq!(report.max_severity(), None);
    }

    #[test]
    fn max_severity_ignores_safe() {
        let mut report = ScanReport::new();
        report.add_file_findings(
            "a.txt".to_string(),
            FileKind::Text,
            100,
            vec![make_finding("safe", Severity::Info)],
        );
        assert_eq!(report.max_severity(), None);
    }

    #[test]
    fn severity_ordering() {
        assert!(Severity::Critical > Severity::High);
        assert!(Severity::High > Severity::Medium);
        assert!(Severity::Medium > Severity::Low);
        assert!(Severity::Low > Severity::Info);
    }

    #[test]
    fn severity_display() {
        assert_eq!(format!("{}", Severity::Critical), "CRITICAL");
        assert_eq!(format!("{}", Severity::High), "HIGH");
        assert_eq!(format!("{}", Severity::Medium), "MEDIUM");
        assert_eq!(format!("{}", Severity::Low), "LOW");
        assert_eq!(format!("{}", Severity::Info), "INFO");
    }

    #[test]
    fn report_serializes_to_json() {
        let mut report = ScanReport::new();
        report.add_file_findings(
            "test.txt".to_string(),
            FileKind::Text,
            42,
            vec![make_finding("pii", Severity::High)],
        );
        let json = serde_json::to_string(&report).unwrap();
        assert!(json.contains("test.txt"));
        assert!(json.contains("pii"));
        // Should roundtrip
        let deserialized: ScanReport = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.files.len(), 1);
    }
}
