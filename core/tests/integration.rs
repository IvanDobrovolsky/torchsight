//! Integration tests for TorchSight — tests that cross module boundaries.
//! These do NOT require Ollama or any external services.

use std::collections::HashMap;

/// Import the crate under test
use torchsight::report::{format_report, FileFinding, ScanReport, Severity};
use torchsight::scanner::classifier::FileKind;

// =============================================================================
// End-to-end report generation pipeline
// =============================================================================

fn build_sample_report() -> ScanReport {
    let mut report = ScanReport::new();

    // File with critical findings
    report.add_file_findings(
        "/data/secrets.env".to_string(),
        FileKind::Text,
        1024,
        vec![
            FileFinding {
                category: "credentials".to_string(),
                description: "AWS access key found in environment file".to_string(),
                evidence: "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
                    .to_string(),
                severity: Severity::Critical,
                source: "beam".to_string(),
                extracted_data: {
                    let mut m = HashMap::new();
                    m.insert("api_key".to_string(), "AKIAIOSFODNN7EXAMPLE".to_string());
                    m
                },
            },
            FileFinding {
                category: "credentials".to_string(),
                description: "Database connection string with password".to_string(),
                evidence: "DATABASE_URL=postgres://admin:s3cret@db.internal:5432/prod"
                    .to_string(),
                severity: Severity::High,
                source: "beam".to_string(),
                extracted_data: HashMap::new(),
            },
        ],
    );

    // File with PII
    report.add_file_findings(
        "/data/customers.csv".to_string(),
        FileKind::Text,
        50000,
        vec![FileFinding {
            category: "pii".to_string(),
            description: "Contains customer PII including SSN and addresses".to_string(),
            evidence: "John Doe,123-45-6789,123 Main St".to_string(),
            severity: Severity::High,
            source: "beam".to_string(),
            extracted_data: {
                let mut m = HashMap::new();
                m.insert("ssn".to_string(), "123-45-6789".to_string());
                m.insert("full_name".to_string(), "John Doe".to_string());
                m
            },
        }],
    );

    // Clean file
    report.add_file_findings(
        "/data/readme.md".to_string(),
        FileKind::Text,
        200,
        vec![FileFinding {
            category: "safe".to_string(),
            description: "Documentation file with no sensitive content".to_string(),
            evidence: String::new(),
            severity: Severity::Info,
            source: "beam".to_string(),
            extracted_data: HashMap::new(),
        }],
    );

    // Image file
    report.add_file_findings(
        "/data/screenshot.png".to_string(),
        FileKind::Image,
        500000,
        vec![FileFinding {
            category: "pii".to_string(),
            description: "Screenshot contains visible credentials".to_string(),
            evidence: "password visible in terminal".to_string(),
            severity: Severity::Medium,
            source: "beam".to_string(),
            extracted_data: HashMap::new(),
        }],
    );

    report
}

#[test]
fn integration_report_statistics() {
    let report = build_sample_report();
    assert_eq!(report.files.len(), 4);
    assert_eq!(report.flagged_count(), 3);
    assert_eq!(report.clean_count(), 1);
    assert_eq!(report.critical_count(), 1);
    assert_eq!(report.high_count(), 2);
    assert_eq!(report.medium_count(), 1);
    assert_eq!(report.total_findings(), 4); // excludes safe
}

#[test]
fn integration_json_report_roundtrip() {
    let report = build_sample_report();
    let json_output = format_report(&report, "json").unwrap();

    // Parse back
    let deserialized: ScanReport = serde_json::from_str(&json_output).unwrap();
    assert_eq!(deserialized.files.len(), 4);
    assert_eq!(deserialized.total_findings(), 4);
    assert_eq!(deserialized.critical_count(), 1);

    // Verify extracted data survived roundtrip
    let secrets_file = &deserialized.files[0];
    assert_eq!(secrets_file.path, "/data/secrets.env");
    let api_key = secrets_file.findings[0]
        .extracted_data
        .get("api_key")
        .unwrap();
    assert_eq!(api_key, "AKIAIOSFODNN7EXAMPLE");
}

#[test]
fn integration_markdown_report_structure() {
    let report = build_sample_report();
    let md = format_report(&report, "markdown").unwrap();

    // Check structure
    assert!(md.contains("# TorchSight Scan"));
    assert!(md.contains("**Summary:**"));
    assert!(md.contains("4 files analyzed"));
    assert!(md.contains("secrets.env"));
    assert!(md.contains("customers.csv"));
    assert!(md.contains("readme.md"));
    assert!(md.contains("[CRITICAL]"));
    assert!(md.contains("[HIGH]"));
    assert!(md.contains("AWS access key"));
}

#[test]
fn integration_sarif_report_structure() {
    let report = build_sample_report();
    let sarif = format_report(&report, "sarif").unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&sarif).unwrap();

    assert_eq!(parsed["version"], "2.1.0");
    let results = parsed["runs"][0]["results"].as_array().unwrap();
    // Should have 4 non-safe findings
    assert_eq!(results.len(), 4);

    // Verify rule IDs
    let rule_ids: Vec<&str> = results
        .iter()
        .map(|r| r["ruleId"].as_str().unwrap())
        .collect();
    assert!(rule_ids.contains(&"torchsight/credentials"));
    assert!(rule_ids.contains(&"torchsight/pii"));
}

#[test]
fn integration_html_report_contains_data() {
    let report = build_sample_report();
    let html = format_report(&report, "html").unwrap();

    assert!(html.contains("<!DOCTYPE html>"));
    assert!(html.contains("TorchSight"));
    assert!(html.contains("secrets.env"));
    assert!(html.contains("customers.csv"));
}

#[test]
fn integration_fail_on_threshold() {
    let report = build_sample_report();

    // Has critical findings
    assert!(report.has_severity_at_or_above(&Severity::Critical));
    assert!(report.has_severity_at_or_above(&Severity::High));
    assert!(report.has_severity_at_or_above(&Severity::Medium));
    assert!(report.has_severity_at_or_above(&Severity::Low));
    assert!(report.has_severity_at_or_above(&Severity::Info));
}

#[test]
fn integration_all_safe_report_does_not_fail() {
    let mut report = ScanReport::new();
    report.add_file_findings(
        "clean.txt".to_string(),
        FileKind::Text,
        100,
        vec![FileFinding {
            category: "safe".to_string(),
            description: "Clean file".to_string(),
            evidence: String::new(),
            severity: Severity::Info,
            source: "beam".to_string(),
            extracted_data: HashMap::new(),
        }],
    );

    assert!(!report.has_severity_at_or_above(&Severity::Info));
    assert!(!report.has_severity_at_or_above(&Severity::Critical));
    assert_eq!(report.total_findings(), 0);
    assert_eq!(report.max_severity(), None);
}

// =============================================================================
// File discovery with tempdir
// =============================================================================

#[test]
fn integration_discover_and_classify_mixed_directory() {
    use torchsight::scanner::discovery::discover_files;

    let dir = tempfile::tempdir().unwrap();

    // Create various file types
    std::fs::write(dir.path().join("config.json"), r#"{"key":"value"}"#).unwrap();
    std::fs::write(dir.path().join("script.py"), "print('hello')").unwrap();
    std::fs::write(dir.path().join("notes.txt"), "Meeting notes").unwrap();

    // Create a subdirectory with more files
    let sub = dir.path().join("subdir");
    std::fs::create_dir(&sub).unwrap();
    std::fs::write(sub.join("data.csv"), "name,age\nAlice,30").unwrap();

    let files = discover_files(
        dir.path().to_str().unwrap(),
        10 * 1024 * 1024,
        &["all".to_string()],
    )
    .unwrap();

    assert_eq!(files.len(), 4);
    assert!(files.iter().all(|f| f.kind == FileKind::Text));
}

#[test]
fn integration_discover_with_ignore_and_size_limit() {
    use torchsight::scanner::discovery::discover_files;

    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("keep.txt"), "important").unwrap();
    std::fs::write(dir.path().join("skip.log"), "debug log").unwrap();
    std::fs::write(dir.path().join("huge.txt"), "x".repeat(5000)).unwrap();
    std::fs::write(dir.path().join(".torchsightignore"), "*.log\n").unwrap();

    let files = discover_files(
        dir.path().to_str().unwrap(),
        1000, // 1KB limit - excludes huge.txt
        &["all".to_string()],
    )
    .unwrap();

    assert_eq!(files.len(), 1);
    assert!(files[0].path.to_string_lossy().contains("keep.txt"));
}
