use crate::report::ScanReport;
use std::path::Path;

#[derive(Debug, Default)]
pub struct Policy {
    pub block: Vec<PolicyRule>,
    pub warn: Vec<PolicyRule>,
    pub ignore: Vec<String>,
}

#[derive(Debug)]
pub struct PolicyRule {
    pub category: String,
    pub severity: Vec<String>,
}

impl Policy {
    /// Load policy from YAML file
    pub fn load(explicit_path: Option<&str>) -> Self {
        let candidates = if let Some(path) = explicit_path {
            vec![path.to_string()]
        } else {
            vec![
                ".torchsight/policy.yml".to_string(),
                ".torchsight/policy.yaml".to_string(),
            ]
        };

        for path in &candidates {
            if Path::new(path).exists() {
                if let Ok(content) = std::fs::read_to_string(path) {
                    match Self::parse_yaml(&content) {
                        Ok(policy) => {
                            tracing::debug!("Loaded policy from {}", path);
                            return policy;
                        }
                        Err(e) => {
                            eprintln!("Warning: Failed to parse policy {}: {}", path, e);
                        }
                    }
                }
            }
        }

        Self::default()
    }

    /// Simple YAML parser (avoids adding a yaml dependency)
    fn parse_yaml(content: &str) -> Result<Self, String> {
        let mut policy = Policy::default();
        let mut current_section: Option<&str> = None;
        let mut current_rule: Option<PolicyRule> = None;

        for line in content.lines() {
            let trimmed = line.trim();

            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }

            // Top-level sections
            if !line.starts_with(' ') && !line.starts_with('\t') {
                // Flush current rule
                if let Some(rule) = current_rule.take() {
                    match current_section {
                        Some("block") => policy.block.push(rule),
                        Some("warn") => policy.warn.push(rule),
                        _ => {}
                    }
                }

                if trimmed.starts_with("block") {
                    current_section = Some("block");
                } else if trimmed.starts_with("warn") {
                    current_section = Some("warn");
                } else if trimmed.starts_with("ignore") {
                    current_section = Some("ignore");
                }
                continue;
            }

            // List items
            if let Some(item) = trimmed.strip_prefix("- ") {
                match current_section {
                    Some("ignore") => {
                        policy.ignore.push(item.to_string());
                    }
                    Some("block") | Some("warn") => {
                        // Flush previous rule
                        if let Some(rule) = current_rule.take() {
                            match current_section {
                                Some("block") => policy.block.push(rule),
                                Some("warn") => policy.warn.push(rule),
                                _ => {}
                            }
                        }

                        // Parse inline: "- category: credentials"
                        if let Some(cat) = item.strip_prefix("category: ") {
                            current_rule = Some(PolicyRule {
                                category: cat.trim().to_string(),
                                severity: Vec::new(),
                            });
                        }
                    }
                    _ => {}
                }
                continue;
            }

            // Nested properties under a rule
            if let Some(ref mut rule) = current_rule {
                if let Some(cat) = trimmed.strip_prefix("category: ") {
                    rule.category = cat.trim().to_string();
                } else if let Some(sev) = trimmed.strip_prefix("severity: ") {
                    // Parse [critical, high] format
                    let sev = sev.trim_start_matches('[').trim_end_matches(']');
                    rule.severity = sev.split(',').map(|s| s.trim().to_string()).collect();
                }
            }
        }

        // Flush last rule
        if let Some(rule) = current_rule.take() {
            match current_section {
                Some("block") => policy.block.push(rule),
                Some("warn") => policy.warn.push(rule),
                _ => {}
            }
        }

        Ok(policy)
    }

    /// Check if any findings should be blocked by policy, returning violation messages
    pub fn check_blocked(&self, report: &ScanReport) -> Vec<String> {
        if self.block.is_empty() {
            return Vec::new();
        }

        let mut violations = Vec::new();

        for file in &report.files {
            for finding in &file.findings {
                if finding.category == "safe" {
                    continue;
                }

                // Check ignore patterns
                if self.is_ignored(&finding.category) {
                    continue;
                }

                for rule in &self.block {
                    if finding.category.starts_with(&rule.category)
                        || rule.category == "*"
                    {
                        // Check severity filter
                        if rule.severity.is_empty()
                            || rule
                                .severity
                                .iter()
                                .any(|s| s.eq_ignore_ascii_case(&format!("{}", finding.severity)))
                        {
                            violations.push(format!(
                                "{}: {} [{}] in {}",
                                finding.category,
                                finding.description,
                                finding.severity,
                                file.path,
                            ));
                        }
                    }
                }
            }
        }

        violations
    }

    fn is_ignored(&self, category: &str) -> bool {
        for pattern in &self.ignore {
            if pattern.ends_with('*') {
                let prefix = &pattern[..pattern.len() - 1];
                if category.starts_with(prefix) {
                    return true;
                }
            } else if pattern == category {
                return true;
            }
        }
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::report::{FileFinding, ScanReport, Severity};
    use crate::scanner::classifier::FileKind;
    use std::collections::HashMap;

    fn make_report(findings: Vec<(&str, Severity)>) -> ScanReport {
        let mut report = ScanReport::new();
        report.add_file_findings(
            "test.txt".to_string(),
            FileKind::Text,
            100,
            findings
                .into_iter()
                .map(|(cat, sev)| FileFinding {
                    category: cat.to_string(),
                    description: format!("Found {}", cat),
                    evidence: String::new(),
                    severity: sev,
                    source: "test".to_string(),
                    extracted_data: HashMap::new(),
                })
                .collect(),
        );
        report
    }

    // =========================================================================
    // Policy parsing
    // =========================================================================

    #[test]
    fn parse_block_rule_with_category() {
        let yaml = r#"
block:
  - category: credentials
"#;
        let policy = Policy::parse_yaml(yaml).unwrap();
        assert_eq!(policy.block.len(), 1);
        assert_eq!(policy.block[0].category, "credentials");
        assert!(policy.block[0].severity.is_empty());
    }

    #[test]
    fn parse_block_rule_with_severity_filter() {
        let yaml = r#"
block:
  - category: pii
    severity: [critical, high]
"#;
        let policy = Policy::parse_yaml(yaml).unwrap();
        assert_eq!(policy.block.len(), 1);
        assert_eq!(policy.block[0].category, "pii");
        assert_eq!(policy.block[0].severity, vec!["critical", "high"]);
    }

    #[test]
    fn parse_multiple_block_rules() {
        let yaml = r#"
block:
  - category: credentials
  - category: malicious
    severity: [critical]
"#;
        let policy = Policy::parse_yaml(yaml).unwrap();
        assert_eq!(policy.block.len(), 2);
        assert_eq!(policy.block[0].category, "credentials");
        assert_eq!(policy.block[1].category, "malicious");
    }

    #[test]
    fn parse_warn_rules() {
        let yaml = r#"
warn:
  - category: pii
    severity: [medium, low]
"#;
        let policy = Policy::parse_yaml(yaml).unwrap();
        assert_eq!(policy.warn.len(), 1);
        assert_eq!(policy.warn[0].category, "pii");
    }

    #[test]
    fn parse_ignore_rules() {
        let yaml = r#"
ignore:
  - safe
  - medical*
"#;
        let policy = Policy::parse_yaml(yaml).unwrap();
        assert_eq!(policy.ignore.len(), 2);
        assert_eq!(policy.ignore[0], "safe");
        assert_eq!(policy.ignore[1], "medical*");
    }

    #[test]
    fn parse_full_policy() {
        let yaml = r#"
block:
  - category: credentials
  - category: malicious
    severity: [critical, high]
warn:
  - category: pii
    severity: [medium]
ignore:
  - safe
"#;
        let policy = Policy::parse_yaml(yaml).unwrap();
        assert_eq!(policy.block.len(), 2);
        assert_eq!(policy.warn.len(), 1);
        assert_eq!(policy.ignore.len(), 1);
    }

    #[test]
    fn parse_empty_yaml() {
        let policy = Policy::parse_yaml("").unwrap();
        assert!(policy.block.is_empty());
        assert!(policy.warn.is_empty());
        assert!(policy.ignore.is_empty());
    }

    #[test]
    fn parse_comments_ignored() {
        let yaml = r#"
# This is a comment
block:
  # Another comment
  - category: credentials
"#;
        let policy = Policy::parse_yaml(yaml).unwrap();
        assert_eq!(policy.block.len(), 1);
    }

    // =========================================================================
    // check_blocked
    // =========================================================================

    #[test]
    fn block_rule_matches_category() {
        let policy = Policy {
            block: vec![PolicyRule {
                category: "credentials".to_string(),
                severity: vec![],
            }],
            warn: vec![],
            ignore: vec![],
        };
        let report = make_report(vec![("credentials", Severity::High)]);
        let blocked = policy.check_blocked(&report);
        assert_eq!(blocked.len(), 1);
        assert!(blocked[0].contains("credentials"));
    }

    #[test]
    fn block_rule_no_match() {
        let policy = Policy {
            block: vec![PolicyRule {
                category: "credentials".to_string(),
                severity: vec![],
            }],
            warn: vec![],
            ignore: vec![],
        };
        let report = make_report(vec![("pii", Severity::High)]);
        let blocked = policy.check_blocked(&report);
        assert!(blocked.is_empty());
    }

    #[test]
    fn block_rule_with_severity_filter_matches() {
        let policy = Policy {
            block: vec![PolicyRule {
                category: "pii".to_string(),
                severity: vec!["CRITICAL".to_string()],
            }],
            warn: vec![],
            ignore: vec![],
        };
        let report = make_report(vec![("pii", Severity::Critical)]);
        let blocked = policy.check_blocked(&report);
        assert_eq!(blocked.len(), 1);
    }

    #[test]
    fn block_rule_with_severity_filter_no_match() {
        let policy = Policy {
            block: vec![PolicyRule {
                category: "pii".to_string(),
                severity: vec!["CRITICAL".to_string()],
            }],
            warn: vec![],
            ignore: vec![],
        };
        let report = make_report(vec![("pii", Severity::Low)]);
        let blocked = policy.check_blocked(&report);
        assert!(blocked.is_empty());
    }

    #[test]
    fn block_wildcard_matches_all() {
        let policy = Policy {
            block: vec![PolicyRule {
                category: "*".to_string(),
                severity: vec![],
            }],
            warn: vec![],
            ignore: vec![],
        };
        let report = make_report(vec![
            ("pii", Severity::High),
            ("credentials", Severity::Critical),
        ]);
        let blocked = policy.check_blocked(&report);
        assert_eq!(blocked.len(), 2);
    }

    #[test]
    fn block_skips_safe_findings() {
        let policy = Policy {
            block: vec![PolicyRule {
                category: "*".to_string(),
                severity: vec![],
            }],
            warn: vec![],
            ignore: vec![],
        };
        let report = make_report(vec![("safe", Severity::Info)]);
        let blocked = policy.check_blocked(&report);
        assert!(blocked.is_empty());
    }

    #[test]
    fn empty_policy_blocks_nothing() {
        let policy = Policy::default();
        let report = make_report(vec![
            ("pii", Severity::Critical),
            ("credentials", Severity::Critical),
            ("malicious", Severity::Critical),
        ]);
        let blocked = policy.check_blocked(&report);
        assert!(blocked.is_empty());
    }

    // =========================================================================
    // ignore rules
    // =========================================================================

    #[test]
    fn ignore_exact_match() {
        let policy = Policy {
            block: vec![PolicyRule {
                category: "*".to_string(),
                severity: vec![],
            }],
            warn: vec![],
            ignore: vec!["pii".to_string()],
        };
        let report = make_report(vec![("pii", Severity::High)]);
        let blocked = policy.check_blocked(&report);
        assert!(blocked.is_empty(), "Ignored category should not be blocked");
    }

    #[test]
    fn ignore_wildcard_prefix() {
        let policy = Policy {
            block: vec![PolicyRule {
                category: "*".to_string(),
                severity: vec![],
            }],
            warn: vec![],
            ignore: vec!["medical*".to_string()],
        };
        let report = make_report(vec![("medical_records", Severity::High)]);
        let blocked = policy.check_blocked(&report);
        assert!(blocked.is_empty());
    }

    #[test]
    fn ignore_does_not_affect_non_matching() {
        let policy = Policy {
            block: vec![PolicyRule {
                category: "*".to_string(),
                severity: vec![],
            }],
            warn: vec![],
            ignore: vec!["pii".to_string()],
        };
        let report = make_report(vec![
            ("pii", Severity::High),
            ("credentials", Severity::Critical),
        ]);
        let blocked = policy.check_blocked(&report);
        assert_eq!(blocked.len(), 1);
        assert!(blocked[0].contains("credentials"));
    }

    #[test]
    fn block_prefix_matches_subcategory() {
        // "malicious" should match "malicious.injection"
        let policy = Policy {
            block: vec![PolicyRule {
                category: "malicious".to_string(),
                severity: vec![],
            }],
            warn: vec![],
            ignore: vec![],
        };
        let report = make_report(vec![("malicious.injection", Severity::Critical)]);
        let blocked = policy.check_blocked(&report);
        assert_eq!(blocked.len(), 1);
    }
}
