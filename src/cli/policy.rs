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
