use regex::Regex;
use std::sync::LazyLock;

use crate::report::Severity;

pub struct PatternMatch {
    pub category: String,
    pub description: String,
    pub matched_text: String,
    pub severity: Severity,
}

struct PatternDef {
    name: &'static str,
    category: &'static str,
    regex: &'static str,
    severity: Severity,
}

const PATTERNS: &[PatternDef] = &[
    // Credentials
    PatternDef {
        name: "AWS Access Key",
        category: "credentials",
        regex: r"(?i)AKIA[0-9A-Z]{16}",
        severity: Severity::Critical,
    },
    PatternDef {
        name: "AWS Secret Key",
        category: "credentials",
        regex: r"(?i)aws[_\-]?secret[_\-]?access[_\-]?key\s*[=:]\s*[A-Za-z0-9/+=]{40}",
        severity: Severity::Critical,
    },
    PatternDef {
        name: "Generic API Key",
        category: "credentials",
        regex: r#"(?i)(api[_\-]?key|apikey)\s*[=:"]\s*[A-Za-z0-9\-_.]{20,}"#,
        severity: Severity::Critical,
    },
    PatternDef {
        name: "Generic Secret",
        category: "credentials",
        regex: r#"(?i)(secret|password|passwd|pwd)\s*[=:"]\s*[^\s"']{8,}"#,
        severity: Severity::Critical,
    },
    PatternDef {
        name: "Private Key",
        category: "credentials",
        regex: r"-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----",
        severity: Severity::Critical,
    },
    PatternDef {
        name: "JWT Token",
        category: "credentials",
        regex: r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}",
        severity: Severity::Warning,
    },
    PatternDef {
        name: "Bearer Token",
        category: "credentials",
        regex: r#"(?i)bearer\s+[A-Za-z0-9\-_.~+/]{20,}"#,
        severity: Severity::Warning,
    },
    PatternDef {
        name: "Connection String",
        category: "credentials",
        regex: r"(?i)(mongodb|postgres|mysql|redis|amqp)://[^\s]+",
        severity: Severity::Critical,
    },
    // PII
    PatternDef {
        name: "Email Address",
        category: "pii",
        regex: r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
        severity: Severity::Warning,
    },
    PatternDef {
        name: "SSN (US)",
        category: "pii",
        regex: r"\b\d{3}-\d{2}-\d{4}\b",
        severity: Severity::Critical,
    },
    PatternDef {
        name: "Phone Number (US)",
        category: "pii",
        regex: r"\b(\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b",
        severity: Severity::Warning,
    },
    PatternDef {
        name: "Credit Card (Visa/MC/Amex)",
        category: "financial",
        regex: r"\b(?:4\d{3}|5[1-5]\d{2}|3[47]\d{2})[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b",
        severity: Severity::Critical,
    },
    PatternDef {
        name: "IBAN",
        category: "financial",
        regex: r"\b[A-Z]{2}\d{2}[A-Z0-9]{4}\d{7}([A-Z0-9]?){0,16}\b",
        severity: Severity::Warning,
    },
    // IP addresses
    PatternDef {
        name: "IPv4 Address",
        category: "network",
        regex: r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b",
        severity: Severity::Info,
    },
];

static COMPILED_PATTERNS: LazyLock<Vec<(Regex, &'static PatternDef)>> = LazyLock::new(|| {
    PATTERNS
        .iter()
        .filter_map(|p| Regex::new(p.regex).ok().map(|r| (r, p)))
        .collect()
});

pub fn scan_text(content: &str) -> Vec<PatternMatch> {
    let mut matches = Vec::new();

    for (regex, def) in COMPILED_PATTERNS.iter() {
        for mat in regex.find_iter(content) {
            let matched = mat.as_str();
            // Redact middle portion for display
            let redacted = redact(matched);

            matches.push(PatternMatch {
                category: def.category.to_string(),
                description: def.name.to_string(),
                matched_text: redacted,
                severity: def.severity.clone(),
            });
        }
    }

    matches
}

fn redact(s: &str) -> String {
    let len = s.len();
    if len <= 8 {
        return format!("{}***", &s[..2.min(len)]);
    }
    let show = 4.min(len / 4);
    format!("{}...{}", &s[..show], &s[len - show..])
}
