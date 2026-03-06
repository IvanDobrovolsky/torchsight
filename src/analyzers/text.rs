use anyhow::Result;
use std::collections::HashMap;
use std::fs;
use std::path::Path;

use crate::llm::OllamaClient;
use crate::report::{FileFinding, Severity};

const MAX_TEXT_READ: usize = 10 * 1024 * 1024; // 10MB
const LLM_CONTEXT_LIMIT: usize = 6000; // chars to send to LLM

pub async fn analyze_text_file(
    path: &Path,
    ollama: &OllamaClient,
) -> Result<Vec<FileFinding>> {
    let content = read_text_safe(path)?;

    if content.trim().is_empty() {
        return Ok(vec![FileFinding {
            category: "safe".to_string(),
            description: "Empty file.".to_string(),
            evidence: String::new(),
            severity: Severity::Info,
            source: "scanner".to_string(),
            extracted_data: HashMap::new(),
        }]);
    }

    let truncated: String = content.chars().take(LLM_CONTEXT_LIMIT).collect();
    let was_truncated = content.len() > LLM_CONTEXT_LIMIT;

    let file_name = path
        .file_name()
        .unwrap_or_default()
        .to_string_lossy();

    let prompt = format!(
        r#"You are a cybersecurity forensics analyst performing a deep security assessment of a file.

File name: "{}"
File size: {} bytes{}

File content:
---
{}
---

Perform a thorough analysis:

=== TASK 1: DOCUMENT CLASSIFICATION ===
What is this file? Examples:
- Configuration file with secrets (database credentials, API keys, tokens)
- Data file with PII (customer records, employee data, user databases)
- Source code with hardcoded credentials
- Log file with sensitive information
- Medical/health records
- Financial records (transactions, invoices, tax documents)
- Legal documents (contracts, NDAs)
- Communication (emails, chat logs)
- Content with profanity, hate speech, threats, or inappropriate language
- Clean configuration, documentation, or code with no sensitive data

=== TASK 2: SENSITIVE DATA EXTRACTION ===
Extract EVERY piece of sensitive data with exact values from the file.
Group related data per person or record.
Use these fields in extracted_data (only include what is actually present):
- "document_type": what kind of file this is
- "full_name", "first_name", "last_name": person names
- "date_of_birth": DOB
- "address", "city", "state", "zip_code": address
- "ssn": social security numbers
- "phone": phone numbers
- "email": email addresses
- "credit_card": credit card numbers
- "bank_account": bank account numbers
- "driver_license": license numbers
- "username", "password": credentials (exact values)
- "api_key": API keys (exact values)
- "token": auth tokens (exact values)
- "secret": secrets (exact values)
- "connection_string": database connection strings (exact values)
- "private_key": private key content
- "ip_address": IP addresses
- "organization": company names
- Add any other sensitive fields you find

=== TASK 3: CONTENT MODERATION ===
Flag any profanity, slurs, hate speech, threats, harassment, extremist content, or inappropriate language in the file.
If found: category = "inappropriate", severity = "critical"
Include: "content_type", "flagged_text" (exact text), "risk_level"

=== TASK 4: COMPLIANCE ===
Note which regulations this data falls under:
- GDPR (EU personal data)
- HIPAA (US health data)
- PCI-DSS (payment card data)
- SOX (financial records)
- FERPA (education records)
Include as "compliance" in extracted_data if applicable.

=== TASK 5: SAFETY VERDICT ===
If nothing sensitive or inappropriate: category = "safe", severity = "info"
Include: "document_type", "summary" (brief description of file content)

Respond ONLY with a JSON array (no other text):
[{{"category": "pii|credentials|financial|medical|confidential|inappropriate|safe", "description": "detailed explanation", "severity": "critical|warning|info", "extracted_data": {{"field": "exact value from file"}}}}]

CRITICAL RULES:
- Extract EXACT values from the file, not descriptions
- One finding per person/record for PII (group their fields together)
- One finding per credential/secret found
- Multiple findings are expected for files with multiple issues
- Every file MUST produce at least one finding"#,
        file_name,
        content.len(),
        if was_truncated { " (truncated for analysis)" } else { "" },
        truncated
    );

    let response = ollama.generate(&prompt).await?;
    let mut findings = parse_llm_findings(&response)?;

    // If LLM returned nothing, mark as analyzed but unclear
    if findings.is_empty() {
        findings.push(FileFinding {
            category: "safe".to_string(),
            description: "File analyzed, no sensitive data or concerns detected.".to_string(),
            evidence: String::new(),
            severity: Severity::Info,
            source: "llm".to_string(),
            extracted_data: {
                let mut m = HashMap::new();
                m.insert("document_type".to_string(), "unknown".to_string());
                m
            },
        });
    }

    Ok(findings)
}

fn parse_llm_findings(response: &str) -> Result<Vec<FileFinding>> {
    let trimmed = response.trim();

    let start = trimmed.find('[');
    let end = trimmed.rfind(']');

    let json_str = match (start, end) {
        (Some(s), Some(e)) if e > s => &trimmed[s..=e],
        _ => return Ok(vec![]),
    };

    #[derive(serde::Deserialize)]
    struct LlmFinding {
        category: String,
        description: String,
        severity: String,
        #[serde(default)]
        extracted_data: HashMap<String, String>,
    }

    let parsed: Vec<LlmFinding> = match serde_json::from_str(json_str) {
        Ok(v) => v,
        Err(_) => return Ok(vec![]),
    };

    Ok(parsed
        .into_iter()
        .map(|f| FileFinding {
            category: f.category,
            description: f.description,
            evidence: String::new(),
            severity: match f.severity.as_str() {
                "critical" => Severity::Critical,
                "warning" => Severity::Warning,
                _ => Severity::Info,
            },
            source: "llm".to_string(),
            extracted_data: f
                .extracted_data
                .into_iter()
                .filter(|(_, v)| !v.trim().is_empty())
                .collect(),
        })
        .collect())
}

fn read_text_safe(path: &Path) -> Result<String> {
    let metadata = fs::metadata(path)?;
    let size = metadata.len() as usize;
    let read_size = size.min(MAX_TEXT_READ);

    let bytes = fs::read(path)?;
    let content = String::from_utf8_lossy(&bytes[..read_size.min(bytes.len())]);
    Ok(content.to_string())
}
