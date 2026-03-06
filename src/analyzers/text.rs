use anyhow::Result;
use std::collections::HashMap;
use std::fs;
use std::path::Path;

use super::patterns;
use crate::llm::OllamaClient;
use crate::report::{FileFinding, Severity};

const MAX_TEXT_READ: usize = 10 * 1024 * 1024; // 10MB for pattern scan
const LLM_CONTEXT_LIMIT: usize = 4000; // chars to send to LLM

pub fn analyze_text_file(path: &Path) -> Result<Vec<FileFinding>> {
    let content = read_text_safe(path)?;
    let pattern_matches = patterns::scan_text(&content);

    let findings: Vec<FileFinding> = pattern_matches
        .into_iter()
        .map(|m| FileFinding {
            category: m.category,
            description: m.description,
            evidence: m.matched_text,
            severity: m.severity,
            source: "pattern".to_string(),
            extracted_data: HashMap::new(),
        })
        .collect();

    Ok(findings)
}

pub async fn analyze_text_with_llm(
    path: &Path,
    ollama: &OllamaClient,
) -> Result<Vec<FileFinding>> {
    let content = read_text_safe(path)?;
    let truncated: String = content.chars().take(LLM_CONTEXT_LIMIT).collect();

    let prompt = format!(
        r#"You are a cybersecurity and content safety forensics analyst. Analyze this file for THREE categories:

=== CATEGORY 1: SENSITIVE DATA ===
Extract ALL sensitive data with exact values into "extracted_data":
- "full_name", "first_name", "last_name": names
- "date_of_birth": DOB
- "address", "city", "state", "zip_code": address parts
- "ssn": social security number
- "phone": phone number
- "email": email address
- "credit_card": credit card number
- "bank_account": bank account
- "driver_license": license number
- "username", "password": credentials
- "api_key", "token", "secret": secrets/keys
- "connection_string": database connection strings
- "document_type": type of document
- Add any other fields you find

=== CATEGORY 2: CONTENT MODERATION ===
Flag any profanity, slurs, hate speech, threats, harassment, extremist content, or inappropriate language.
Use category "inappropriate" with extracted_data: {{"content_type": "profanity|hate_speech|threats|harassment", "flagged_text": "the exact problematic text", "risk_level": "low|medium|high"}}

=== CATEGORY 3: SAFE CONTENT ===
If nothing sensitive or inappropriate is found, return:
category "safe", severity "info", description of what the file contains.
extracted_data: {{"document_type": "config|code|readme|data|etc", "summary": "brief summary"}}

File content:
---
{}
---

Respond ONLY with this exact JSON (no other text):
[{{"category": "pii|credentials|financial|medical|confidential|inappropriate|safe", "description": "detailed description", "severity": "critical|warning|info", "extracted_data": {{"field": "value"}}}}]

IMPORTANT: Put ACTUAL VALUES in extracted_data. Group related data per person/record. Every file MUST produce at least one finding."#,
        truncated
    );

    let response = ollama.generate(&prompt).await?;
    parse_llm_findings(&response)
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
