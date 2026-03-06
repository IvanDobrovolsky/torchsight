use anyhow::Result;
use std::collections::HashMap;
use std::fs;
use std::path::Path;

use crate::llm::OllamaClient;
use crate::report::{FileFinding, Severity};

pub async fn analyze_image(path: &Path, ollama: &OllamaClient) -> Result<Vec<FileFinding>> {
    let image_bytes = fs::read(path)?;

    let prompt = r#"You are a cybersecurity and content safety forensics analyst. Analyze this image thoroughly for TWO categories:

=== CATEGORY 1: SENSITIVE DATA EXTRACTION ===
Extract ALL sensitive information visible with exact values:
- "full_name", "first_name", "last_name": names of any person
- "date_of_birth": date of birth
- "address", "city", "state", "zip_code": address fields
- "ssn": social security number
- "phone": phone number
- "email": email address
- "credit_card": credit card number
- "bank_account": bank account number
- "driver_license": driver's license number
- "passport": passport number
- "id_number": any ID number
- "username", "password": credentials
- "api_key", "token": secrets
- "ip_address": IP addresses
- "document_type": type of document (e.g. "California Driver's License")
- "classification": confidentiality level
- "organization": company/org name
- "expiration_date": expiration dates
- Add any other relevant fields you can read

=== CATEGORY 2: CONTENT MODERATION ===
Flag ANY of the following:
- Hate symbols, Nazi imagery, extremist content, propaganda
- Historical figures associated with atrocities or hate movements
- Violence, gore, graphic content
- Profanity or slurs visible in text
- Sexually explicit or NSFW content
- Harassment, bullying, threatening content
- Self-harm or dangerous activity promotion
- Illegal activity depiction

For content moderation findings, use:
- category: "inappropriate"
- extracted_data should include: "content_type" (e.g. "hate imagery", "profanity", "violence", "nsfw"), "description_of_content" (what exactly is depicted), "risk_level" (low/medium/high)

=== CATEGORY 3: SAFE CONTENT CLASSIFICATION ===
If the image is safe and contains NO sensitive data and NO inappropriate content, still describe what the image contains:
- category: "safe"
- severity: "info"
- description: describe what the image shows
- extracted_data: {"content_type": "photo|screenshot|document|illustration|etc", "subject": "brief description of subject"}

Respond ONLY with this exact JSON format (no other text):
[{"category": "pii|credentials|financial|medical|confidential|inappropriate|safe", "description": "detailed description", "severity": "critical|warning|info", "extracted_data": {"field_name": "exact value"}}]

IMPORTANT:
- For sensitive data: put ACTUAL VALUES in extracted_data, not descriptions
- For inappropriate content: always severity "critical" or "warning"
- For safe content: severity "info"
- Every image MUST produce at least one finding (even if just "safe")"#;

    let response = ollama.analyze_image(prompt, &image_bytes).await?;
    parse_image_findings(&response)
}

fn parse_image_findings(response: &str) -> Result<Vec<FileFinding>> {
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
            evidence: "[image content]".to_string(),
            severity: match f.severity.as_str() {
                "critical" => Severity::Critical,
                "warning" => Severity::Warning,
                _ => Severity::Info,
            },
            source: "llm-vision".to_string(),
            extracted_data: f
                .extracted_data
                .into_iter()
                .filter(|(_, v)| !v.trim().is_empty())
                .collect(),
        })
        .collect())
}
