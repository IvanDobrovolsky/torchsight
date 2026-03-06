use anyhow::Result;
use std::collections::HashMap;
use std::fs;
use std::path::Path;

use crate::llm::OllamaClient;
use crate::report::{FileFinding, Severity};

pub async fn analyze_image(path: &Path, ollama: &OllamaClient) -> Result<Vec<FileFinding>> {
    let image_bytes = fs::read(path)?;

    // Step 1: Describe what's in the image first
    let describe_prompt = r#"Describe this image in detail. What do you see? Be specific about:
1. Is this a document, ID card, photo of a person, screenshot, or something else?
2. If there is text visible, what does it say?
3. Who or what is depicted?
4. Are there any logos, symbols, or identifying marks?"#;

    let description = ollama.analyze_image(describe_prompt, &image_bytes).await?;

    // Step 2: Analyze the description for security/content concerns
    let analyze_prompt = format!(
        r#"You are a cybersecurity and content safety analyst. Based on this image description, classify the image and extract data.

Image description:
"{}"

Answer these questions and respond with JSON:

1. SENSITIVE DATA: Does it contain personal information (names, SSN, addresses, phone numbers, emails, credit cards, driver's license numbers, passwords, API keys)? If yes, extract EVERY field with its EXACT value.

2. INAPPROPRIATE CONTENT: Does it depict any of these?
   - Adolf Hitler, Nazi symbols, swastikas, SS imagery, fascist propaganda
   - Any dictator, war criminal, or hate figure
   - Violence, gore, weapons used threateningly
   - Profanity, slurs, hate speech
   - Sexually explicit content, nudity
   - Drug use, illegal activity
   If yes, category MUST be "inappropriate" and severity MUST be "critical".

3. SAFE: If none of the above, it is safe.

Respond ONLY with JSON array (no other text):
[{{"category": "pii|credentials|financial|inappropriate|safe", "description": "what the image shows and why it is flagged or safe", "severity": "critical|warning|info", "extracted_data": {{"field": "value"}}}}]

Rules:
- If document/ID: category "pii", severity "critical", extract ALL visible fields (full_name, address, driver_license, date_of_birth, etc)
- If hate/offensive content: category "inappropriate", severity "critical", extracted_data must include "content_type" and "subject"
- If safe (like a pet photo, landscape, artwork): category "safe", severity "info", extracted_data: {{"content_type": "photo", "subject": "brief description"}}
- Put EXACT values, not descriptions like "a name is visible""#,
        description
    );

    let response = ollama.generate(&analyze_prompt).await?;
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
