use anyhow::Result;
use std::collections::HashMap;
use std::fs;
use std::path::Path;

use super::ocr;
use crate::llm::OllamaClient;
use crate::report::{FileFinding, Severity};

pub async fn analyze_image(path: &Path, ollama: &OllamaClient) -> Result<Vec<FileFinding>> {
    let image_bytes = fs::read(path)?;
    let mut findings: Vec<FileFinding> = Vec::new();

    // ── Stage 1: OCR — extract all text from the image ──
    let ocr_text = match ocr::extract_text(path) {
        Ok(result) if !result.text.is_empty() => {
            Some((result.text, result.confidence))
        }
        _ => None,
    };

    // ── Stage 2: Vision — describe what the image shows ──
    let vision_prompt = r#"Look at this image carefully. Describe in detail:
1. What type of image is this? (photo, document, ID card, screenshot, medical record, etc.)
2. What is the main subject?
3. Describe any text you can see.
4. Describe any people, faces, symbols, logos, or markings.
5. Is there anything inappropriate, offensive, or hateful in this image?
Be specific and thorough."#;

    let vision_description = ollama.describe_image(vision_prompt, &image_bytes).await
        .unwrap_or_else(|_| "Could not analyze image visually.".to_string());

    // ── Stage 3: LLM deep analysis — combine OCR text + vision description ──
    let ocr_section = match &ocr_text {
        Some((text, confidence)) => format!(
            "=== TEXT EXTRACTED BY OCR (confidence: {:.0}%) ===\n{}\n=== END OCR TEXT ===",
            confidence, text
        ),
        None => "=== NO TEXT DETECTED BY OCR ===".to_string(),
    };

    let analysis_prompt = format!(
        r#"You are a cybersecurity forensics analyst performing a deep security assessment of an image file.

You have TWO sources of information about this image:

1. VISUAL DESCRIPTION (what the image looks like):
"{}"

2. OCR TEXT EXTRACTION (text read from the image):
{}

Based on BOTH sources, perform a complete analysis:

=== TASK 1: DOCUMENT CLASSIFICATION ===
What type of document or image is this? Examples:
- Government ID (driver's license, passport, national ID)
- Financial document (bank statement, credit card, check, invoice)
- Medical record (prescription, lab results, insurance card)
- Legal document (contract, NDA, court filing)
- Screenshot of sensitive system (terminal, admin panel, database)
- Personal photo, artwork, landscape, etc.
- Propaganda, hate imagery, extremist content

=== TASK 2: SENSITIVE DATA EXTRACTION ===
Extract EVERY piece of sensitive information. Use the OCR text to get exact values.
Return extracted_data with these fields (only include fields that are actually present):
- "document_type": what this document is
- "full_name": complete name of any person
- "first_name", "last_name": name parts
- "date_of_birth": DOB
- "address": street address
- "city", "state", "zip_code": address parts
- "ssn": social security number
- "phone": phone number
- "email": email address
- "credit_card": credit card number
- "bank_account": bank account number
- "driver_license": driver's license number
- "passport_number": passport number
- "id_number": any identification number
- "expiration_date": expiration date
- "issue_date": issue date
- "username", "password": credentials
- "api_key", "token", "secret": secrets
- "organization": company or agency name
- Add any other fields you find

=== TASK 3: CONTENT MODERATION ===
Flag if the image contains:
- Adolf Hitler, Nazi symbols, swastikas, SS insignia, fascist imagery
- Any dictator, war criminal, terrorist figure
- Violence, weapons, gore
- Sexually explicit content, nudity
- Profanity, hate speech, racial slurs
- Drug paraphernalia, illegal activity
If flagged: category = "inappropriate", severity = "critical"
Include in extracted_data: "content_type", "subject", "risk_level"

=== TASK 4: SAFETY VERDICT ===
If the image is completely safe (no sensitive data, no inappropriate content):
category = "safe", severity = "info"
Include in extracted_data: "content_type" (photo/illustration/etc), "subject" (what it shows)

Respond ONLY with a JSON array (no other text):
[{{"category": "pii|credentials|financial|medical|confidential|inappropriate|safe", "description": "detailed explanation of what was found and why it matters", "severity": "critical|warning|info", "extracted_data": {{"field": "exact value"}}}}]

CRITICAL RULES:
- Use the OCR text for exact values, not approximations
- Every image MUST produce at least one finding
- Multiple findings are OK (e.g., PII + inappropriate in same image)
- Put REAL VALUES in extracted_data, never "a name was visible""#,
        vision_description, ocr_section
    );

    let response = ollama.generate(&analysis_prompt).await?;

    // Parse LLM response
    let llm_findings = parse_findings(&response)?;
    findings.extend(llm_findings);

    // If LLM returned nothing, add a basic finding from what we have
    if findings.is_empty() {
        if let Some((text, _)) = &ocr_text {
            findings.push(FileFinding {
                category: "unclassified".to_string(),
                description: "Image contains text but could not be fully analyzed by LLM.".to_string(),
                evidence: text.chars().take(200).collect(),
                severity: Severity::Warning,
                source: "ocr".to_string(),
                extracted_data: {
                    let mut m = HashMap::new();
                    m.insert("ocr_text".to_string(), text.clone());
                    m
                },
            });
        } else {
            findings.push(FileFinding {
                category: "safe".to_string(),
                description: "No text or sensitive content detected.".to_string(),
                evidence: String::new(),
                severity: Severity::Info,
                source: "llm-vision".to_string(),
                extracted_data: HashMap::new(),
            });
        }
    }

    Ok(findings)
}

fn parse_findings(response: &str) -> Result<Vec<FileFinding>> {
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
            source: "llm-vision+ocr".to_string(),
            extracted_data: f
                .extracted_data
                .into_iter()
                .filter(|(_, v)| !v.trim().is_empty())
                .collect(),
        })
        .collect())
}
