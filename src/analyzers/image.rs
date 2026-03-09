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
    let vision_prompt = r#"What is this image? Answer briefly:
1. Type: photo, screenshot, scan, document, ID card, or other
2. Subject: what it shows in one sentence
3. Any visible text, numbers, or codes? If yes, list them. If no, say "none".
Be concise."#;

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
        r#"Analyze this image for security-relevant content.

VISUAL DESCRIPTION: "{}"

{}

RULES:
- If the image is just a photo (person, animal, landscape, object) with NO sensitive text or data visible, classify as safe.
- Only flag content if there is ACTUAL sensitive data: names+SSN, passwords, API keys, medical records, classified markings, malicious code, etc.
- Do NOT flag normal photos as PII just because a person or animal is visible.
- Do NOT speculate about metadata or EXIF data — only flag what is actually visible.
- Use OCR text for exact values when available.

Examine this content for data leakage, threats, and compliance issues."#,
        vision_description, ocr_section
    );

    let is_beam = ollama.text_model().contains("beam");
    let response = if is_beam {
        ollama.chat(&analysis_prompt).await?
    } else {
        ollama.generate(&analysis_prompt).await?
    };

    // Parse LLM response
    let llm_findings = if is_beam {
        super::text::parse_beam_findings_public(&response)?
    } else {
        parse_findings(&response)?
    };
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
