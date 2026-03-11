use anyhow::Result;
use once_cell::sync::Lazy;
use regex::Regex;
use std::collections::HashMap;
use std::fs;
use std::path::Path;
use std::process::Command;

use crate::llm::OllamaClient;
use crate::report::{FileFinding, Severity};

const MAX_TEXT_READ: usize = 10 * 1024 * 1024; // 10MB
const LLM_CONTEXT_LIMIT: usize = 6000; // chars to send to LLM

pub async fn analyze_text_file(
    path: &Path,
    ollama: &OllamaClient,
) -> Result<Vec<FileFinding>> {
    let content = if is_pdf(path) {
        extract_pdf_text(path)?
    } else {
        read_text_safe(path)?
    };

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

    let is_beam = ollama.text_model().contains("beam");
    let response = if is_beam {
        let message = format!(
            "Analyze the following text for security threats, sensitive data, and policy violations.\n\n{}",
            truncated
        );
        ollama.chat(&message).await?
    } else {
        let was_truncated = content.len() > LLM_CONTEXT_LIMIT;
        let file_name = path
            .file_name()
            .unwrap_or_default()
            .to_string_lossy();
        let prompt = build_detailed_prompt(&file_name, content.len(), was_truncated, &truncated);
        ollama.generate(&prompt).await?
    };

    let mut findings = if is_beam {
        parse_beam_findings(&response)?
    } else {
        parse_llm_findings(&response)?
    };

    // Enrich findings with file context
    let file_name = path.file_name().unwrap_or_default().to_string_lossy();
    let content_preview: String = truncated.chars().take(150).collect();

    for finding in &mut findings {
        finding.extracted_data.insert(
            "source_file".to_string(),
            file_name.to_string(),
        );
        // Add a content snippet as evidence if empty
        if finding.evidence.is_empty() && finding.category != "safe" {
            finding.evidence = content_preview.clone();
        }
    }

    // Regex safety net: catch high-confidence attack patterns the model missed
    let regex_extra = regex_safety_net(&content, &findings);
    findings.extend(regex_extra);

    // If LLM returned nothing, mark as analyzed but unclear
    if findings.is_empty() {
        findings.push(FileFinding {
            category: "safe".to_string(),
            description: format!("File analyzed ({}), no sensitive data or concerns detected.", file_name),
            evidence: String::new(),
            severity: Severity::Info,
            source: "llm".to_string(),
            extracted_data: {
                let mut m = HashMap::new();
                m.insert("document_type".to_string(), "unknown".to_string());
                m.insert("source_file".to_string(), file_name.to_string());
                m
            },
        });
    }

    Ok(findings)
}

fn build_detailed_prompt(file_name: &str, content_len: usize, was_truncated: bool, truncated: &str) -> String {
    format!(
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
- Military/defense documents (OPORDs, FRAGOs, SITREPs, intelligence reports, weapons specs)
- Nuclear-related information (RD, FRD, CNWDI markings)
- Geospatial/targeting data (MGRS coordinates, target packages)
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
- "classification_level": security classification (TOP SECRET, SECRET, CONFIDENTIAL, CUI)
- "codeword": SCI codewords or compartments (e.g., //SCI, //NOFORN, //REL TO)
- "operation_name": military operation names
- "unit": military unit designations
- "coordinates": MGRS or lat/lon coordinates
- "dtg": date-time group (military format)
- "system_name": weapons system names
- "report_type": intelligence report type (HUMINT, SIGINT, IMINT, OSINT)
- Add any other sensitive fields you find

=== TASK 3: SECURITY THREATS ===
Detect any malicious or dangerous content in this file:
- Embedded scripts (JavaScript in HTML/SVG/JSON, VBA macros, PowerShell, shell scripts)
- Injection payloads (SQL injection, XSS vectors, command injection, LDAP injection)
- Server-Side Template Injection (SSTI) — Jinja2 {{}}, Twig, Freemarker, Velocity, Mako, EJS
- XML External Entity (XXE) — <!DOCTYPE> with ENTITY declarations, external DTD references
- Malicious code (reverse shells, C2 beacons, backdoors, web shells, keyloggers)
- Obfuscated payloads (base64-encoded commands, hex-encoded shellcode, eval/exec with encoded strings)
- Suspicious function calls (eval(), exec(), system(), os.popen(), subprocess, Runtime.exec())
- Deserialization attacks (pickle.loads, yaml.load without SafeLoader, ObjectInputStream, unserialize, Marshal.load)
- Path traversal (../../etc/passwd, directory traversal attempts)
- Phishing indicators (credential harvesting forms, fake login pages, social engineering scripts)
- Exploit code (buffer overflow, format string, use-after-free, ROP chains)
- LLM Prompt Injection (direct injection, indirect injection via data, jailbreak attempts, system prompt extraction)
- Supply Chain Attacks (dependency confusion, typosquatted package names, malicious install scripts in package.json/setup.py/Cargo.toml, lockfile poisoning)
- SSRF payloads (requests to 169.254.169.254, cloud metadata endpoints, internal service URLs, DNS rebinding)
- ReDoS patterns (catastrophic backtracking regexes, nested quantifiers like (a+)+, (a|a)*b)
- Prototype Pollution (JavaScript __proto__, constructor.prototype manipulation)
- Steganography indicators (unusual file padding, embedded data after EOF markers, LSB encoding patterns)
- Cloud/Infrastructure secrets (AWS credentials in env vars, terraform state with secrets, .kube/config, docker-compose secrets)
- CI/CD pipeline leaks (GitHub Actions with hardcoded secrets, Jenkins credentials, GitLab CI tokens in .gitlab-ci.yml)
- Container secrets (Dockerfile ENV with passwords, K8s Secret manifests in plaintext, Helm values with credentials)

=== TASK 3b: MILITARY / DEFENSE / CLASSIFIED ===
Detect military or classified content:
- Classification markings (TOP SECRET, SECRET, CONFIDENTIAL, UNCLASSIFIED, CUI, FOUO)
- SCI/SAP compartments (//SCI, //NOFORN, //REL TO, //ORCON, //PROPIN)
- Military communications (OPORD, FRAGO, SITREP, INTREP, SALUTE reports)
- Date-Time Groups (e.g., 061430ZMAR2026)
- MGRS coordinates (e.g., 38SMB4488), military grid references
- Unit designations (e.g., 1st BCT, 3/75 Ranger, JSOC, SOCOM)
- Weapons systems specifications or technical data
- Intelligence report formats (HUMINT, SIGINT, IMINT, MASINT, OSINT)
- Source reliability ratings (A-F) and information credibility (1-6)
- Nuclear information markers (RESTRICTED DATA, FORMERLY RESTRICTED DATA, CNWDI, NNPI)
- NATO classification markings (NATO CONFIDENTIAL, COSMIC TOP SECRET)
- Defense contractor sensitive information or export-controlled data
If found: category = "confidential", severity = "critical"
Include in extracted_data: "classification_level", "codeword", "operation_name", "unit", "coordinates", "report_type", "system_name"
Include in compliance: "ITAR", "EO-13526", "NIST-800-53" as applicable

For malicious/threat findings from TASK 3:
Include in extracted_data: "threat_type", "payload" (exact malicious content), "attack_vector", "risk_level"

=== TASK 4: FILE METADATA CHECK ===
Check for sensitive metadata leaks:
- EXIF data with GPS coordinates, device info, or user identity
- PDF properties with author names, organization, software versions
- Office document metadata (author, company, revision history)
- Git conflict markers or merge artifacts with usernames
If found: category = "pii", include "metadata_type", "gps_coordinates", "device_info", "author" in extracted_data

=== TASK 5: COMPLIANCE ===
Note which regulations this data falls under:
- GDPR (EU personal data)
- HIPAA (US health data)
- PCI-DSS (payment card data)
- SOX (financial records)
- FERPA (education records)
- CCPA (California consumer data)
- ITAR (military/defense data)
- EAR (dual-use technology)
Include as "compliance" in extracted_data if applicable.

=== TASK 6: SAFETY VERDICT ===
If nothing sensitive or malicious found: category = "safe", severity = "info"
Include: "document_type", "summary" (brief description of file content)

Respond ONLY with a JSON array (no other text):
[{{"category": "pii|credentials|financial|medical|confidential|malicious|safe", "description": "detailed explanation", "severity": "critical|warning|info", "extracted_data": {{"field": "exact value from file"}}}}]

CRITICAL RULES:
- Extract EXACT values from the file, not descriptions
- One finding per person/record for PII (group their fields together)
- One finding per credential/secret found
- Multiple findings are expected for files with multiple issues
- Every file MUST produce at least one finding"#,
        file_name,
        content_len,
        if was_truncated { " (truncated for analysis)" } else { "" },
        truncated
    )
}

/// Public wrapper for image analyzer to reuse beam parsing
pub fn parse_beam_findings_public(response: &str) -> Result<Vec<FileFinding>> {
    parse_beam_findings(response)
}

/// Derive the correct category from the subcategory prefix when they mismatch.
/// Only overrides "confidential" — the model's main over-predicted catch-all.
/// E.g., subcategory "pii.identity" with category "confidential" → category "pii".
fn resolve_category(category: &str, subcategory: &str) -> String {
    const KNOWN_CATEGORIES: &[&str] = &[
        "pii", "credentials", "financial", "medical", "confidential", "malicious", "safe",
    ];

    if category == "confidential" {
        if let Some(prefix) = subcategory.split('.').next() {
            if KNOWN_CATEGORIES.contains(&prefix) && prefix != "confidential" {
                return prefix.to_string();
            }
        }
    }

    category.to_string()
}

/// Try to repair truncated JSON arrays by finding the last complete object.
/// The beam model often generates repetitive filler that hits the token limit,
/// truncating the JSON mid-object. This recovers what we can.
fn try_repair_json_array(partial: &str) -> Option<String> {
    // Find the last complete '}' that could end a JSON object
    let mut depth = 0i32;
    let mut last_complete_obj_end = None;
    let mut in_string = false;
    let mut escape_next = false;

    for (i, ch) in partial.char_indices() {
        if escape_next {
            escape_next = false;
            continue;
        }
        match ch {
            '\\' if in_string => escape_next = true,
            '"' => in_string = !in_string,
            '{' if !in_string => depth += 1,
            '}' if !in_string => {
                depth -= 1;
                if depth == 0 {
                    last_complete_obj_end = Some(i);
                }
            }
            _ => {}
        }
    }

    if let Some(end) = last_complete_obj_end {
        let repaired = format!("{}]", &partial[..=end]);
        return Some(repaired);
    }

    None
}

/// Parse beam model output: multiple separate JSON arrays with text between them.
/// Handles truncated JSON (from token limit) and fixes category-subcategory mismatches.
fn parse_beam_findings(response: &str) -> Result<Vec<FileFinding>> {
    #[derive(serde::Deserialize)]
    struct BeamFinding {
        category: String,
        subcategory: Option<String>,
        severity: Option<String>,
        explanation: Option<String>,
    }

    let mut findings = Vec::new();
    let mut safe_findings = Vec::new();
    let mut seen = std::collections::HashSet::new();
    let mut pos = 0;
    let bytes = response.as_bytes();

    while pos < bytes.len() {
        // Find next '[' start
        let start = match response[pos..].find('[') {
            Some(i) => pos + i,
            None => break,
        };

        // Try to find matching ']'
        let (json_str, next_pos) = match response[start..].find(']') {
            Some(i) => {
                let end = start + i + 1;
                (response[start..end].to_string(), end)
            }
            None => {
                // No closing ']' — try to repair truncated JSON
                match try_repair_json_array(&response[start..]) {
                    Some(repaired) => {
                        let next = bytes.len(); // consumed everything
                        (repaired, next)
                    }
                    None => break,
                }
            }
        };

        if let Ok(parsed) = serde_json::from_str::<Vec<BeamFinding>>(&json_str) {
            for f in parsed {
                let subcategory = f.subcategory.unwrap_or_default();
                let category = resolve_category(&f.category, &subcategory);
                let key = format!("{}:{}", category, subcategory);
                if seen.contains(&key) {
                    continue;
                }
                seen.insert(key);

                let severity_str = f.severity.as_deref().unwrap_or("medium");
                let severity = match severity_str {
                    "critical" => Severity::Critical,
                    "high" => Severity::High,
                    "medium" => Severity::Medium,
                    "low" => Severity::Low,
                    "info" => Severity::Info,
                    // Legacy fallbacks
                    "warning" => Severity::Medium,
                    _ => Severity::Medium,
                };

                let description = f.explanation.unwrap_or_else(|| {
                    format!("Detected {} content", if subcategory.is_empty() { &category } else { &subcategory })
                });

                if category == "safe" {
                    safe_findings.push(FileFinding {
                        category,
                        description,
                        evidence: subcategory,
                        severity,
                        source: "beam".to_string(),
                        extracted_data: HashMap::new(),
                    });
                } else {
                    findings.push(FileFinding {
                        category,
                        description,
                        evidence: subcategory,
                        severity,
                        source: "beam".to_string(),
                        extracted_data: HashMap::new(),
                    });
                }
            }
        }

        pos = next_pos;
    }

    // If no non-safe findings, use beam's safe findings (with its explanation)
    if findings.is_empty() {
        if !safe_findings.is_empty() {
            findings = safe_findings;
        } else {
            findings.push(FileFinding {
                category: "safe".to_string(),
                description: "No security issues detected.".to_string(),
                evidence: String::new(),
                severity: Severity::Info,
                source: "beam".to_string(),
                extracted_data: HashMap::new(),
            });
        }
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
                "high" => Severity::High,
                "medium" | "warning" => Severity::Medium,
                "low" => Severity::Low,
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

// ---------------------------------------------------------------------------
// Regex safety net — catches high-confidence attack patterns the LLM misses
// ---------------------------------------------------------------------------

struct SafetyPattern {
    regex: &'static Lazy<Regex>,
    subcategory: &'static str,
    description: &'static str,
    severity: Severity,
}

macro_rules! lazy_re {
    ($name:ident, $pat:expr) => {
        static $name: Lazy<Regex> = Lazy::new(|| Regex::new($pat).expect(concat!("bad regex: ", $pat)));
    };
}

// --- A. SSTI ---
lazy_re!(RE_SSTI_CLASS, r"\{\{[^}]*__class__");
lazy_re!(RE_SSTI_MRO, r"\{\{[^}]*__mro__");
lazy_re!(RE_SSTI_SUBCLASSES, r"\{\{[^}]*__subclasses__");
lazy_re!(RE_SSTI_CONFIG, r"\{\{[^}]*config\s*\.");
lazy_re!(RE_SSTI_REQUEST, r"\{\{[^}]*request\s*\.");
lazy_re!(RE_SSTI_JAVA_RUNTIME, r"\$\{[^}]*Runtime\s*\.");
lazy_re!(RE_SSTI_JAVA_GETRUNTIME, r"\$\{[^}]*getRuntime");
lazy_re!(RE_SSTI_VELOCITY, r"#set\s*\(\s*\$[^)]*class\s*\.");

// --- B. XXE ---
lazy_re!(RE_XXE_DOCTYPE, r"(?s)<!DOCTYPE[^>]*\[.*<!ENTITY");
lazy_re!(RE_XXE_SYSTEM, r#"<!ENTITY[^>]*SYSTEM\s*["']"#);
lazy_re!(RE_XXE_PUBLIC, r#"<!ENTITY[^>]*PUBLIC\s*["']"#);

// --- C. Deserialization ---
lazy_re!(RE_PICKLE, r"pickle\.loads\s*\(");
lazy_re!(RE_YAML_UNSAFE, r"yaml\.load\s*\([^)]*\)");
lazy_re!(RE_YAML_SAFE, r"Loader\s*=\s*SafeLoader");
lazy_re!(RE_OBJINPUTSTREAM, r"ObjectInputStream");
lazy_re!(RE_UNSERIALIZE, r"unserialize\s*\(");
lazy_re!(RE_MARSHAL_LOAD, r"Marshal\.load\s*\(");
lazy_re!(RE_BINARYFORMATTER, r"BinaryFormatter\.Deserialize");

// --- D. Shell / RCE ---
lazy_re!(RE_EVAL_ATOB, r"\beval\s*\(\s*atob\b");
lazy_re!(RE_EXEC_COMPILE, r"\bexec\s*\(\s*compile\b");
lazy_re!(RE_IMPORT_OS, r#"\b__import__\s*\(\s*['"]os['"]\s*\)"#);
lazy_re!(RE_REVSHELL_NC, r"\b(nc|ncat|netcat)\s+.*-e\s+/bin/(sh|bash)");
lazy_re!(RE_REVSHELL_DEVTCP, r"/dev/tcp/");

// --- E. SSRF ---
lazy_re!(RE_SSRF_AWS, r"169\.254\.169\.254");
lazy_re!(RE_SSRF_GCP, r"metadata\.google\.internal");
lazy_re!(RE_SSRF_ALIBABA, r"100\.100\.100\.200");

// --- F. Supply chain ---
lazy_re!(RE_NPM_CURL, r#""(preinstall|postinstall|preuninstall)":\s*"[^"]*curl\s"#);
lazy_re!(RE_NPM_WGET, r#""(preinstall|postinstall)":\s*"[^"]*wget\s"#);
lazy_re!(RE_SETUP_PY, r"(?s)cmdclass.*install.*os\.system");

// --- G. Prompt injection ---
lazy_re!(RE_PROMPT_IGNORE, r"(?i)ignore\s+(all\s+)?previous\s+instructions");
lazy_re!(RE_PROMPT_DAN, r"(?i)you\s+are\s+now\s+(DAN|an?\s+unrestricted)");
lazy_re!(RE_PROMPT_OVERRIDE, r"(?i)system:\s*override");

fn regex_safety_net(content: &str, existing_findings: &[FileFinding]) -> Vec<FileFinding> {
    // If the model already detected "malicious", don't add duplicates
    let model_found_malicious = existing_findings
        .iter()
        .any(|f| f.category == "malicious");

    if model_found_malicious {
        return Vec::new();
    }

    let patterns: &[SafetyPattern] = &[
        // A. SSTI
        SafetyPattern { regex: &RE_SSTI_CLASS, subcategory: "malicious.injection", description: "Jinja2 SSTI: __class__ access in template expression", severity: Severity::Critical },
        SafetyPattern { regex: &RE_SSTI_MRO, subcategory: "malicious.injection", description: "Jinja2 SSTI: __mro__ traversal in template expression", severity: Severity::Critical },
        SafetyPattern { regex: &RE_SSTI_SUBCLASSES, subcategory: "malicious.injection", description: "Jinja2 SSTI: __subclasses__ enumeration in template expression", severity: Severity::Critical },
        SafetyPattern { regex: &RE_SSTI_CONFIG, subcategory: "malicious.injection", description: "Jinja2 SSTI: config object access in template expression", severity: Severity::High },
        SafetyPattern { regex: &RE_SSTI_REQUEST, subcategory: "malicious.injection", description: "Jinja2 SSTI: request object access in template expression", severity: Severity::High },
        SafetyPattern { regex: &RE_SSTI_JAVA_RUNTIME, subcategory: "malicious.injection", description: "Java SSTI: Runtime class access in expression", severity: Severity::Critical },
        SafetyPattern { regex: &RE_SSTI_JAVA_GETRUNTIME, subcategory: "malicious.injection", description: "Java SSTI: getRuntime() call in expression", severity: Severity::Critical },
        SafetyPattern { regex: &RE_SSTI_VELOCITY, subcategory: "malicious.injection", description: "Velocity SSTI: class access via #set directive", severity: Severity::Critical },

        // B. XXE
        SafetyPattern { regex: &RE_XXE_DOCTYPE, subcategory: "malicious.injection", description: "XXE: DOCTYPE with ENTITY declaration", severity: Severity::Critical },
        SafetyPattern { regex: &RE_XXE_SYSTEM, subcategory: "malicious.injection", description: "XXE: external SYSTEM entity declaration", severity: Severity::Critical },
        SafetyPattern { regex: &RE_XXE_PUBLIC, subcategory: "malicious.injection", description: "XXE: PUBLIC entity declaration", severity: Severity::High },

        // C. Deserialization
        SafetyPattern { regex: &RE_PICKLE, subcategory: "malicious.exploit", description: "Unsafe deserialization: pickle.loads() can execute arbitrary code", severity: Severity::Critical },
        // yaml.load is handled separately below
        SafetyPattern { regex: &RE_OBJINPUTSTREAM, subcategory: "malicious.exploit", description: "Java deserialization: ObjectInputStream can execute arbitrary code", severity: Severity::High },
        SafetyPattern { regex: &RE_UNSERIALIZE, subcategory: "malicious.exploit", description: "PHP deserialization: unserialize() can trigger object injection", severity: Severity::Critical },
        SafetyPattern { regex: &RE_MARSHAL_LOAD, subcategory: "malicious.exploit", description: "Ruby deserialization: Marshal.load() can execute arbitrary code", severity: Severity::Critical },
        SafetyPattern { regex: &RE_BINARYFORMATTER, subcategory: "malicious.exploit", description: ".NET deserialization: BinaryFormatter.Deserialize can execute arbitrary code", severity: Severity::Critical },

        // D. Shell / RCE
        SafetyPattern { regex: &RE_EVAL_ATOB, subcategory: "malicious.shell", description: "Obfuscated code execution: eval(atob()) decodes and runs hidden payload", severity: Severity::Critical },
        SafetyPattern { regex: &RE_EXEC_COMPILE, subcategory: "malicious.shell", description: "Dynamic code execution: exec(compile()) runs dynamically constructed code", severity: Severity::Critical },
        SafetyPattern { regex: &RE_IMPORT_OS, subcategory: "malicious.shell", description: "Suspicious OS import: __import__('os') used to access system commands", severity: Severity::Critical },
        SafetyPattern { regex: &RE_REVSHELL_NC, subcategory: "malicious.shell", description: "Reverse shell: netcat with -e flag piping to shell", severity: Severity::Critical },
        SafetyPattern { regex: &RE_REVSHELL_DEVTCP, subcategory: "malicious.shell", description: "Reverse shell: /dev/tcp used for network connection", severity: Severity::Critical },

        // E. SSRF
        SafetyPattern { regex: &RE_SSRF_AWS, subcategory: "malicious.ssrf", description: "SSRF: AWS metadata endpoint (169.254.169.254)", severity: Severity::High },
        SafetyPattern { regex: &RE_SSRF_GCP, subcategory: "malicious.ssrf", description: "SSRF: GCP metadata endpoint (metadata.google.internal)", severity: Severity::High },
        SafetyPattern { regex: &RE_SSRF_ALIBABA, subcategory: "malicious.ssrf", description: "SSRF: Alibaba Cloud metadata endpoint (100.100.100.200)", severity: Severity::High },

        // F. Supply chain
        SafetyPattern { regex: &RE_NPM_CURL, subcategory: "malicious.exploit", description: "Supply chain attack: npm lifecycle hook executes curl", severity: Severity::Critical },
        SafetyPattern { regex: &RE_NPM_WGET, subcategory: "malicious.exploit", description: "Supply chain attack: npm lifecycle hook executes wget", severity: Severity::Critical },
        SafetyPattern { regex: &RE_SETUP_PY, subcategory: "malicious.exploit", description: "Supply chain attack: setup.py cmdclass runs os.system()", severity: Severity::Critical },

        // G. Prompt injection
        SafetyPattern { regex: &RE_PROMPT_IGNORE, subcategory: "malicious.prompt_injection", description: "Prompt injection: attempt to override previous instructions", severity: Severity::High },
        SafetyPattern { regex: &RE_PROMPT_DAN, subcategory: "malicious.prompt_injection", description: "Prompt injection: jailbreak attempt (DAN / unrestricted mode)", severity: Severity::High },
        SafetyPattern { regex: &RE_PROMPT_OVERRIDE, subcategory: "malicious.prompt_injection", description: "Prompt injection: system override attempt", severity: Severity::High },
    ];

    let mut results = Vec::new();
    let mut seen_subcategories = std::collections::HashSet::new();

    for pat in patterns {
        if seen_subcategories.contains(pat.subcategory) {
            continue;
        }

        if let Some(m) = pat.regex.find(content) {
            let matched_text = m.as_str();
            let evidence: String = matched_text.chars().take(200).collect();

            results.push(FileFinding {
                category: "malicious".to_string(),
                description: pat.description.to_string(),
                evidence,
                severity: pat.severity.clone(),
                source: "regex".to_string(),
                extracted_data: HashMap::new(),
            });

            seen_subcategories.insert(pat.subcategory);
        }
    }

    // Special handling: yaml.load without SafeLoader
    if !seen_subcategories.contains("malicious.exploit") {
        if let Some(m) = RE_YAML_UNSAFE.find(content) {
            let match_start = m.start();
            // Check if SafeLoader appears near the match (within 100 chars after)
            let search_end = (match_start + m.len() + 100).min(content.len());
            let vicinity = &content[match_start..search_end];
            if !RE_YAML_SAFE.is_match(vicinity) {
                let evidence: String = m.as_str().chars().take(200).collect();
                results.push(FileFinding {
                    category: "malicious".to_string(),
                    description: "Unsafe deserialization: yaml.load() without SafeLoader can execute arbitrary code".to_string(),
                    evidence,
                    severity: Severity::Critical,
                    source: "regex".to_string(),
                    extracted_data: HashMap::new(),
                });
            }
        }
    }

    results
}

fn read_text_safe(path: &Path) -> Result<String> {
    let metadata = fs::metadata(path)?;
    let size = metadata.len() as usize;
    let read_size = size.min(MAX_TEXT_READ);

    let bytes = fs::read(path)?;
    let content = String::from_utf8_lossy(&bytes[..read_size.min(bytes.len())]);
    Ok(content.to_string())
}

fn is_pdf(path: &Path) -> bool {
    path.extension()
        .and_then(|e| e.to_str())
        .is_some_and(|e| e.eq_ignore_ascii_case("pdf"))
}

fn extract_pdf_text(path: &Path) -> Result<String> {
    let output = Command::new("pdftotext")
        .args(["-layout", path.to_str().unwrap_or(""), "-"])
        .output();

    match output {
        Ok(out) if out.status.success() => {
            let text = String::from_utf8_lossy(&out.stdout).to_string();
            if text.trim().is_empty() {
                anyhow::bail!("PDF contains no extractable text (may be scanned/image-only)")
            }
            Ok(text)
        }
        Ok(out) => {
            let err = String::from_utf8_lossy(&out.stderr);
            anyhow::bail!("pdftotext failed: {}", err)
        }
        Err(_) => {
            anyhow::bail!("pdftotext not found. Install: pacman -S poppler (Arch) or apt install poppler-utils (Debian)")
        }
    }
}
