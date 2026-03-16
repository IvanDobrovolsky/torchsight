use anyhow::Result;
use dialoguer::{Input, MultiSelect, theme::ColorfulTheme};

pub struct ScanRequest {
    pub path: String,
    pub concerns: Vec<String>,
    pub file_types: Vec<String>,
}

const CONCERN_OPTIONS: &[&str] = &[
    "PII (names, emails, SSN, phone numbers)",
    "Credentials (API keys, passwords, tokens)",
    "Financial (credit cards, bank accounts)",
    "Medical / PHI",
    "Classification (confidential, internal, public)",
    "All of the above",
];

const FILE_TYPE_OPTIONS: &[&str] = &["Text files", "Image files", "All files"];

pub fn gather_scan_request() -> Result<ScanRequest> {
    let cwd = std::env::current_dir()
        .map(|p| p.display().to_string())
        .unwrap_or_else(|_| ".".to_string());

    let path: String = Input::with_theme(&ColorfulTheme::default())
        .with_prompt(format!("Path to scan (/ or . = {})", cwd))
        .default("/".to_string())
        .interact_text()?;

    let concern_indices = MultiSelect::with_theme(&ColorfulTheme::default())
        .with_prompt("What to look for (space to select, enter to confirm)")
        .items(CONCERN_OPTIONS)
        .defaults(&[false, false, false, false, false, true])
        .interact()?;

    let concerns: Vec<String> = if concern_indices.contains(&5) || concern_indices.is_empty() {
        CONCERN_OPTIONS[..5].iter().map(|s| s.to_string()).collect()
    } else {
        concern_indices
            .iter()
            .map(|&i| CONCERN_OPTIONS[i].to_string())
            .collect()
    };

    let file_type_indices = MultiSelect::with_theme(&ColorfulTheme::default())
        .with_prompt("File types to scan")
        .items(FILE_TYPE_OPTIONS)
        .defaults(&[false, false, true])
        .interact()?;

    let file_types: Vec<String> =
        if file_type_indices.contains(&2) || file_type_indices.is_empty() {
            vec!["text".into(), "image".into()]
        } else {
            file_type_indices
                .iter()
                .map(|&i| match i {
                    0 => "text".to_string(),
                    1 => "image".to_string(),
                    _ => "all".to_string(),
                })
                .collect()
        };

    Ok(ScanRequest {
        path,
        concerns,
        file_types,
    })
}
