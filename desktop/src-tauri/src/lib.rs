use serde::{Deserialize, Serialize};
use std::process::Command;

#[derive(Serialize, Deserialize, Clone)]
pub struct Finding {
    pub category: String,
    pub subcategory: String,
    pub severity: String,
    pub explanation: String,
    pub source_file: Option<String>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct FileResult {
    pub path: String,
    pub kind: String,
    pub findings: Vec<Finding>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct ScanResult {
    pub files: Vec<FileResult>,
    pub total_files: usize,
    pub flagged_files: usize,
    pub clean_files: usize,
    pub critical: usize,
    pub high: usize,
    pub medium: usize,
    pub low: usize,
    pub info: usize,
}

/// Check if Ollama is reachable
#[tauri::command]
async fn check_ollama(url: String) -> Result<bool, String> {
    let client = reqwest::Client::new();
    match client
        .get(format!("{}/api/tags", url))
        .timeout(std::time::Duration::from_secs(5))
        .send()
        .await
    {
        Ok(resp) => Ok(resp.status().is_success()),
        Err(_) => Ok(false),
    }
}

/// List available Ollama models
#[tauri::command]
async fn list_models(url: String) -> Result<Vec<String>, String> {
    let client = reqwest::Client::new();
    let resp = client
        .get(format!("{}/api/tags", url))
        .timeout(std::time::Duration::from_secs(5))
        .send()
        .await
        .map_err(|e| e.to_string())?
        .json::<serde_json::Value>()
        .await
        .map_err(|e| e.to_string())?;

    let models = resp["models"]
        .as_array()
        .map(|arr| {
            arr.iter()
                .filter_map(|m| m["name"].as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();

    Ok(models)
}

/// Run a scan by invoking the torchsight CLI and parsing JSON output
#[tauri::command]
async fn scan_path(path: String) -> Result<ScanResult, String> {
    let output = tokio::task::spawn_blocking(move || {
        Command::new("torchsight")
            .args(["--format", "json", &path])
            .output()
    })
    .await
    .map_err(|e| e.to_string())?
    .map_err(|e| format!("Failed to run torchsight: {}", e))?;

    let stdout = String::from_utf8_lossy(&output.stdout);

    // Find the JSON report in stdout (skip banner lines)
    let json_str = stdout
        .lines()
        .find(|line| line.trim_start().starts_with('{'))
        .or_else(|| {
            // Try to find a JSON file path in output and read it
            stdout.lines().find(|l| l.contains("Report saved:")).and_then(|l| {
                l.split("Report saved:").nth(1).map(|p| p.trim())
            })
        })
        .ok_or_else(|| {
            format!(
                "No JSON output from torchsight. stderr: {}",
                String::from_utf8_lossy(&output.stderr)
            )
        })?;

    // If it's a file path, read the file
    let json_content = if json_str.ends_with(".json") {
        std::fs::read_to_string(json_str.trim()).map_err(|e| e.to_string())?
    } else {
        json_str.to_string()
    };

    serde_json::from_str(&json_content).map_err(|e| format!("Failed to parse report: {}", e))
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_shell::init())
        .invoke_handler(tauri::generate_handler![
            check_ollama,
            list_models,
            scan_path,
        ])
        .run(tauri::generate_context!())
        .expect("error while running TorchSight desktop");
}
