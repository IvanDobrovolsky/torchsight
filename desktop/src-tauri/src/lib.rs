use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::process::Command;
use tauri::Emitter;

trait CommandNoWindowExt {
    fn no_window(&mut self) -> &mut Self;
}

impl CommandNoWindowExt for Command {
    fn no_window(&mut self) -> &mut Self {
        #[cfg(target_os = "windows")]
        {
            use std::os::windows::process::CommandExt;
            const CREATE_NO_WINDOW: u32 = 0x0800_0000;
            self.creation_flags(CREATE_NO_WINDOW);
        }
        self
    }
}

// ── Structs matching the actual CLI JSON report format ──

#[derive(Deserialize, Clone)]
struct RawReport {
    files: Vec<RawFileResult>,
}

#[derive(Deserialize, Clone)]
struct RawFileResult {
    path: String,
    kind: String,
    findings: Vec<RawFinding>,
}

#[derive(Deserialize, Clone)]
struct RawFinding {
    category: String,
    #[serde(default)]
    description: String,
    #[serde(default)]
    evidence: String,
    severity: String,
    #[serde(default)]
    extracted_data: Option<serde_json::Value>,
}

// ── Structs sent to the frontend ──

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

#[derive(Serialize, Deserialize, Clone)]
pub struct FileResult {
    pub path: String,
    pub kind: String,
    pub findings: Vec<Finding>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct Finding {
    pub category: String,
    pub subcategory: String,
    pub severity: String,
    pub explanation: String,
}

impl From<RawReport> for ScanResult {
    fn from(raw: RawReport) -> Self {
        let mut critical = 0;
        let mut high = 0;
        let mut medium = 0;
        let mut low = 0;
        let mut info = 0;
        let mut flagged = 0;

        let files: Vec<FileResult> = raw.files.iter().map(|f| {
            let findings: Vec<Finding> = f.findings.iter().map(|fin| {
                let sev = fin.severity.to_lowercase();
                match sev.as_str() {
                    "critical" => critical += 1,
                    "high" => high += 1,
                    "medium" => medium += 1,
                    "low" => low += 1,
                    _ => info += 1,
                }
                Finding {
                    category: fin.category.clone(),
                    subcategory: fin.evidence.clone(),
                    severity: sev,
                    explanation: fin.description.clone(),
                }
            }).collect();

            let has_real_findings = findings.iter().any(|f| f.category != "safe" && f.severity != "info");
            if has_real_findings { flagged += 1; }

            FileResult {
                path: f.path.clone(),
                kind: f.kind.clone(),
                findings,
            }
        }).collect();

        let total = files.len();
        ScanResult {
            total_files: total,
            flagged_files: flagged,
            clean_files: total - flagged,
            critical, high, medium, low, info,
            files,
        }
    }
}

#[derive(Serialize, Clone)]
pub struct FileEntry {
    pub name: String,
    pub path: String,
    pub extension: String,
    pub size: u64,
    pub size_human: String,
}

#[derive(Serialize, Clone)]
pub struct SystemStats {
    pub cpu_percent: f64,
    pub memory_used_gb: f64,
    pub memory_total_gb: f64,
    pub memory_percent: f64,
    pub gpu_percent: f64,
    pub gpu_mem_used_gb: f64,
    pub gpu_mem_total_gb: f64,
}

// ── Commands ──

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

#[tauri::command]
fn check_tesseract() -> bool {
    #[cfg(target_os = "windows")]
    {
        if Command::new("where").arg("tesseract").no_window().output()
            .map(|o| o.status.success() && !o.stdout.is_empty())
            .unwrap_or(false) { return true; }
        for path in [
            "C:\\Program Files\\Tesseract-OCR\\tesseract.exe",
            "C:\\Program Files (x86)\\Tesseract-OCR\\tesseract.exe",
        ] {
            if std::path::Path::new(path).exists() { return true; }
        }
        false
    }
    #[cfg(not(target_os = "windows"))]
    {
        Command::new("which").arg("tesseract").output()
            .map(|o| o.status.success() && !o.stdout.is_empty())
            .unwrap_or(false)
    }
}

#[cfg(target_os = "windows")]
fn ollama_path() -> std::path::PathBuf {
    if let Ok(local) = std::env::var("LOCALAPPDATA") {
        let p = std::path::PathBuf::from(local).join("Programs").join("Ollama").join("ollama.exe");
        if p.exists() { return p; }
    }
    std::path::PathBuf::from("ollama.exe")
}

#[tauri::command]
fn check_ollama_installed() -> bool {
    #[cfg(target_os = "windows")]
    {
        if let Ok(local) = std::env::var("LOCALAPPDATA") {
            let p = std::path::PathBuf::from(local).join("Programs").join("Ollama").join("ollama.exe");
            if p.exists() { return true; }
        }
        Command::new("where").arg("ollama").no_window().output()
            .map(|o| o.status.success() && !o.stdout.is_empty())
            .unwrap_or(false)
    }
    #[cfg(not(target_os = "windows"))]
    {
        Command::new("which").arg("ollama").output()
            .map(|o| o.status.success() && !o.stdout.is_empty())
            .unwrap_or(false)
    }
}

async fn download_with_progress(
    url: &str,
    dest: &std::path::Path,
    app: &tauri::AppHandle,
    event: &str,
) -> Result<(), String> {
    use futures_util::StreamExt;
    use tokio::io::AsyncWriteExt;

    let resp = reqwest::Client::new()
        .get(url)
        .send()
        .await
        .map_err(|e| format!("download request failed: {e}"))?
        .error_for_status()
        .map_err(|e| format!("download HTTP error: {e}"))?;
    let total = resp.content_length().unwrap_or(0);
    let mut stream = resp.bytes_stream();
    let mut file = tokio::fs::File::create(dest)
        .await
        .map_err(|e| format!("create file failed: {e}"))?;
    let mut downloaded: u64 = 0;
    let mut last_pct: i32 = -1;
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|e| format!("download chunk failed: {e}"))?;
        file.write_all(&chunk).await.map_err(|e| format!("write failed: {e}"))?;
        downloaded += chunk.len() as u64;
        let pct = if total > 0 { ((downloaded * 100) / total) as i32 } else { -1 };
        if pct != last_pct {
            last_pct = pct;
            let _ = app.emit(event, serde_json::json!({
                "downloaded": downloaded,
                "total": total,
                "percent": pct,
            }));
        }
    }
    file.flush().await.ok();
    Ok(())
}

#[tauri::command]
async fn install_ollama(app_handle: tauri::AppHandle) -> Result<(), String> {
    #[cfg(not(target_os = "windows"))]
    { let _ = app_handle; return Err("Auto-install only supported on Windows. Install Ollama manually from https://ollama.com".into()); }

    #[cfg(target_os = "windows")]
    {
        let url = "https://ollama.com/download/OllamaSetup.exe";
        let tmp = std::env::temp_dir().join("OllamaSetup.exe");
        download_with_progress(url, &tmp, &app_handle, "ollama-download-progress").await?;
        let _ = app_handle.emit("ollama-install-status", "running");
        let status = tokio::task::spawn_blocking({
            let tmp = tmp.clone();
            move || Command::new(&tmp).arg("/S").no_window().status()
        })
        .await
        .map_err(|e| e.to_string())?
        .map_err(|e| format!("Ollama installer failed to launch: {e}"))?;
        let _ = std::fs::remove_file(&tmp);
        if !status.success() {
            return Err(format!("Ollama installer exited with status {status}"));
        }
        Ok(())
    }
}

#[tauri::command]
async fn install_tesseract(app_handle: tauri::AppHandle) -> Result<(), String> {
    #[cfg(not(target_os = "windows"))]
    { let _ = app_handle; return Err("Auto-install only supported on Windows.".into()); }

    #[cfg(target_os = "windows")]
    {
        let url = "https://github.com/UB-Mannheim/tesseract/releases/download/v5.4.0.20240606/tesseract-ocr-w64-setup-5.4.0.20240606.exe";
        let tmp = std::env::temp_dir().join("TesseractSetup.exe");
        download_with_progress(url, &tmp, &app_handle, "tesseract-download-progress").await?;
        let _ = app_handle.emit("tesseract-install-status", "running");
        let status = tokio::task::spawn_blocking({
            let tmp = tmp.clone();
            move || Command::new(&tmp)
                .args(["/VERYSILENT", "/NORESTART", "/SUPPRESSMSGBOXES"])
                .no_window()
                .status()
        })
        .await
        .map_err(|e| e.to_string())?
        .map_err(|e| format!("Tesseract installer failed to launch: {e}"))?;
        let _ = std::fs::remove_file(&tmp);
        if !status.success() {
            return Err(format!("Tesseract installer exited with status {status}"));
        }
        Ok(())
    }
}

#[tauri::command]
fn start_ollama_service() -> Result<(), String> {
    // Spawn detached so the Ollama service survives our process exit. Without
    // this, killing TorchSight (or it crashing) would tear down Ollama with it,
    // and the next launch would re-trigger the full setup orchestrator.
    #[cfg(target_os = "windows")]
    {
        let path = ollama_path();
        // `cmd /c start "" /B <exe> serve` invokes ShellExecute under the hood,
        // which detaches the spawned process from this cmd. The cmd itself exits
        // immediately, leaving ollama.exe running as a top-level process.
        Command::new("cmd")
            .args(["/c", "start", "", "/B", &path.to_string_lossy(), "serve"])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .stdin(std::process::Stdio::null())
            .no_window()
            .spawn()
            .map_err(|e| format!("Failed to start Ollama service: {e}"))?;
        Ok(())
    }
    #[cfg(not(target_os = "windows"))]
    {
        // Unix: spawning detached is rarely needed (Ollama runs as a system
        // service on macOS/Linux). Plain spawn is fine for the fallback.
        Command::new("ollama")
            .arg("serve")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .stdin(std::process::Stdio::null())
            .spawn()
            .map_err(|e| format!("Failed to start Ollama service: {e}"))?;
        Ok(())
    }
}

#[tauri::command]
async fn pull_model(model: String, app_handle: tauri::AppHandle) -> Result<(), String> {
    use futures_util::StreamExt;

    let resp = reqwest::Client::new()
        .post("http://127.0.0.1:11434/api/pull")
        .json(&serde_json::json!({"name": model, "stream": true}))
        .send()
        .await
        .map_err(|e| format!("pull request failed: {e}"))?
        .error_for_status()
        .map_err(|e| format!("pull HTTP error: {e}"))?;

    let mut stream = resp.bytes_stream();
    let mut buffer = String::new();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|e| format!("pull stream error: {e}"))?;
        buffer.push_str(&String::from_utf8_lossy(&chunk));
        while let Some(idx) = buffer.find('\n') {
            let line: String = buffer.drain(..=idx).collect();
            let line = line.trim();
            if line.is_empty() { continue; }
            if let Ok(json) = serde_json::from_str::<serde_json::Value>(line) {
                let _ = app_handle.emit("model-pull-progress", &json);
                if json.get("status").and_then(|v| v.as_str()) == Some("success") {
                    return Ok(());
                }
                if let Some(err) = json.get("error").and_then(|v| v.as_str()) {
                    return Err(err.to_string());
                }
            }
        }
    }
    Ok(())
}

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
        .map(|arr| arr.iter().filter_map(|m| m["name"].as_str().map(String::from)).collect())
        .unwrap_or_default();
    Ok(models)
}

#[tauri::command]
async fn list_files(path: String) -> Result<Vec<FileEntry>, String> {
    tokio::task::spawn_blocking(move || {
        let mut entries = Vec::new();
        for entry in walkdir::WalkDir::new(&path).max_depth(10).into_iter().filter_map(|e| e.ok()) {
            if entry.file_type().is_file() {
                let fp = entry.path();
                let size = entry.metadata().map(|m| m.len()).unwrap_or(0);
                entries.push(FileEntry {
                    name: fp.file_name().and_then(|n| n.to_str()).unwrap_or("").to_string(),
                    path: fp.to_string_lossy().to_string(),
                    extension: fp.extension().and_then(|e| e.to_str()).unwrap_or("").to_string(),
                    size,
                    size_human: format_size(size),
                });
            }
        }
        entries.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(entries)
    })
    .await
    .map_err(|e| e.to_string())?
}

// sysinfo handle is global so CPU usage can be sampled correctly (the first
// refresh after construction reports zero — subsequent refreshes report deltas).
static SYS: std::sync::OnceLock<std::sync::Mutex<sysinfo::System>> = std::sync::OnceLock::new();

#[tauri::command]
async fn get_system_stats() -> Result<SystemStats, String> {
    tokio::task::spawn_blocking(|| {
        let sys_lock = SYS.get_or_init(|| std::sync::Mutex::new(sysinfo::System::new()));
        let mut sys = sys_lock.lock().map_err(|e| e.to_string())?;
        // CPU usage requires a refresh + delta; refresh_cpu_all updates per-core load.
        sys.refresh_cpu_all();
        // Sleep briefly to let CPU counters tick — sysinfo needs >= MINIMUM_CPU_UPDATE_INTERVAL.
        std::thread::sleep(sysinfo::MINIMUM_CPU_UPDATE_INTERVAL);
        sys.refresh_cpu_all();
        sys.refresh_memory();

        let cpu_percent = sys.global_cpu_usage() as f64;
        let total = sys.total_memory() as f64;
        let used  = sys.used_memory() as f64;
        let gb = 1024.0 * 1024.0 * 1024.0;

        // GPU stats stay platform-specific (sysinfo doesn't cover GPUs).
        let (gpu_pct, gpu_used, gpu_total) = {
            #[cfg(target_os = "macos")] { get_gpu_stats_macos() }
            #[cfg(target_os = "linux")] { get_gpu_stats_linux() }
            #[cfg(target_os = "windows")] { get_gpu_stats_windows() }
        };

        Ok(SystemStats {
            cpu_percent,
            memory_used_gb: used / gb,
            memory_total_gb: total / gb,
            memory_percent: if total > 0.0 { (used / total) * 100.0 } else { 0.0 },
            gpu_percent: gpu_pct,
            gpu_mem_used_gb: gpu_used,
            gpu_mem_total_gb: gpu_total,
        })
    })
    .await
    .map_err(|e| e.to_string())?
}

#[tauri::command]
async fn scan_path(path: String, app_handle: tauri::AppHandle) -> Result<ScanResult, String> {
    let binary = find_torchsight_binary()?;
    let report_dir = std::env::temp_dir().join("torchsight-desktop");
    std::fs::create_dir_all(&report_dir).map_err(|e| e.to_string())?;

    let scan_path = path.clone();
    let report_dir_clone = report_dir.clone();
    let app = app_handle.clone();

    let output = tokio::task::spawn_blocking(move || {
        let mut child = Command::new(&binary)
            .args(["--format", "json", &scan_path])
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .current_dir(&report_dir_clone)
            .no_window()
            .spawn()
            .map_err(|e| format!("Failed to run torchsight: {}", e))?;

        // Read stderr live for progress — use BufReader for proper line buffering
        let stderr = child.stderr.take();
        let app_clone = app.clone();
        let stderr_handle = std::thread::spawn(move || {
            let mut buf_all = String::new();
            if let Some(stderr) = stderr {
                use std::io::BufRead;
                let reader = std::io::BufReader::new(stderr);
                for line in reader.lines() {
                    match line {
                        Ok(line) => {
                            buf_all.push_str(&line);
                            buf_all.push('\n');
                            let clean = strip_ansi(&line).trim().to_string();
                            if !clean.is_empty() && (clean.contains("Scanning") || clean.contains("Scan complete") || clean.contains("[")) {
                                let _ = app_clone.emit("scan-progress", &clean);
                            }
                        }
                        Err(_) => break,
                    }
                }
            }
            buf_all
        });

        let stdout_output = {
            let mut s = String::new();
            if let Some(mut stdout) = child.stdout.take() {
                use std::io::Read;
                stdout.read_to_string(&mut s).ok();
            }
            s
        };

        let _ = child.wait();
        let stderr_output = stderr_handle.join().unwrap_or_default();
        Ok::<(String, String), String>((stdout_output, stderr_output))
    })
    .await
    .map_err(|e| e.to_string())??;

    let (stdout, stderr) = output;
    let combined = format!("{}\n{}", stdout, stderr);

    // Clean old reports from temp dir BEFORE looking for the new one
    if let Ok(entries) = std::fs::read_dir(&report_dir) {
        let scan_start = std::time::SystemTime::now() - std::time::Duration::from_secs(5);
        for entry in entries.flatten() {
            let n = entry.file_name().to_string_lossy().to_string();
            if n.starts_with("torchsight_report") && n.ends_with(".json") {
                if let Ok(meta) = entry.metadata() {
                    if let Ok(modified) = meta.modified() {
                        if modified < scan_start {
                            let _ = std::fs::remove_file(entry.path());
                        }
                    }
                }
            }
        }
    }

    // Find report file path from CLI output
    let json_path = combined.lines()
        .find(|l| l.contains("Report saved:") && l.contains(".json"))
        .and_then(|l| {
            let after = l.split("Report saved:").nth(1)?;
            let clean = strip_ansi(after.trim());
            let p = std::path::Path::new(&clean);
            if p.is_absolute() && p.exists() {
                Some(clean)
            } else {
                let resolved = report_dir.join(&clean);
                if resolved.exists() { Some(resolved.to_string_lossy().to_string()) } else { None }
            }
        });

    // Try the extracted path
    if let Some(ref path) = json_path {
        if let Ok(content) = std::fs::read_to_string(path) {
            let raw: RawReport = serde_json::from_str(&content)
                .map_err(|e| format!("Failed to parse report: {}", e))?;
            return Ok(raw.into());
        }
    }

    // No report found — return error, never return stale data
    Err(format!("Scan failed. No report generated.\n{}",
        stderr.trim().chars().take(500).collect::<String>()))
}

#[tauri::command]
async fn export_report(result: ScanResult) -> Result<String, String> {
    let timestamp = chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string();
    let date_file = chrono::Local::now().format("%Y%m%d_%H%M%S").to_string();

    // Separate flagged and clean files
    let mut flagged_rows = String::new();
    let mut clean_rows = String::new();

    for file in &result.files {
        let has_findings = file.findings.iter().any(|f| f.category != "safe" && f.severity != "info");

        if has_findings {
            for finding in &file.findings {
                if finding.category == "safe" { continue; }
                let sev_color = match finding.severity.as_str() {
                    "critical" => "#DC2626",
                    "high" => "#EA580C",
                    "medium" => "#D97706",
                    "low" => "#CA8A04",
                    _ => "#8B83A3",
                };
                let short_path = file.path.rsplit('/').next().unwrap_or(&file.path);
                let subcat = if finding.subcategory.is_empty() {
                    finding.category.clone()
                } else {
                    finding.subcategory.clone()
                };
                flagged_rows.push_str(&format!(
                    r#"<tr>
                        <td title="{full}" style="font-family:monospace;font-size:12px">{short}</td>
                        <td><span style="background:{sev_color};color:#fff;padding:2px 8px;border-radius:4px;font-size:11px;font-weight:600">{severity}</span></td>
                        <td><span style="background:#f0f0f0;padding:2px 8px;border-radius:4px;font-size:11px">{subcat}</span></td>
                        <td style="font-size:12px;color:#333">{explanation}</td>
                    </tr>"#,
                    full = html_esc(&file.path),
                    short = html_esc(short_path),
                    sev_color = sev_color,
                    severity = html_esc(&finding.severity),
                    subcat = html_esc(&subcat),
                    explanation = html_esc(&finding.explanation),
                ));
            }
        } else {
            let short_path = file.path.rsplit('/').next().unwrap_or(&file.path);
            let desc = file.findings.iter()
                .find(|f| f.category == "safe" && !f.explanation.is_empty())
                .map(|f| f.explanation.as_str())
                .unwrap_or("No sensitive content detected.");
            clean_rows.push_str(&format!(
                r#"<tr>
                    <td title="{full}" style="font-family:monospace;font-size:12px">{short}</td>
                    <td><span style="color:#059669;font-weight:600">&#10003; Clean</span></td>
                    <td style="font-size:12px;color:#777">{desc}</td>
                </tr>"#,
                full = html_esc(&file.path),
                short = html_esc(short_path),
                desc = html_esc(desc),
            ));
        }
    }

    let flagged_section = if flagged_rows.is_empty() {
        "<p style=\"color:#059669;font-weight:600;margin:16px 0\">No findings — all files are clean.</p>".to_string()
    } else {
        format!(
            r#"<h2 style="font-size:18px;margin:24px 0 12px;color:#DC2626">Flagged Files</h2>
<table><thead><tr><th>File</th><th>Severity</th><th>Classification</th><th>Explanation</th></tr></thead><tbody>{flagged_rows}</tbody></table>"#
        )
    };

    let clean_section = if clean_rows.is_empty() {
        String::new()
    } else {
        format!(
            r#"<h2 style="font-size:18px;margin:24px 0 12px;color:#059669">Clean Files</h2>
<table><thead><tr><th>File</th><th>Status</th><th>Description</th></tr></thead><tbody>{clean_rows}</tbody></table>"#
        )
    };

    let html = format!(r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>TorchSight Security Report</title>
<style>
  body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; margin: 40px; color: #1a1a1a; }}
  h1 {{ font-size: 24px; border-bottom: 3px solid #6366F1; padding-bottom: 8px; }}
  .meta {{ color: #666; font-size: 13px; margin-bottom: 24px; }}
  .stats {{ display: flex; gap: 16px; margin-bottom: 24px; flex-wrap: wrap; }}
  .stat {{ background: #f5f5f5; border-radius: 8px; padding: 12px 20px; text-align: center; min-width: 80px; }}
  .stat-num {{ font-size: 22px; font-weight: 700; }}
  .stat-label {{ font-size: 11px; color: #666; text-transform: uppercase; }}
  .stat-critical .stat-num {{ color: #DC2626; }}
  .stat-high .stat-num {{ color: #EA580C; }}
  .stat-medium .stat-num {{ color: #D97706; }}
  .stat-low .stat-num {{ color: #CA8A04; }}
  table {{ width: 100%; border-collapse: collapse; margin-bottom: 16px; }}
  th {{ text-align: left; padding: 8px 12px; background: #f0f0f0; font-size: 12px; text-transform: uppercase; color: #555; }}
  td {{ padding: 8px 12px; border-bottom: 1px solid #eee; vertical-align: top; }}
  tr:hover {{ background: #fafafa; }}
  .footer {{ margin-top: 32px; padding-top: 12px; border-top: 1px solid #ddd; font-size: 11px; color: #999; }}
  .hint {{ color: #999; font-size: 12px; margin-top: 4px; }}
  @media print {{ body {{ margin: 20px; }} .hint {{ display: none; }} }}
</style>
</head>
<body>
<h1>TorchSight Security Report</h1>
<div class="meta">Generated {timestamp}</div>
<div class="hint">To save as PDF: File &rarr; Print &rarr; Save as PDF</div>
<div class="stats">
  <div class="stat"><div class="stat-num">{total}</div><div class="stat-label">Files</div></div>
  <div class="stat stat-critical"><div class="stat-num">{critical}</div><div class="stat-label">Critical</div></div>
  <div class="stat stat-high"><div class="stat-num">{high}</div><div class="stat-label">High</div></div>
  <div class="stat stat-medium"><div class="stat-num">{medium}</div><div class="stat-label">Medium</div></div>
  <div class="stat stat-low"><div class="stat-num">{low}</div><div class="stat-label">Low</div></div>
  <div class="stat"><div class="stat-num">{clean}</div><div class="stat-label">Clean</div></div>
</div>
{flagged_section}
{clean_section}
<div class="footer">TorchSight &mdash; Open-source security scanner powered by local LLMs</div>
</body>
</html>"#,
        timestamp = timestamp,
        total = result.total_files,
        critical = result.critical,
        high = result.high,
        medium = result.medium,
        low = result.low,
        clean = result.clean_files,
        flagged_section = flagged_section,
        clean_section = clean_section,
    );

    let report_dir = std::env::temp_dir().join("torchsight-desktop");
    std::fs::create_dir_all(&report_dir).map_err(|e| e.to_string())?;
    let path = report_dir.join(format!("torchsight_report_{}.html", date_file));
    std::fs::write(&path, &html).map_err(|e| e.to_string())?;

    // Open in system browser
    open::that(&path).map_err(|e| e.to_string())?;

    Ok(path.to_string_lossy().to_string())
}

fn html_esc(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;")
}

// ── Helpers ──

fn format_size(bytes: u64) -> String {
    if bytes < 1024 { format!("{} B", bytes) }
    else if bytes < 1024 * 1024 { format!("{:.1} KB", bytes as f64 / 1024.0) }
    else if bytes < 1024 * 1024 * 1024 { format!("{:.1} MB", bytes as f64 / (1024.0 * 1024.0)) }
    else { format!("{:.2} GB", bytes as f64 / (1024.0 * 1024.0 * 1024.0)) }
}

fn strip_ansi(s: &str) -> String {
    let mut result = String::with_capacity(s.len());
    let mut in_escape = false;
    for c in s.chars() {
        if c == '\x1b' { in_escape = true; }
        else if in_escape { if c.is_ascii_alphabetic() { in_escape = false; } }
        else { result.push(c); }
    }
    result
}

fn find_torchsight_binary() -> Result<PathBuf, String> {
    let bin_name = if cfg!(target_os = "windows") { "torchsight.exe" } else { "torchsight" };

    if let Ok(exe) = std::env::current_exe() {
        let sibling = exe.parent().unwrap_or(exe.as_path()).join(bin_name);
        if sibling.exists() { return Ok(sibling); }

        #[cfg(target_os = "macos")]
        if let Some(macos_dir) = exe.parent() {
            if macos_dir.ends_with("MacOS") {
                if let Some(bundle_parent) = macos_dir.ancestors().nth(3) {
                    let beside_app = bundle_parent.join(bin_name);
                    if beside_app.exists() { return Ok(beside_app); }
                }
            }
        }

        for ancestor in exe.ancestors().skip(1) {
            let candidate = ancestor.join(format!("target/release/{}", bin_name));
            if candidate.exists() { return Ok(candidate); }
        }
    }

    let home = dirs::home_dir().unwrap_or_default();

    #[cfg(target_os = "windows")]
    {
        let candidates = [
            home.join(format!(".cargo/bin/{}", bin_name)),
            home.join(format!("AppData/Local/Programs/torchsight/{}", bin_name)),
        ];
        for c in &candidates {
            if c.exists() { return Ok(c.clone()); }
        }
        // Try PATH via `where`
        if let Ok(output) = Command::new("where").arg("torchsight").no_window().output() {
            let path = String::from_utf8_lossy(&output.stdout).lines().next().unwrap_or("").trim().to_string();
            if !path.is_empty() {
                let p = PathBuf::from(&path);
                if p.exists() { return Ok(p); }
            }
        }
    }

    #[cfg(not(target_os = "windows"))]
    {
        let candidates = [
            home.join(".local/bin/torchsight"),
            home.join(".cargo/bin/torchsight"),
            PathBuf::from("/usr/local/bin/torchsight"),
            PathBuf::from("/opt/homebrew/bin/torchsight"),
        ];
        for c in &candidates {
            if c.exists() { return Ok(c.clone()); }
        }
        // Try PATH via `which`
        if let Ok(output) = Command::new("which").arg("torchsight").output() {
            let path = String::from_utf8_lossy(&output.stdout).trim().to_string();
            if !path.is_empty() {
                let p = PathBuf::from(&path);
                if p.exists() { return Ok(p); }
            }
        }
    }

    Err("Could not find torchsight CLI binary. Install it with: cargo install --path core".to_string())
}

#[cfg(target_os = "macos")]
fn run_cmd(cmd: &str, args: &[&str]) -> Option<String> {
    Command::new(cmd).args(args).output().ok()
        .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
}

#[cfg(target_os = "macos")]
fn parse_vm_stat(vm: &str, key: &str) -> f64 {
    vm.lines().find(|l| l.contains(key))
        .and_then(|l| l.split(':').nth(1).and_then(|v| v.trim().trim_end_matches('.').parse().ok()))
        .unwrap_or(0.0)
}

#[cfg(target_os = "macos")]
fn get_gpu_stats_macos() -> (f64, f64, f64) {
    let output = run_cmd("ioreg", &["-r", "-d", "1", "-c", "IOAccelerator"]).unwrap_or_default();

    // PerformanceStatistics is a single-line dict like:
    // "PerformanceStatistics" = {"Device Utilization %"=31,"In use system memory"=810024960,"Alloc system memory"=17025794048,...}
    // Parse key=value pairs from it
    let gpu_util = parse_ioreg_stat(&output, "Device Utilization %").unwrap_or(0.0);
    let in_use = parse_ioreg_stat(&output, "In use system memory\"").unwrap_or(0.0); // exact match, not driver variant
    let alloc = parse_ioreg_stat(&output, "Alloc system memory").unwrap_or(0.0);

    let gb = 1024.0 * 1024.0 * 1024.0;
    let total_alloc = if alloc > 0.0 { alloc / gb } else { 16.0 };
    (gpu_util, in_use / gb, total_alloc)
}

#[cfg(target_os = "macos")]
fn parse_ioreg_stat(output: &str, key: &str) -> Option<f64> {
    // Find the key in the output, then extract the number after '='
    let idx = output.find(key)?;
    let after_key = &output[idx + key.len()..];
    // Skip to the '=' sign
    let eq_idx = after_key.find('=')?;
    let after_eq = &after_key[eq_idx + 1..];
    // Read digits (and possible decimal point)
    let num_str: String = after_eq.trim().chars()
        .take_while(|c| c.is_ascii_digit() || *c == '.')
        .collect();
    num_str.parse().ok()
}

#[cfg(target_os = "linux")]
fn parse_meminfo(info: &str, key: &str) -> f64 {
    info.lines().find(|l| l.starts_with(key))
        .and_then(|l| l.split_whitespace().nth(1).and_then(|v| v.parse().ok()))
        .unwrap_or(0.0)
}

#[cfg(target_os = "linux")]
fn get_gpu_stats_linux() -> (f64, f64, f64) {
    // Try nvidia-smi
    if let Some(output) = Command::new("nvidia-smi")
        .args(["--query-gpu=utilization.gpu,memory.used,memory.total", "--format=csv,noheader,nounits"])
        .output().ok()
    {
        let s = String::from_utf8_lossy(&output.stdout);
        let parts: Vec<&str> = s.trim().split(',').map(|p| p.trim()).collect();
        if parts.len() == 3 {
            let util = parts[0].parse().unwrap_or(0.0);
            let used = parts[1].parse::<f64>().unwrap_or(0.0) / 1024.0;
            let total = parts[2].parse::<f64>().unwrap_or(0.0) / 1024.0;
            return (util, used, total);
        }
    }
    (0.0, 0.0, 0.0)
}

#[cfg(target_os = "windows")]
fn run_cmd_win(cmd: &str, args: &[&str]) -> Option<String> {
    Command::new(cmd).args(args).no_window().output().ok()
        .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
}

#[cfg(target_os = "windows")]
fn get_gpu_stats_windows() -> (f64, f64, f64) {
    if let Some(output) = Command::new("nvidia-smi")
        .args(["--query-gpu=utilization.gpu,memory.used,memory.total", "--format=csv,noheader,nounits"])
        .no_window()
        .output().ok()
    {
        let s = String::from_utf8_lossy(&output.stdout);
        let parts: Vec<&str> = s.trim().split(',').map(|p| p.trim()).collect();
        if parts.len() == 3 {
            let util = parts[0].parse().unwrap_or(0.0);
            let used = parts[1].parse::<f64>().unwrap_or(0.0) / 1024.0;
            let total = parts[2].parse::<f64>().unwrap_or(0.0) / 1024.0;
            return (util, used, total);
        }
    }
    (0.0, 0.0, 0.0)
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_shell::init())
        .invoke_handler(tauri::generate_handler![
            check_ollama, check_ollama_installed, check_tesseract, list_models, list_files, get_system_stats, scan_path, export_report,
            install_ollama, install_tesseract, start_ollama_service, pull_model,
        ])
        .run(tauri::generate_context!())
        .expect("error while running TorchSight desktop");
}
