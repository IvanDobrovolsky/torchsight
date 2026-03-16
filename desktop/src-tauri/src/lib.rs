use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::process::Command;
use tauri::Emitter;

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

#[derive(Serialize, Clone)]
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

#[derive(Serialize, Clone)]
pub struct FileResult {
    pub path: String,
    pub kind: String,
    pub findings: Vec<Finding>,
}

#[derive(Serialize, Clone)]
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

#[tauri::command]
async fn get_system_stats() -> Result<SystemStats, String> {
    tokio::task::spawn_blocking(|| {
        #[cfg(target_os = "macos")]
        {
            // RAM
            let mem_total = run_cmd("sysctl", &["-n", "hw.memsize"])
                .and_then(|s| s.trim().parse::<f64>().ok())
                .unwrap_or(0.0);
            let vm = run_cmd("vm_stat", &[]).unwrap_or_default();
            let page_size = 16384.0_f64;
            let free = (parse_vm_stat(&vm, "Pages free")
                + parse_vm_stat(&vm, "Pages inactive")
                + parse_vm_stat(&vm, "Pages speculative")) * page_size;
            let used = mem_total - free;

            // CPU
            let cpu = run_cmd("ps", &["-A", "-o", "%cpu"])
                .map(|s| s.lines().skip(1).filter_map(|l| l.trim().parse::<f64>().ok()).sum::<f64>())
                .unwrap_or(0.0);
            let ncpu = run_cmd("sysctl", &["-n", "hw.logicalcpu"])
                .and_then(|s| s.trim().parse::<f64>().ok())
                .unwrap_or(1.0);

            // GPU — via ioreg PerformanceStatistics (Apple Silicon)
            let (gpu_pct, gpu_used, gpu_total) = get_gpu_stats_macos();

            Ok(SystemStats {
                cpu_percent: (cpu / ncpu).min(100.0),
                memory_used_gb: used / (1024.0 * 1024.0 * 1024.0),
                memory_total_gb: mem_total / (1024.0 * 1024.0 * 1024.0),
                memory_percent: if mem_total > 0.0 { (used / mem_total) * 100.0 } else { 0.0 },
                gpu_percent: gpu_pct,
                gpu_mem_used_gb: gpu_used,
                gpu_mem_total_gb: gpu_total,
            })
        }

        #[cfg(target_os = "linux")]
        {
            let meminfo = std::fs::read_to_string("/proc/meminfo").unwrap_or_default();
            let total = parse_meminfo(&meminfo, "MemTotal");
            let available = parse_meminfo(&meminfo, "MemAvailable");
            let used = total - available;
            let loadavg = std::fs::read_to_string("/proc/loadavg").unwrap_or_default();
            let load1 = loadavg.split_whitespace().next()
                .and_then(|s| s.parse::<f64>().ok()).unwrap_or(0.0);
            // Try nvidia-smi for GPU
            let (gpu_pct, gpu_used, gpu_total) = get_gpu_stats_linux();

            Ok(SystemStats {
                cpu_percent: (load1 * 100.0 / 4.0).min(100.0), // rough estimate
                memory_used_gb: used / (1024.0 * 1024.0),
                memory_total_gb: total / (1024.0 * 1024.0),
                memory_percent: if total > 0.0 { (used / total) * 100.0 } else { 0.0 },
                gpu_percent: gpu_pct,
                gpu_mem_used_gb: gpu_used,
                gpu_mem_total_gb: gpu_total,
            })
        }

        #[cfg(target_os = "windows")]
        {
            Ok(SystemStats {
                cpu_percent: 0.0, memory_used_gb: 0.0, memory_total_gb: 0.0,
                memory_percent: 0.0, gpu_percent: 0.0, gpu_mem_used_gb: 0.0, gpu_mem_total_gb: 0.0,
            })
        }
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
            .spawn()
            .map_err(|e| format!("Failed to run torchsight: {}", e))?;

        // Read stderr live for progress
        let stderr = child.stderr.take();
        let app_clone = app.clone();
        let stderr_handle = std::thread::spawn(move || {
            let mut buf_all = String::new();
            if let Some(mut stderr) = stderr {
                use std::io::Read;
                let mut buf = [0u8; 512];
                loop {
                    match stderr.read(&mut buf) {
                        Ok(0) => break,
                        Ok(n) => {
                            let chunk = String::from_utf8_lossy(&buf[..n]);
                            buf_all.push_str(&chunk);
                            for line in chunk.lines() {
                                let clean = strip_ansi(line).trim().to_string();
                                if !clean.is_empty() && (clean.contains("Scanning") || clean.contains("Scan complete") || clean.contains("[")) {
                                    let _ = app_clone.emit("scan-progress", &clean);
                                }
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

    // Find report file path
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

    // Try the extracted path first
    if let Some(ref path) = json_path {
        if let Ok(content) = std::fs::read_to_string(path) {
            let raw: RawReport = serde_json::from_str(&content)
                .map_err(|e| format!("Failed to parse report: {}", e))?;
            return Ok(raw.into());
        }
    }

    // Fallback: newest report in report_dir
    if let Ok(entries) = std::fs::read_dir(&report_dir) {
        let mut reports: Vec<_> = entries.filter_map(|e| e.ok())
            .filter(|e| {
                let n = e.file_name().to_string_lossy().to_string();
                n.starts_with("torchsight_report") && n.ends_with(".json")
            }).collect();
        reports.sort_by_key(|e| std::cmp::Reverse(e.metadata().ok().and_then(|m| m.modified().ok())));
        if let Some(latest) = reports.first() {
            let content = std::fs::read_to_string(latest.path()).map_err(|e| e.to_string())?;
            let raw: RawReport = serde_json::from_str(&content)
                .map_err(|e| format!("Failed to parse report: {}", e))?;
            return Ok(raw.into());
        }
    }

    Err(format!("No report found after scan. Check that torchsight CLI works.\nstdout: {}\nstderr: {}",
        &stdout[..stdout.len().min(300)], &stderr[..stderr.len().min(300)]))
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
    if let Ok(exe) = std::env::current_exe() {
        let sibling = exe.parent().unwrap_or(exe.as_path()).join("torchsight");
        if sibling.exists() { return Ok(sibling); }
        if let Some(macos_dir) = exe.parent() {
            if macos_dir.ends_with("MacOS") {
                if let Some(bundle_parent) = macos_dir.ancestors().nth(3) {
                    let beside_app = bundle_parent.join("torchsight");
                    if beside_app.exists() { return Ok(beside_app); }
                }
            }
        }
        for ancestor in exe.ancestors().skip(1) {
            let candidate = ancestor.join("target/release/torchsight");
            if candidate.exists() { return Ok(candidate); }
        }
    }
    let home = dirs::home_dir().unwrap_or_default();
    for c in &[home.join(".cargo/bin/torchsight"), PathBuf::from("/usr/local/bin/torchsight")] {
        if c.exists() { return Ok(c.clone()); }
    }
    Ok(PathBuf::from("torchsight"))
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

/// Export the last scan report as PDF using the CLI's report generator
#[tauri::command]
async fn export_pdf(save_path: String) -> Result<String, String> {
    let report_dir = std::env::temp_dir().join("torchsight-desktop");

    // Find the latest JSON report
    let entries = std::fs::read_dir(&report_dir).map_err(|e| e.to_string())?;
    let mut reports: Vec<_> = entries.filter_map(|e| e.ok())
        .filter(|e| {
            let n = e.file_name().to_string_lossy().to_string();
            n.starts_with("torchsight_report") && n.ends_with(".json")
        }).collect();
    reports.sort_by_key(|e| std::cmp::Reverse(e.metadata().ok().and_then(|m| m.modified().ok())));

    let json_path = reports.first()
        .ok_or("No scan report found. Run a scan first.")?
        .path();

    let binary = find_torchsight_binary()?;
    let save = save_path.clone();

    // The CLI's --format pdf writes to cwd, so we run it from a temp dir
    // then move the output to the user's chosen path
    let output = tokio::task::spawn_blocking(move || {
        // Use the CLI to generate PDF from the existing JSON report
        // The CLI reads the path arg and scans, but we already have results.
        // Instead, use uv + generate.py directly with the JSON file.

        // Find report/generate.py relative to the binary
        let mut script_path = None;
        if let Ok(exe) = std::env::current_exe() {
            for ancestor in exe.ancestors().skip(1) {
                let candidate = ancestor.join("report/generate.py");
                if candidate.exists() {
                    script_path = Some(candidate);
                    break;
                }
            }
        }
        // Also check relative to the CLI binary
        for ancestor in binary.ancestors().skip(1) {
            let candidate = ancestor.join("report/generate.py");
            if candidate.exists() {
                script_path = Some(candidate);
                break;
            }
        }

        let script = script_path.ok_or("Could not find report/generate.py. Make sure the TorchSight repo is available.")?;
        let project_dir = script.parent().unwrap();

        let result = Command::new("uv")
            .args([
                "run",
                "--project", project_dir.to_str().unwrap(),
                "python",
                script.to_str().unwrap(),
                json_path.to_str().unwrap(),
                "-o", &save,
            ])
            .output()
            .map_err(|e| format!("Failed to run uv: {}. Install with: curl -LsSf https://astral.sh/uv/install.sh | sh", e))?;

        if !result.status.success() {
            let stderr = String::from_utf8_lossy(&result.stderr);
            return Err(format!("PDF generation failed: {}", stderr.trim()));
        }

        Ok(save)
    })
    .await
    .map_err(|e| e.to_string())??;

    Ok(output)
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_shell::init())
        .invoke_handler(tauri::generate_handler![
            check_ollama, list_models, list_files, get_system_stats, scan_path, export_pdf,
        ])
        .run(tauri::generate_context!())
        .expect("error while running TorchSight desktop");
}
