/// Platform-aware install hints for external tools.
pub fn install_hint(tool: &str) -> &'static str {
    match (tool, std::env::consts::OS) {
        ("tesseract", "macos") => "brew install tesseract",
        ("tesseract", "linux") => "sudo apt install tesseract-ocr",
        ("poppler", "macos") => "brew install poppler",
        ("poppler", "linux") => "sudo apt install poppler-utils",
        ("ollama", _) => "https://ollama.com/download",
        _ => "see project README",
    }
}

/// One-line system stats: CPU%, RAM%, GPU% (if available).
pub fn system_stats_oneliner() -> String {
    let cpu = cpu_percent();
    let ram = ram_percent();
    let gpu = gpu_percent();

    if gpu > 0.0 {
        format!("CPU {}% RAM {}% GPU {}%", cpu as u32, ram as u32, gpu as u32)
    } else {
        format!("CPU {}% RAM {}%", cpu as u32, ram as u32)
    }
}

fn cpu_percent() -> f64 {
    #[cfg(target_os = "macos")]
    {
        let ncpu = run_cmd("sysctl", &["-n", "hw.logicalcpu"])
            .and_then(|s| s.trim().parse::<f64>().ok())
            .unwrap_or(1.0);
        let total = run_cmd("ps", &["-A", "-o", "%cpu"])
            .map(|s| s.lines().skip(1).filter_map(|l| l.trim().parse::<f64>().ok()).sum::<f64>())
            .unwrap_or(0.0);
        (total / ncpu).min(100.0)
    }
    #[cfg(target_os = "linux")]
    {
        let stat = std::fs::read_to_string("/proc/loadavg").unwrap_or_default();
        let load1 = stat.split_whitespace().next()
            .and_then(|s| s.parse::<f64>().ok()).unwrap_or(0.0);
        let ncpu = std::fs::read_to_string("/proc/cpuinfo")
            .map(|s| s.matches("processor").count() as f64)
            .unwrap_or(1.0);
        ((load1 / ncpu) * 100.0).min(100.0)
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    { 0.0 }
}

fn ram_percent() -> f64 {
    #[cfg(target_os = "macos")]
    {
        let total = run_cmd("sysctl", &["-n", "hw.memsize"])
            .and_then(|s| s.trim().parse::<f64>().ok()).unwrap_or(1.0);
        let vm = run_cmd("vm_stat", &[]).unwrap_or_default();
        let page = 16384.0_f64;
        let free = (parse_vm_line(&vm, "Pages free")
            + parse_vm_line(&vm, "Pages inactive")
            + parse_vm_line(&vm, "Pages speculative")) * page;
        ((total - free) / total * 100.0).min(100.0)
    }
    #[cfg(target_os = "linux")]
    {
        let info = std::fs::read_to_string("/proc/meminfo").unwrap_or_default();
        let total = parse_meminfo_val(&info, "MemTotal");
        let avail = parse_meminfo_val(&info, "MemAvailable");
        if total > 0.0 { ((total - avail) / total * 100.0).min(100.0) } else { 0.0 }
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    { 0.0 }
}

fn gpu_percent() -> f64 {
    #[cfg(target_os = "macos")]
    {
        let output = run_cmd("ioreg", &["-r", "-d", "1", "-c", "IOAccelerator"]).unwrap_or_default();
        if let Some(idx) = output.find("Device Utilization %") {
            let after = &output[idx + "Device Utilization %".len()..];
            if let Some(eq) = after.find('=') {
                return after[eq + 1..].trim().chars()
                    .take_while(|c| c.is_ascii_digit() || *c == '.')
                    .collect::<String>()
                    .parse().unwrap_or(0.0);
            }
        }
        0.0
    }
    #[cfg(target_os = "linux")]
    {
        std::process::Command::new("nvidia-smi")
            .args(["--query-gpu=utilization.gpu", "--format=csv,noheader,nounits"])
            .output().ok()
            .and_then(|o| String::from_utf8_lossy(&o.stdout).trim().parse().ok())
            .unwrap_or(0.0)
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    { 0.0 }
}

#[cfg(target_os = "macos")]
fn run_cmd(cmd: &str, args: &[&str]) -> Option<String> {
    std::process::Command::new(cmd).args(args).output().ok()
        .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
}

#[cfg(target_os = "macos")]
fn parse_vm_line(vm: &str, key: &str) -> f64 {
    vm.lines().find(|l| l.contains(key))
        .and_then(|l| l.split(':').nth(1).and_then(|v| v.trim().trim_end_matches('.').parse().ok()))
        .unwrap_or(0.0)
}

#[cfg(target_os = "linux")]
fn parse_meminfo_val(info: &str, key: &str) -> f64 {
    info.lines().find(|l| l.starts_with(key))
        .and_then(|l| l.split_whitespace().nth(1).and_then(|v| v.parse().ok()))
        .unwrap_or(0.0)
}
