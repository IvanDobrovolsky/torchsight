use anyhow::Result;
use chrono::Utc;
use console::style;

use super::builder::{ScanReport, Severity};

pub fn format_report(report: &ScanReport, format: &str) -> Result<String> {
    match format {
        "json" => Ok(serde_json::to_string_pretty(report)?),
        "markdown" => Ok(format_markdown(report)),
        "sarif" => Ok(format_sarif(report)),
        "html" => Ok(format_html(report)),
        _ => Ok(format_terminal(report)),
    }
}

pub fn format_sarif(report: &ScanReport) -> String {
    let mut results = Vec::new();
    let mut rules_map: std::collections::HashMap<String, serde_json::Value> =
        std::collections::HashMap::new();

    for file in &report.files {
        for finding in &file.findings {
            if finding.category == "safe" {
                continue;
            }

            let rule_id = format!("torchsight/{}", finding.category);

            rules_map.entry(rule_id.clone()).or_insert_with(|| {
                serde_json::json!({
                    "id": rule_id,
                    "shortDescription": { "text": finding.category },
                })
            });

            let level = match finding.severity {
                Severity::Critical | Severity::High => "error",
                Severity::Medium => "warning",
                Severity::Low | Severity::Info => "note",
            };

            results.push(serde_json::json!({
                "ruleId": rule_id,
                "level": level,
                "message": { "text": finding.description },
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": { "uri": file.path },
                        "region": { "startLine": 1 }
                    }
                }],
                "properties": {
                    "severity": format!("{}", finding.severity),
                    "source": finding.source,
                    "evidence": finding.evidence,
                }
            }));
        }
    }

    let rules: Vec<serde_json::Value> = rules_map.into_values().collect();

    let sarif = serde_json::json!({
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "torchsight",
                    "version": env!("CARGO_PKG_VERSION"),
                    "informationUri": "https://github.com/torchsight/torchsight",
                    "rules": rules
                }
            },
            "results": results
        }]
    });

    serde_json::to_string_pretty(&sarif).unwrap_or_default()
}

pub fn save_report(report: &ScanReport, format: &str) -> Result<String> {
    let timestamp = Utc::now().format("%Y-%m-%d_%H%M%S");

    match format {
        "pdf" => save_pdf(report, &timestamp.to_string()),
        _ => {
            let ext = match format {
                "json" => "json",
                "markdown" => "md",
                "sarif" => "sarif.json",
                "html" => "html",
                _ => "txt",
            };
            let filename = format!("torchsight_report_{}.{}", timestamp, ext);
            let content = format_report(report, format)?;
            std::fs::write(&filename, &content)?;
            Ok(filename)
        }
    }
}


fn save_pdf(report: &ScanReport, timestamp: &str) -> Result<String> {
    let filename = format!("torchsight_report_{}.pdf", timestamp);

    // Write JSON to temp file
    let tmp_json = std::env::temp_dir().join(format!("torchsight_{}.json", timestamp));
    let json_content = serde_json::to_string_pretty(report)?;
    std::fs::write(&tmp_json, &json_content)?;

    // Find the report generator script relative to the executable
    let report_script = find_report_script()?;

    // Call Python report generator
    let output = std::process::Command::new("uv")
        .args([
            "run",
            "--project",
            report_script
                .parent()
                .unwrap()
                .to_str()
                .unwrap(),
            "python",
            report_script.to_str().unwrap(),
            tmp_json.to_str().unwrap(),
            "-o",
            &filename,
        ])
        .output()?;

    // Clean up temp file
    let _ = std::fs::remove_file(&tmp_json);

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!("PDF generator failed: {}", stderr.trim());
    }

    Ok(filename)
}

fn find_report_script() -> Result<std::path::PathBuf> {
    // Compile-time project root (works in dev builds)
    let project_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let from_manifest = project_root.join("report/generate.py");
    if from_manifest.exists() {
        return Ok(from_manifest.canonicalize()?);
    }

    // Try relative to executable (installed binary)
    if let Ok(exe) = std::env::current_exe() {
        let candidates = [
            exe.parent()
                .unwrap_or(std::path::Path::new("."))
                .join("../report/generate.py"),
            exe.parent()
                .unwrap_or(std::path::Path::new("."))
                .join("../../report/generate.py"),
            exe.parent()
                .unwrap_or(std::path::Path::new("."))
                .join("../share/torchsight/report/generate.py"),
        ];
        for c in &candidates {
            if c.exists() {
                return Ok(c.canonicalize()?);
            }
        }
    }

    // Try relative to cwd (fallback)
    let cwd_candidates = [
        std::path::PathBuf::from("report/generate.py"),
        std::path::PathBuf::from("../report/generate.py"),
    ];
    for c in &cwd_candidates {
        if c.exists() {
            return Ok(c.canonicalize()?);
        }
    }

    anyhow::bail!(
        "Could not find report/generate.py. Make sure the report directory is present."
    )
}

fn format_html(report: &ScanReport) -> String {
    let json_data = serde_json::to_string(report).unwrap_or_default();
    let timestamp = report.timestamp.format("%Y-%m-%d %H:%M:%S UTC").to_string();

    // Collect severity and category counts
    let mut category_counts: std::collections::HashMap<String, usize> =
        std::collections::HashMap::new();
    for file in &report.files {
        for finding in &file.findings {
            if finding.category != "safe" {
                *category_counts
                    .entry(finding.category.clone())
                    .or_default() += 1;
            }
        }
    }

    let categories_json = serde_json::to_string(&category_counts).unwrap_or_default();

    format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>TorchSight Report — {timestamp}</title>
<style>
* {{ margin: 0; padding: 0; box-sizing: border-box; }}
body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, monospace; background: #0d1117; color: #c9d1d9; }}
.container {{ max-width: 1200px; margin: 0 auto; padding: 20px; }}
h1 {{ color: #58a6ff; margin-bottom: 5px; font-size: 1.8em; }}
.subtitle {{ color: #8b949e; margin-bottom: 20px; }}
.summary {{ display: flex; gap: 15px; margin-bottom: 25px; flex-wrap: wrap; }}
.card {{ background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 18px; min-width: 140px; text-align: center; }}
.card .num {{ font-size: 2em; font-weight: bold; }}
.card .label {{ color: #8b949e; font-size: 0.85em; margin-top: 4px; }}
.critical {{ color: #f85149; }} .high {{ color: #f0883e; }} .medium {{ color: #d29922; }} .low {{ color: #58a6ff; }} .info {{ color: #8b949e; }}
.charts {{ display: flex; gap: 20px; margin-bottom: 25px; flex-wrap: wrap; }}
.chart-box {{ background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 20px; flex: 1; min-width: 300px; }}
.chart-box h3 {{ color: #c9d1d9; margin-bottom: 15px; font-size: 1em; }}
.bar {{ display: flex; align-items: center; margin-bottom: 8px; }}
.bar-label {{ width: 120px; font-size: 0.85em; color: #8b949e; }}
.bar-fill {{ height: 20px; border-radius: 3px; min-width: 2px; transition: width 0.3s; }}
.bar-val {{ margin-left: 8px; font-size: 0.85em; }}
.controls {{ margin-bottom: 15px; display: flex; gap: 10px; flex-wrap: wrap; align-items: center; }}
.controls select, .controls input {{ background: #0d1117; color: #c9d1d9; border: 1px solid #30363d; border-radius: 5px; padding: 6px 10px; font-size: 0.9em; }}
.controls input {{ flex: 1; min-width: 200px; }}
table {{ width: 100%; border-collapse: collapse; background: #161b22; border: 1px solid #30363d; border-radius: 8px; overflow: hidden; }}
th {{ background: #1c2128; color: #8b949e; text-align: left; padding: 10px 12px; font-size: 0.85em; cursor: pointer; user-select: none; }}
th:hover {{ color: #c9d1d9; }}
td {{ padding: 10px 12px; border-top: 1px solid #21262d; font-size: 0.85em; }}
tr:hover td {{ background: #1c2128; }}
.badge {{ padding: 2px 8px; border-radius: 10px; font-size: 0.75em; font-weight: bold; text-transform: uppercase; }}
.badge.Critical {{ background: #f8514922; color: #f85149; }}
.badge.High {{ background: #f0883e22; color: #f0883e; }}
.badge.Medium {{ background: #d2992222; color: #d29922; }}
.badge.Low {{ background: #58a6ff22; color: #58a6ff; }}
.badge.Info {{ background: #8b949e22; color: #8b949e; }}
.evidence {{ color: #8b949e; max-width: 400px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }}
footer {{ text-align: center; color: #484f58; margin-top: 30px; padding: 15px; font-size: 0.8em; }}
</style>
</head>
<body>
<div class="container">
<h1>TorchSight Scan Report</h1>
<p class="subtitle">{timestamp} &middot; v{version}</p>

<div class="summary">
  <div class="card"><div class="num">{total_files}</div><div class="label">Files Scanned</div></div>
  <div class="card"><div class="num">{total_findings}</div><div class="label">Total Findings</div></div>
  <div class="card"><div class="num critical">{critical}</div><div class="label">Critical</div></div>
  <div class="card"><div class="num high">{high}</div><div class="label">High</div></div>
  <div class="card"><div class="num medium">{medium}</div><div class="label">Medium</div></div>
  <div class="card"><div class="num low">{low}</div><div class="label">Low</div></div>
  <div class="card"><div class="num info">{info_count}</div><div class="label">Info</div></div>
</div>

<div class="charts">
  <div class="chart-box">
    <h3>Severity Distribution</h3>
    <div id="severity-chart"></div>
  </div>
  <div class="chart-box">
    <h3>Category Breakdown</h3>
    <div id="category-chart"></div>
  </div>
</div>

<div class="controls">
  <select id="filter-severity"><option value="">All Severities</option><option>Critical</option><option>High</option><option>Medium</option><option>Low</option><option>Info</option></select>
  <select id="filter-category"><option value="">All Categories</option></select>
  <input type="text" id="filter-search" placeholder="Search findings...">
</div>

<table>
<thead><tr><th onclick="sortTable(0)">File</th><th onclick="sortTable(1)">Severity</th><th onclick="sortTable(2)">Category</th><th onclick="sortTable(3)">Description</th><th>Evidence</th></tr></thead>
<tbody id="findings-body"></tbody>
</table>

<footer>Generated by TorchSight v{version}</footer>
</div>

<script>
const DATA = {json_data};
const CATS = {categories_json};
const SCOLORS = {{Critical:'#f85149',High:'#f0883e',Medium:'#d29922',Low:'#58a6ff',Info:'#8b949e'}};
const SORDER = ['Critical','High','Medium','Low','Info'];

// Build rows
let rows = [];
DATA.files.forEach(f => {{
  f.findings.forEach(fin => {{
    if (fin.category === 'safe') return;
    rows.push({{ file: f.path, severity: fin.severity, category: fin.category, description: fin.description, evidence: fin.evidence || '' }});
  }});
}});

// Populate category filter
let catSel = document.getElementById('filter-category');
Object.keys(CATS).sort().forEach(c => {{ let o = document.createElement('option'); o.value = c; o.textContent = c; catSel.appendChild(o); }});

// Severity chart
let sevDiv = document.getElementById('severity-chart');
let sevCounts = {{}};
rows.forEach(r => sevCounts[r.severity] = (sevCounts[r.severity]||0)+1);
let maxSev = Math.max(...Object.values(sevCounts), 1);
SORDER.forEach(s => {{
  let c = sevCounts[s] || 0;
  sevDiv.innerHTML += `<div class="bar"><span class="bar-label">${{s}}</span><div class="bar-fill" style="width:${{c/maxSev*100}}%;background:${{SCOLORS[s]}}"></div><span class="bar-val">${{c}}</span></div>`;
}});

// Category chart
let catDiv = document.getElementById('category-chart');
let maxCat = Math.max(...Object.values(CATS), 1);
let catColors = ['#58a6ff','#f0883e','#d29922','#f85149','#3fb950','#bc8cff','#79c0ff','#ff7b72'];
Object.entries(CATS).sort((a,b)=>b[1]-a[1]).forEach(([k,v], i) => {{
  catDiv.innerHTML += `<div class="bar"><span class="bar-label">${{k}}</span><div class="bar-fill" style="width:${{v/maxCat*100}}%;background:${{catColors[i%catColors.length]}}"></div><span class="bar-val">${{v}}</span></div>`;
}});

function render(data) {{
  let tb = document.getElementById('findings-body');
  tb.innerHTML = '';
  data.forEach(r => {{
    tb.innerHTML += `<tr><td>${{r.file}}</td><td><span class="badge ${{r.severity}}">${{r.severity}}</span></td><td>${{r.category}}</td><td>${{r.description}}</td><td class="evidence">${{r.evidence}}</td></tr>`;
  }});
}}

function applyFilters() {{
  let sev = document.getElementById('filter-severity').value;
  let cat = document.getElementById('filter-category').value;
  let q = document.getElementById('filter-search').value.toLowerCase();
  let filtered = rows.filter(r => {{
    if (sev && r.severity !== sev) return false;
    if (cat && r.category !== cat) return false;
    if (q && !r.description.toLowerCase().includes(q) && !r.file.toLowerCase().includes(q) && !r.evidence.toLowerCase().includes(q)) return false;
    return true;
  }});
  render(filtered);
}}

document.getElementById('filter-severity').onchange = applyFilters;
document.getElementById('filter-category').onchange = applyFilters;
document.getElementById('filter-search').oninput = applyFilters;

let sortDir = [1,1,1,1,1];
function sortTable(col) {{
  let keys = ['file','severity','category','description','evidence'];
  let key = keys[col];
  sortDir[col] *= -1;
  if (key === 'severity') {{
    rows.sort((a,b) => (SORDER.indexOf(a.severity) - SORDER.indexOf(b.severity)) * sortDir[col]);
  }} else {{
    rows.sort((a,b) => a[key].localeCompare(b[key]) * sortDir[col]);
  }}
  applyFilters();
}}

render(rows);
</script>
</body>
</html>"#,
        timestamp = timestamp,
        version = env!("CARGO_PKG_VERSION"),
        total_files = report.files.len(),
        total_findings = report.total_findings(),
        critical = report.critical_count(),
        high = report.high_count(),
        medium = report.medium_count(),
        low = report.low_count(),
        info_count = report.info_count(),
        json_data = json_data,
        categories_json = categories_json,
    )
}

fn format_markdown(report: &ScanReport) -> String {
    let mut out = String::new();

    out.push_str(&format!(
        "# TorchSight Scan Report\n\n**Date:** {}\n\n",
        report.timestamp.format("%Y-%m-%d %H:%M:%S UTC")
    ));

    out.push_str(&format!(
        "**Summary:** {} findings ({} critical, {} high, {} medium, {} low, {} info)\n\n",
        report.total_findings(),
        report.critical_count(),
        report.high_count(),
        report.medium_count(),
        report.low_count(),
        report.info_count(),
    ));

    out.push_str("---\n\n");

    for file in &report.files {
        out.push_str(&format!("## {}\n\n", file.path));
        out.push_str(&format!(
            "- **Type:** {}\n- **Size:** {} bytes\n- **Findings:** {}\n\n",
            file.kind,
            file.size,
            file.findings.len()
        ));

        for finding in &file.findings {
            let icon = match finding.severity {
                Severity::Critical => "[CRITICAL]",
                Severity::High => "[HIGH]",
                Severity::Medium => "[MEDIUM]",
                Severity::Low => "[LOW]",
                Severity::Info => "[INFO]",
            };
            out.push_str(&format!(
                "- {} {} - {} (source: {})\n",
                icon, finding.category, finding.description, finding.source
            ));
            if !finding.evidence.is_empty() {
                out.push_str(&format!("  - Evidence: `{}`\n", finding.evidence));
            }

            if !finding.extracted_data.is_empty() {
                out.push_str("  - **Extracted Data:**\n");
                let mut keys: Vec<&String> = finding.extracted_data.keys().collect();
                keys.sort();
                for key in keys {
                    let label = key.replace('_', " ");
                    out.push_str(&format!(
                        "    - {}: `{}`\n",
                        label, finding.extracted_data[key]
                    ));
                }
            }
        }

        out.push('\n');
    }

    out
}

fn format_terminal(report: &ScanReport) -> String {
    let mut out = String::new();

    for file in &report.files {
        let has_issues = file.findings.iter().any(|f| f.category != "safe");

        if has_issues {
            out.push_str(&format!(
                "\n  {} ({})\n",
                style(&file.path).bold(),
                file.kind
            ));
        } else {
            out.push_str(&format!(
                "\n  {} ({}) {}\n",
                style(&file.path).dim(),
                file.kind,
                style("[CLEAN]").green().bold()
            ));
        }

        for finding in &file.findings {
            if finding.category == "safe" {
                // Show safe files with their summary
                let summary = finding
                    .extracted_data
                    .get("summary")
                    .or_else(|| finding.extracted_data.get("subject"))
                    .map(|s| s.as_str())
                    .unwrap_or(&finding.description);
                out.push_str(&format!("    {}\n", style(summary).dim()));
                continue;
            }

            let severity_str = match finding.severity {
                Severity::Critical => format!("{}", style("CRITICAL").red().bold()),
                Severity::High => format!("{}", style("HIGH").red()),
                Severity::Medium => format!("{}", style("MEDIUM").yellow().bold()),
                Severity::Low => format!("{}", style("LOW").yellow()),
                Severity::Info => format!("{}", style("INFO").dim()),
            };

            out.push_str(&format!(
                "    [{}] {} - {}\n",
                severity_str, finding.category, finding.description
            ));

            if !finding.evidence.is_empty() && finding.evidence != "[image content]" {
                out.push_str(&format!(
                    "           Evidence: {}\n",
                    style(&finding.evidence).dim()
                ));
            }

            if !finding.extracted_data.is_empty() {
                let mut keys: Vec<&String> = finding.extracted_data.keys().collect();
                keys.sort();
                for key in keys {
                    let label = key.replace('_', " ");
                    let value = &finding.extracted_data[key];
                    let colored_value = format!("{}", style(value).yellow());
                    out.push_str(&format!(
                        "           {}: {}\n",
                        style(label).dim(),
                        colored_value
                    ));
                }
            }
        }
    }

    out
}
