# TorchSight — Next Steps

## Priority 1: CI/DevOps Integration

### Git Pre-Commit Hook
Scan staged files before commit. Catches secrets/PII before they enter git history.
```
torchsight git-hook install    # installs .git/hooks/pre-commit
torchsight git-hook scan       # called by the hook, scans staged files only
```
- Exit code 1 if critical/high findings → blocks commit
- Direct comparison point vs detect-secrets in evaluations

### Diff Mode / Stdin Pipe
Scan only changed content, not entire files. Essential for CI pipelines.
```
git diff | torchsight scan --stdin
torchsight scan --diff HEAD~1
```

### Policy Engine (YAML rules)
User-defined policies for automated enforcement:
```yaml
# .torchsight/policy.yml
block:
  - category: credentials
    severity: [critical, high]
  - category: malicious
warn:
  - category: pii
ignore:
  - subcategory: safe.*
```
`--fail-on` flag for CI exit codes: `torchsight scan /path --fail-on high`

## Priority 2: Output & Reporting

### SARIF Output Format
SARIF (Static Analysis Results Interchange Format) is the standard for GitHub Code Scanning, VS Code, and other tools.
```
torchsight scan /path --format sarif
```
Findings appear directly as GitHub PR annotations.

### HTML Report with Interactive Dashboard
Self-contained HTML file — no Python dependency:
- Severity distribution charts
- Category breakdown pie chart
- Filterable/sortable findings table
- Inline JS/CSS, single file output

## Priority 3: Real-Time Monitoring

### Watch Mode (File System Watcher)
Monitor directories in real-time using `notify` crate:
```
torchsight watch /path/to/dir --interval 5s
```
Flags new/modified files as they appear. Useful for shared drives, upload folders, CI artifact directories.

## Priority 4: Performance & UX

### Parallel Scanning with Rayon
`rayon::par_iter` on file discovery for large directory scans. Scan thousands of files across all CPU cores simultaneously.

### Config File (`.torchsight.toml`)
Persistent settings instead of CLI flags:
```toml
[model]
text = "torchsight/beam"
vision = "llama3.2-vision"
ollama_url = "http://localhost:11434"

[scan]
max_size_mb = 1024
exclude = ["node_modules", ".git", "*.pyc"]
fail_on = "high"

[report]
format = "json"
auto_pdf = true
```

### `.torchsightignore`
Gitignore-style patterns to skip paths during scans.

### Ollama Auto-Pull
If model isn't installed, automatically `ollama pull` it before scanning.

### Structured Logging
`tracing` crate for production deployments — log levels, JSON output, file rotation.
