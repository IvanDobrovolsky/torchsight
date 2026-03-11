# TorchSight — Next Steps

## Implemented

### Git Pre-Commit Hook ✅
```
torchsight git-hook install    # installs .git/hooks/pre-commit
torchsight git-hook uninstall  # removes the hook
torchsight git-hook scan       # called by the hook, scans staged files only
```
- Exit code 1 if critical/high findings → blocks commit
- Graceful degradation if Ollama is unreachable

### Diff Mode / Stdin Pipe ✅
```
cat file.txt | torchsight --stdin
torchsight --diff HEAD~1
```

### Policy Engine (YAML rules) ✅
```yaml
# .torchsight/policy.yml
block:
  - category: credentials
    severity: [critical, high]
  - category: malicious
warn:
  - category: pii
ignore:
  - safe*
```
`--fail-on` flag for CI exit codes: `torchsight /path --fail-on high`
`--policy` flag for custom policy file path

### SARIF Output Format ✅
```
torchsight /path --format sarif
```
SARIF 2.1.0 compliant output for GitHub Code Scanning integration.

### HTML Report with Interactive Dashboard ✅
```
torchsight /path --format html
```
Self-contained HTML file with severity/category charts, filterable/sortable table, dark theme.

### Watch Mode (File System Watcher) ✅
```
torchsight watch /path/to/dir --interval 5s
```
Uses `notify` crate with debouncing. Scans new/modified files as they appear.

### Config File (`.torchsight.toml`) ✅
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
CLI args override config file values.

### `.torchsightignore` ✅
Gitignore-style patterns to skip paths during scans. Supports:
- Directory names: `node_modules`
- Extension globs: `*.pyc`
- Path globs: `build/`
- Recursive globs: `**/*.test.js`

### Ollama Auto-Pull ✅
If model isn't installed, automatically `ollama pull` it before scanning.

---

## Remaining

### Parallel Scanning with Rayon
`rayon::par_iter` on file discovery for large directory scans.

### Structured Logging
`tracing` crate for production deployments — JSON output, file rotation.
Already has `tracing` + `tracing-subscriber` as dependencies.
