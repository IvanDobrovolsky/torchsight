# TorchSight — Claude Code Context

## What This Is
On-premise cybersecurity scanner. Rust CLI + local LLMs (Ollama). Scans text/image/PDF files for sensitive data, credentials, malicious payloads, classified content. Apache 2.0.

## Architecture
- **Rust CLI** with interactive REPL (`src/cli/repl.rs`)
- **Beam model** (`torchsight/beam`) — custom LoRA fine-tune of Qwen 3.5 27B, uses `/api/chat` endpoint
- **Vision model** (`llama3.2-vision`) — describes images, uses `/api/generate` endpoint
- **Tesseract OCR** — extracts text from images (system binary, not Rust crate)
- **Image pipeline**: OCR text + vision description → beam deep analysis
- **Text pipeline**: read file (or pdftotext for PDFs) → truncate to 6000 chars → beam chat
- **Regex safety net** — 35 compiled patterns as fallback for attacks the LLM misses

## Key Files
- `src/main.rs` — CLI args, subcommands, health checks, entry point
- `src/config.rs` — `.torchsight.toml` config file loader
- `src/analyzers/text.rs` — text/PDF analysis, `parse_beam_findings()` parser
- `src/analyzers/image.rs` — OCR + vision + beam hybrid pipeline
- `src/llm/ollama.rs` — Ollama HTTP client (600s timeouts, auto-pull)
- `src/scanner/pipeline.rs` — file discovery, progress bar, error handling
- `src/scanner/discovery.rs` — file discovery, `.torchsightignore` support
- `src/cli/git_hook.rs` — pre-commit hook install/uninstall/scan
- `src/cli/watch.rs` — real-time file system watcher
- `src/cli/stdin.rs` — stdin pipe and git diff scanning
- `src/cli/policy.rs` — YAML policy engine (block/warn/ignore rules)
- `src/report/` — JSON, Markdown, Terminal, PDF, SARIF, HTML output
- `report/generate.py` — PDF report generator (called via `uv run`)
- `training/output/Modelfile` — Ollama model definition (system prompt must match training)
- `training/scripts/sft_converter.py` — SYSTEM_PROMPT is the source of truth
- `install.sh` — cross-platform installer (Linux + macOS)

## CI/DevOps Features
- **`--fail-on <severity>`** — exit code 1 if findings at/above threshold (for CI)
- **`--stdin`** — scan piped content: `cat file | torchsight --stdin`
- **`--diff <ref>`** — scan changed files since git ref: `torchsight --diff HEAD~1`
- **`--policy <path>`** — custom policy file (default: `.torchsight/policy.yml`)
- **`--format sarif`** — SARIF 2.1.0 output for GitHub Code Scanning
- **`--format html`** — self-contained HTML report with interactive dashboard
- **`git-hook install/uninstall/scan`** — pre-commit hook management
- **`watch <path> --interval 5s`** — real-time file system monitoring
- **`.torchsight.toml`** — config file (CLI args override)
- **`.torchsightignore`** — gitignore-style path exclusions
- **Auto-pull** — automatically `ollama pull` missing models

## Beam Model v1.0
- Qwen 3.5 27B (dense) + LoRA (r=128, alpha=256), 5 epochs, ~175K balanced samples from 18+ sources
- GGUFs in `training/output/`: `beam-1.0-q4_K_M.gguf` (~17GB), `beam-1.0-q8_0.gguf` (~28GB)
- q4_K_M = default (fits 32GB M1 Mac), q8_0 = higher quality (48GB+ GPU or 64GB Mac)
- Output: JSON arrays `[{category, subcategory, severity, explanation}]`
- Training GPU: H100 80GB PCIe (~55GB VRAM for LoRA training)

## Finding Enrichment (implemented)
- **Image findings** include `visual_description` from vision model and OCR text as evidence
- **Text findings** include `source_file` name and content preview as evidence
- **Safe image findings** include the vision description ("Image analyzed: <desc>. No sensitive content.")
- All findings carry `source_file` in `extracted_data` for traceability

## Current Status / Known Issues
- CPU inference is very slow (~6 min/file). Apple Silicon M1 Max = ~2-5 sec/file
- HuggingFace upload pending (org: `torchsight`, need write token)
- PDF reports generated via Python (`uv run`), requires `uv` installed
- Beam model sometimes generates repetitive filler after valid findings (hits num_predict 2048 limit)
- `parse_beam_findings` deduplicates by category:subcategory and skips "safe" entries when non-safe findings exist

## Build & Run
```bash
./install.sh                    # Full install (Rust, Tesseract, Ollama, model)
cargo build --release           # Just build
./target/release/torchsight     # Start REPL
./target/release/torchsight /path  # Scan directly
```

## Training Data Sources (all verified safe for AI training)
- **Public domain (US Gov):** Enron (FERC), NVD/NIST, CIA FOIA, CRS Reports, Army Doctrine, SEC EDGAR
- **Apache 2.0:** AI4Privacy (300K PII), Phishing Dataset, Fenrir v2.0 (cybersecurity), NIST Training, Prompt Injection (deepset + geekyrakshit)
- **MIT:** SecLists, PayloadsAllTheThings
- **Royalty-free:** MITRE ATT&CK
- **CC-BY 4.0:** GHSA (GitHub Security Advisories)
- **Research-free:** Loghub (system logs)
- **Excluded:** OWASP (CC-BY-SA ShareAlike risk), MTSamples (provenance unclear), Exploit-DB (GPL)

## Training
```bash
cd training
uv venv && source .venv/bin/activate
uv pip install requests tqdm datasets beautifulsoup4 lxml
python scripts/download_all.py              # Download all datasets
python scripts/processors/process_all.py    # Process raw → JSONL
python scripts/processors/synth_generator.py  # Generate synthetic data
python scripts/processors/hard_negatives_generator.py  # Hard negatives
python scripts/rebalance_dataset.py         # Balance dataset
python scripts/sft_converter.py             # Convert to SFT format
python scripts/train_lora.py                # Train LoRA
python scripts/export_gguf.py               # Export to GGUF
```
Compatible: trl 0.11.4 + transformers 4.45.2 + peft 0.13.2
