# TorchSight — Claude Code Context

## What This Is
On-premise cybersecurity scanner. Rust CLI + local LLMs (Ollama). Scans text/image/PDF files for sensitive data, credentials, malicious payloads, classified content. Apache 2.0.

## Architecture
- **Rust CLI** with interactive REPL (`src/cli/repl.rs`)
- **Beam model** (`torchsight/beam`) — custom LoRA fine-tune of Llama 3.1 8B, uses `/api/chat` endpoint
- **Vision model** (`llama3.2-vision`) — describes images, uses `/api/generate` endpoint
- **Tesseract OCR** — extracts text from images (system binary, not Rust crate)
- **Image pipeline**: OCR text + vision description → beam deep analysis
- **Text pipeline**: read file (or pdftotext for PDFs) → truncate to 6000 chars → beam chat
- **No regex** — pure LLM analysis for all classification

## Key Files
- `src/main.rs` — CLI args, health checks, entry point
- `src/analyzers/text.rs` — text/PDF analysis, `parse_beam_findings()` parser
- `src/analyzers/image.rs` — OCR + vision + beam hybrid pipeline
- `src/llm/ollama.rs` — Ollama HTTP client (600s timeouts for CPU compat)
- `src/scanner/pipeline.rs` — file discovery, progress bar, error handling
- `src/report/` — JSON, Markdown, Terminal, PDF output
- `report/generate.py` — PDF report generator (called via `uv run`)
- `training/output/Modelfile` — Ollama model definition (system prompt must match training)
- `training/scripts/sft_converter.py` — SYSTEM_PROMPT is the source of truth
- `install.sh` — cross-platform installer (Linux + macOS)

## Beam Model v1.0
- Llama 3.1 8B + LoRA (r=64, alpha=128), 3 epochs, 86K balanced samples
- Eval loss: 0.4227, test score: 9.5/10
- GGUFs in `training/output/`: `beam-1.0-f16.gguf` (15GB), `beam-1.0-q8.gguf` (8GB)
- Output: multiple JSON arrays `[{category, subcategory, severity, explanation}]`
- Known quirk: generates repetitive filler text after findings (hits num_predict 2048 limit)

## Current Status / Known Issues
- Vision description is computed but NOT included in final findings (wasted work)
- Findings lack rich detail — should include actual extracted values and document context
- CPU inference is very slow (~6 min/file). Apple Silicon M1 Max = ~2-5 sec/file
- HuggingFace upload pending (org: `torchsight`, need write token)
- PDF reports generated via Python (`uv run`), requires `uv` installed

## Build & Run
```bash
./install.sh                    # Full install (Rust, Tesseract, Ollama, model)
cargo build --release           # Just build
./target/release/torchsight     # Start REPL
./target/release/torchsight /path  # Scan directly
```

## Training
```bash
cd training
python scripts/rebalance_dataset.py    # Balance dataset
python scripts/sft_converter.py        # Convert to SFT format
python scripts/train_lora.py           # Train LoRA
python scripts/export_gguf.py          # Export to GGUF
```
Compatible: trl 0.11.4 + transformers 4.45.2 + peft 0.13.2
