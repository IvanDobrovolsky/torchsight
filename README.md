<p align="center">
  <img src="assets/logo.svg" width="180" alt="TorchSight">
</p>

<h1 align="center">TorchSight</h1>

<p align="center">
  On-premise cybersecurity scanner powered by local LLMs.<br>
  Fully local. No cloud. No data leaves your machine.
</p>

<p align="center">
  <a href="#install">Install</a> &middot;
  <a href="#usage">Usage</a> &middot;
  <a href="#the-beam-model">Model</a> &middot;
  <a href="#training-data">Training Data</a> &middot;
  <a href="LICENSE">Apache 2.0</a>
</p>

---

TorchSight scans text files, images, and PDFs for sensitive data, security threats, and compliance violations using a custom fine-tuned LLM. Everything runs locally through [Ollama](https://ollama.com) — no API keys, no cloud, no data exfiltration.

### What it detects

| Category | Examples |
|----------|---------|
| **PII** | Names, SSNs, DOB, addresses, phone numbers, government IDs |
| **Credentials** | Passwords, API keys, tokens, private keys, connection strings |
| **Financial** | Credit cards, bank accounts, invoices, tax documents |
| **Medical / PHI** | Diagnoses, prescriptions, lab results, insurance records |
| **Confidential** | Classification markings, military documents, defense data, NDAs |
| **Malicious** | SQL injection, XSS, reverse shells, prompt injection, exploit code |

## Install

### Linux (recommended)

```bash
git clone https://github.com/IvanDobrovolsky/torchsight.git
cd torchsight
./install.sh
```

The installer handles Rust, Tesseract OCR, Ollama, model pulls, and builds the binary.

### macOS

```bash
brew install ollama tesseract rust
ollama serve &
ollama pull torchsight/beam
git clone https://github.com/IvanDobrovolsky/torchsight.git
cd torchsight && cargo build --release
cp target/release/torchsight /usr/local/bin/
```

### Windows

**Option A: WSL2 (recommended)**

```bash
wsl --install
# Inside WSL2, follow the Linux instructions above
```

**Option B: Native**

```powershell
winget install Rustlang.Rustup
winget install UB-Mannheim.TesseractOCR
winget install Ollama.Ollama
ollama pull torchsight/beam
git clone https://github.com/IvanDobrovolsky/torchsight.git
cd torchsight; cargo build --release
```

### Manual install (any platform)

```bash
# 1. Install Rust: https://rustup.rs
# 2. Install Ollama: https://ollama.com
# 3. Install Tesseract: https://github.com/tesseract-ocr/tesseract (optional, for image OCR)

ollama pull torchsight/beam              # Required: security classifier
ollama pull llama3.2-vision              # Optional: image analysis + interactive Q&A

git clone https://github.com/IvanDobrovolsky/torchsight.git
cd torchsight
cargo build --release
cp target/release/torchsight ~/.local/bin/
```

## Usage

TorchSight has two modes:

### Command mode (default)

Scan, get results, done. Fast — uses only the beam model (~4GB).

```bash
torchsight /path/to/scan                # Scan a file or directory
torchsight /path/to/scan <<< "n"        # Scan and exit (no interactive prompt)
```

### Interactive mode

Scan and then ask questions about the results in natural language. Loads an additional vision model (~4.9GB) for Q&A.

```bash
torchsight -i /path/to/scan             # Scan + Q&A
torchsight -i                           # Start REPL directly
```

In interactive mode you can ask things like:

```
torchsight> What sensitive data was found?
torchsight> Are there any credentials exposed?
torchsight> scan ~/Downloads
torchsight> Analyze my config files for leaked secrets
```

### Commands

| Command | Description |
|---------|-------------|
| `scan <path>` | Scan a file or directory |
| `scan` | Interactive scan wizard |
| `report` | Show findings from last scan |
| `save` | Save report (JSON / Markdown / PDF) |
| `history` | Show scan history |
| `help` | Show available commands |
| `exit` | Quit |

### CLI options

```
torchsight [OPTIONS] [PATH]

Options:
    -i, --interactive        Enable LLM-powered Q&A after scan
    --text-model <MODEL>     Text analysis model [default: torchsight/beam]
    --vision-model <MODEL>   Vision model [default: llama3.2-vision]
    --ollama-url <URL>       Ollama server URL [default: http://localhost:11434]
    --max-size-mb <MB>       Max file size to scan [default: 1024]
    --format <FMT>           Report format: json, markdown [default: json]
    -h, --help               Show help
    -V, --version            Show version
```

## How it works

```
File --> Discovery --> [OCR + Vision (images)] --> Beam LLM --> Findings --> Report (PDF/JSON/MD)
```

1. **Discovery** — recursively finds text files, images, and PDFs
2. **OCR** — Tesseract extracts text from images
3. **Vision** — llama3.2-vision describes image content
4. **Classification** — beam model analyzes every file and outputs structured JSON findings
5. **Report** — results displayed in terminal and saved as PDF, JSON, or Markdown

There are no regex patterns or keyword matching. Every file goes through the LLM.

## The beam model

[torchsight/beam](https://huggingface.co/torchsight/beam) is fine-tuned from Llama 3.1 8B Instruct on 105,000 security samples across 7 categories and 49 subcategories. It outputs structured JSON:

```json
[
  {
    "category": "pii",
    "subcategory": "pii.identity",
    "severity": "critical",
    "explanation": "Found personal identity information for John Smith and Social Security Number(s)"
  }
]
```

## Training data

All training data is from publicly available, commercially licensed sources:

| Source | License | Samples |
|--------|---------|---------|
| [NVD](https://nvd.nist.gov) (NIST) | Public Domain | 50,000 |
| Synthetic (generated) | Original | 22,200 |
| [OSSF Malicious Packages](https://github.com/ossf/malicious-packages) | Apache 2.0 | 5,000 |
| [SecLists](https://github.com/danielmiessler/SecLists) | MIT | 3,229 |
| [GitHub Security Advisories](https://github.com/advisories) | CC-BY-4.0 | 3,000 |
| [Enron Email Corpus](https://www.cs.cmu.edu/~enron/) | Public Domain (FERC) | 2,000 |
| [MTSamples](https://mtsamples.com) | CC0 | 2,000 |
| [MITRE ATT&CK](https://attack.mitre.org) | Apache 2.0 | 1,620 |
| [Deepset Prompt Injections](https://huggingface.co/datasets/deepset/prompt-injections) | Apache 2.0 | 263 |
| [CRS Reports](https://crsreports.congress.gov) | Public Domain | 156 |

See [training/README.md](training/README.md) for details on the training pipeline.

### Reproducing the dataset

```bash
cd training/scripts
python download_all.py      # Download public datasets
python sft_converter.py     # Convert to SFT format
python train_lora.py        # Fine-tune with LoRA
python export_gguf.py       # Export to GGUF
```

## Requirements

| Dependency | Purpose | Required |
|---|---|---|
| [Ollama](https://ollama.com) | LLM runtime | Yes |
| [torchsight/beam](https://huggingface.co/torchsight/beam) | Security classification | Yes |
| [Rust](https://rustup.rs) | Build from source | Yes |
| [Tesseract](https://github.com/tesseract-ocr/tesseract) | Image text extraction (OCR) | Optional |
| [llama3.2-vision](https://ollama.com/library/llama3.2-vision) | Image analysis + interactive Q&A | Optional |

## License

[Apache 2.0](LICENSE)
