<p align="center">
  <img src="assets/logo.svg" width="180" alt="TorchSight">
</p>

<h1 align="center">TorchSight</h1>

<p align="center">
  On-premise security scanner for text and image files.<br>
  Fully local. No cloud. No data leaves your machine.
</p>

<p align="center">
  <a href="#install">Install</a> &middot;
  <a href="#usage">Usage</a> &middot;
  <a href="docs/ARCHITECTURE.md">Architecture</a> &middot;
  <a href="docs/CORPUS.md">Training Corpus</a> &middot;
  <a href="LICENSE">Apache 2.0</a>
</p>

---

TorchSight scans files for sensitive data, security threats, and compliance violations using local LLMs via Ollama. It detects PII, credentials, financial records, medical data, classified documents, and malicious payloads — all without sending a single byte to the cloud.

### What it detects

| Category | Examples |
|----------|---------|
| **PII** | Names, SSNs, DOB, addresses, phone numbers, government IDs |
| **Credentials** | Passwords, API keys, tokens, private keys, connection strings |
| **Financial** | Credit cards, bank accounts, invoices, tax documents |
| **Medical** | Diagnoses, prescriptions, lab results, insurance records |
| **Confidential** | NDAs, contracts, classified markings, military documents |
| **Malicious** | SQL injection, XSS, reverse shells, exploits, obfuscated payloads |

### How it works

```
File → Tesseract OCR (images) → Vision Model (images) → Text Model → Findings + PDF Report
```

- **Tesseract OCR** extracts text from images
- **llama3.2-vision** describes image content
- **mistral:7b** performs deep security analysis on everything
- All models run locally through Ollama

## Install

```bash
git clone https://github.com/user/torchsight.git
cd torchsight
./install.sh
```

The installer handles Rust, Tesseract, Ollama, model pulls, and builds the binary.

### Manual install

```bash
# Prerequisites
cargo build --release
ollama pull mistral
ollama pull llama3.2-vision
sudo pacman -S tesseract tesseract-data-eng  # or apt/dnf/brew equivalent

# Install
cp target/release/torchsight ~/.local/bin/
```

## Usage

```bash
torchsight                          # Interactive mode
torchsight /path/to/scan            # Direct scan
torchsight --text-model mistral     # Custom text model
torchsight --vision-model llava     # Custom vision model
torchsight --help                   # All options
```

### Interactive commands

| Command | Description |
|---------|-------------|
| `scan` | Start interactive scan wizard |
| `scan <path>` | Scan a specific path |
| `report` | Show last scan findings |
| `save` | Save report (json/markdown) |
| `<question>` | Ask about scan results |
| `exit` | Quit |

## Training

TorchSight includes a training pipeline for fine-tuning custom security models. See [training/README.md](training/README.md).

```bash
cd training/scripts
python download_all.py    # Download public datasets (~5.5GB)
```

## Documentation

- [Architecture](docs/ARCHITECTURE.md) — system design, pipeline, detection categories
- [Training Corpus](docs/CORPUS.md) — datasets, label taxonomy, annotation schema

## License

[Apache 2.0](LICENSE)
