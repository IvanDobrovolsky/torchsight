<p align="center">
  <img src="assets/logo.svg" width="180" alt="TorchSight">
</p>

<h1 align="center">TorchSight</h1>

<p align="center">
  On-premise security scanner powered by local LLMs.<br>
  Scans files for sensitive data, credentials, and threats. Nothing leaves your machine.
</p>

---

## Install

```bash
git clone https://github.com/IvanDobrovolsky/torchsight.git
cd torchsight && ./install.sh
```

<details>
<summary>macOS / Windows / manual install</summary>

**macOS**
```bash
brew install ollama tesseract rust
ollama pull torchsight/beam
cargo build --release && cp target/release/torchsight /usr/local/bin/
```

**Windows** — use [WSL2](https://learn.microsoft.com/en-us/windows/wsl/install) and follow the Linux instructions.

**Manual** — install [Rust](https://rustup.rs), [Ollama](https://ollama.com), and optionally [Tesseract](https://github.com/tesseract-ocr/tesseract). Then `ollama pull torchsight/beam` and `cargo build --release`.
</details>

## Usage

```bash
torchsight /path/to/scan              # scan and report
torchsight -i /path/to/scan           # scan + interactive Q&A (loads extra model ~4.9GB)
torchsight                            # start REPL
```

## What it detects

PII, credentials, financial records, medical data, classified/military documents, malicious payloads (injection, exploits, prompt injection, reverse shells), and more — across text, images, and PDFs.

## How it works

Every file goes through [torchsight/beam](https://huggingface.co/torchsight/beam), a Llama 3.1 8B model fine-tuned on 78K balanced security samples from 18 public datasets. No regex, no keyword matching — pure LLM classification. Images get OCR + vision analysis first. All local via [Ollama](https://ollama.com).

## Training data

78,358 samples from 18 verified sources. All public domain, Apache 2.0, MIT, CC-BY 4.0, or royalty-free. Zero gray-area licenses. See [training/](training/) for the full pipeline and dataset details.

## License

[Apache 2.0](LICENSE)
