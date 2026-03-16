<p align="center">
  <img src="assets/logo.svg" width="180" alt="TorchSight">
</p>

<h1 align="center">TorchSight</h1>

<p align="center">
  Open-source security scanner and document classifier powered by local LLMs.<br>
  Nothing leaves your machine.
</p>

<p align="center">
  <a href="https://torchsight.dev">Website</a> ·
  <a href="docs/ARCHITECTURE.md">Architecture</a> ·
  <a href="beam/">Beam Model</a> ·
  <a href="CONTRIBUTING.md">Contributing</a>
</p>

---

## Install

```bash
git clone https://github.com/IvanDobrovolsky/torchsight.git
cd torchsight && ./install.sh
```

See [torchsight.dev](https://torchsight.dev) for platform-specific instructions.

## Usage

```bash
torchsight /path/to/scan              # scan and report
torchsight                            # interactive REPL
torchsight /path --format sarif       # SARIF output for CI
torchsight /path --fail-on high       # exit 1 if findings >= high
torchsight --diff HEAD~3              # scan git changes
torchsight git-hook install           # pre-commit hook
torchsight watch /path --interval 5s  # watch mode
cat file | torchsight --stdin         # pipe mode
```

## Desktop

Cross-platform desktop app built with [Tauri v2](https://v2.tauri.app).

```bash
cd desktop && npm install && npm run tauri build
```

## Project Structure

```
core/       Rust CLI + scanning engine
beam/       Beam model training pipeline
desktop/    Tauri v2 desktop app
site/       Documentation website
report/     Report templates
```

## License

[Apache 2.0](LICENSE)
