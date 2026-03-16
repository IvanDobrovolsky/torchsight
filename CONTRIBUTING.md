# Contributing to TorchSight

## Getting Started

```bash
git clone https://github.com/torchsight/torchsight.git
cd torchsight

# Install dependencies (Rust, Tesseract, Ollama, Beam model)
./install.sh

# Or build manually
cargo build --release
```

Requirements: Rust 1.75+, Tesseract OCR, Ollama, `uv` (for PDF reports and model training).

## Project Structure

```
torchsight/
  core/          Rust CLI and scanner (src/)
  beam/          Beam model training pipeline (Python)
  desktop/       Tauri desktop application
  site/          Documentation website
  report/        PDF/HTML report generation
  install.sh     Cross-platform installer
```

## Development

```bash
# Run in dev mode
cargo run -- /path/to/scan

# Start the REPL
cargo run

# Run tests
cargo test

# Check for issues before committing
cargo fmt --check
cargo clippy -- -D warnings
```

Ollama must be running (`ollama serve`) and the Beam model pulled (`ollama pull torchsight/beam`) for integration testing.

## Pull Requests

Branch naming: `feat/description`, `fix/description`, `docs/description`.

Commit messages: imperative mood, lowercase, no period. Examples:
- `feat: add SARIF output format`
- `fix: handle empty PDF files in text analyzer`
- `docs: update training data source table`

Every PR should include:
- A clear description of what changed and why
- Test coverage for new functionality
- `cargo fmt` and `cargo clippy` passing with no warnings

## Reporting Issues

Include:
- Operating system and architecture (e.g., macOS ARM64, Ubuntu 22.04 x86\_64)
- Ollama version (`ollama --version`)
- Beam model version (q4\_K\_M or q8\_0)
- Steps to reproduce
- Actual vs. expected behavior
- Relevant logs or error output

## Code Style

- **Rust**: `cargo fmt` (default rustfmt config), `cargo clippy` with `-D warnings`
- **Python**: `ruff check` and `ruff format` (beam training scripts)
- **JavaScript/TypeScript**: Standard style (desktop and site)

No dead code. No `unwrap()` in production paths -- use proper error handling.

## License

All contributions are licensed under Apache 2.0. By submitting a pull request, you agree that your contribution is licensed under the same terms as the project.
