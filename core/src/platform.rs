/// Platform-aware install hints for external tools.
pub fn install_hint(tool: &str) -> &'static str {
    match (tool, std::env::consts::OS) {
        ("tesseract", "macos") => "brew install tesseract",
        ("tesseract", "linux") => "sudo apt install tesseract-ocr",
        ("poppler", "macos") => "brew install poppler",
        ("poppler", "linux") => "sudo apt install poppler-utils",
        ("ollama", _) => "https://ollama.com/download",
        _ => "see project README",
    }
}
