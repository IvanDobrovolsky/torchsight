#!/usr/bin/env bash
set -euo pipefail

BOLD='\033[1m'
CYAN='\033[0;36m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
RED='\033[0;31m'
DIM='\033[2m'
RESET='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TEXT_MODEL="${TORCHSIGHT_TEXT_MODEL:-torchsight/beam}"
VISION_MODEL="${TORCHSIGHT_VISION_MODEL:-llama3.2-vision}"

info()  { echo -e "  ${CYAN}>>>${RESET} $1"; }
ok()    { echo -e "  ${GREEN}[OK]${RESET} $1"; }
warn()  { echo -e "  ${YELLOW}[WARN]${RESET} $1"; }
fail()  { echo -e "  ${RED}[FAIL]${RESET} $1"; exit 1; }

echo ""
echo -e "  ${BOLD}TorchSight Installer${RESET}"
echo -e "  ${DIM}On-Premise Security Scanner${RESET}"
echo ""

# ── 1. Check OS & package manager ──────────────────────────────────────────

detect_pm() {
    if command -v pacman &>/dev/null; then echo "pacman"
    elif command -v apt &>/dev/null; then echo "apt"
    elif command -v dnf &>/dev/null; then echo "dnf"
    elif command -v brew &>/dev/null; then echo "brew"
    else echo "unknown"
    fi
}

PM=$(detect_pm)
info "Detected package manager: ${BOLD}$PM${RESET}"

# ── 2. Install Rust if needed ──────────────────────────────────────────────

if command -v cargo &>/dev/null; then
    ok "Rust already installed ($(rustc --version))"
else
    info "Installing Rust via rustup..."
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
    source "$HOME/.cargo/env"
    ok "Rust installed ($(rustc --version))"
fi

# ── 3. Install Tesseract OCR ────────────────────────────────────────────────

if command -v tesseract &>/dev/null; then
    ok "Tesseract OCR already installed ($(tesseract --version 2>&1 | head -1))"
else
    info "Installing Tesseract OCR..."

    case "$PM" in
        pacman)
            sudo pacman -S --noconfirm tesseract tesseract-data-eng
            ;;
        apt)
            sudo apt update && sudo apt install -y tesseract-ocr tesseract-ocr-eng
            ;;
        dnf)
            sudo dnf install -y tesseract tesseract-langpack-eng
            ;;
        brew)
            brew install tesseract
            ;;
        *)
            warn "Install tesseract manually: https://github.com/tesseract-ocr/tesseract"
            ;;
    esac

    ok "Tesseract OCR installed"
fi

# ── 4. Install Ollama if needed ────────────────────────────────────────────

if command -v ollama &>/dev/null; then
    ok "Ollama already installed ($(ollama --version 2>/dev/null || echo 'installed'))"
else
    info "Installing Ollama..."

    case "$PM" in
        pacman)
            if command -v yay &>/dev/null; then
                yay -S --noconfirm ollama
            elif command -v paru &>/dev/null; then
                paru -S --noconfirm ollama
            else
                sudo pacman -S --noconfirm ollama
            fi
            ;;
        brew)
            brew install ollama
            ;;
        *)
            curl -fsSL https://ollama.com/install.sh | sh
            ;;
    esac

    ok "Ollama installed"
fi

# ── 5. Start Ollama service ────────────────────────────────────────────────

if curl -s http://localhost:11434/api/tags &>/dev/null; then
    ok "Ollama service is running"
else
    info "Starting Ollama service..."
    if command -v systemctl &>/dev/null; then
        sudo systemctl start ollama 2>/dev/null || true
        sudo systemctl enable ollama 2>/dev/null || true
    fi

    # Verify or start manually
    if ! curl -s http://localhost:11434/api/tags &>/dev/null; then
        info "Starting Ollama in background..."
        nohup ollama serve &>/dev/null &
        sleep 3
    fi

    if curl -s http://localhost:11434/api/tags &>/dev/null; then
        ok "Ollama is running"
    else
        warn "Could not start Ollama automatically. Run 'ollama serve' manually."
    fi
fi

# ── 6. Pull models ──────────────────────────────────────────────────────────

info "Setting up model: ${BOLD}$TEXT_MODEL${RESET}"

if ollama list 2>/dev/null | grep -q "$TEXT_MODEL"; then
    ok "Model '$TEXT_MODEL' already available"
else
    info "Pulling model '$TEXT_MODEL'..."
    ollama pull "$TEXT_MODEL"
    ok "Model '$TEXT_MODEL' ready"
fi

# Vision model is optional (for interactive mode)
info "Setting up vision model: ${BOLD}$VISION_MODEL${RESET} (optional, for interactive mode)"

if ollama list 2>/dev/null | grep -q "$VISION_MODEL"; then
    ok "Model '$VISION_MODEL' already available"
else
    info "Pulling model '$VISION_MODEL'..."
    ollama pull "$VISION_MODEL" || warn "Vision model pull failed. Interactive mode will be unavailable."
fi

# ── 7. Build TorchSight ───────────────────────────────────────────────────

cd "$SCRIPT_DIR"

info "Building TorchSight (release mode)..."
cargo build --release 2>&1 | tail -1
ok "Built successfully"

# ── 8. Install binary ─────────────────────────────────────────────────────

INSTALL_DIR="$HOME/.local/bin"
mkdir -p "$INSTALL_DIR"
cp target/release/torchsight "$INSTALL_DIR/torchsight"

if echo "$PATH" | grep -q "$INSTALL_DIR"; then
    ok "Installed to $INSTALL_DIR/torchsight"
else
    ok "Installed to $INSTALL_DIR/torchsight"
    warn "$INSTALL_DIR is not in your PATH. Add it:"
    echo ""
    echo -e "    ${DIM}echo 'export PATH=\"\$HOME/.local/bin:\$PATH\"' >> ~/.bashrc${RESET}"
    echo ""
fi

# ── Done ───────────────────────────────────────────────────────────────────

echo ""
echo -e "  ${GREEN}${BOLD}Installation complete!${RESET}"
echo ""
echo -e "  ${DIM}Usage:${RESET}"
echo -e "    ${CYAN}torchsight /path/to/scan${RESET}         Scan files"
echo -e "    ${CYAN}torchsight -i /path/to/scan${RESET}      Scan + interactive Q&A"
echo -e "    ${CYAN}torchsight${RESET}                       Start REPL"
echo -e "    ${CYAN}torchsight --help${RESET}                All options"
echo ""
