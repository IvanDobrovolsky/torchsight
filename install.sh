#!/usr/bin/env bash
set -euo pipefail

BOLD='\033[1m'
CYAN='\033[0;36m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
RED='\033[0;31m'
DIM='\033[2m'
RESET='\033[0m'

TEXT_MODEL="${TORCHSIGHT_TEXT_MODEL:-mistral}"
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
            sudo apt install -y tesseract-ocr tesseract-ocr-eng
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
        apt)
            curl -fsSL https://ollama.com/install.sh | sh
            ;;
        dnf)
            curl -fsSL https://ollama.com/install.sh | sh
            ;;
        brew)
            brew install ollama
            ;;
        *)
            warn "Unknown package manager. Trying ollama install script..."
            curl -fsSL https://ollama.com/install.sh | sh
            ;;
    esac

    ok "Ollama installed"
fi

# ── 4. Start Ollama service ────────────────────────────────────────────────

if systemctl is-active --quiet ollama 2>/dev/null; then
    ok "Ollama service is running"
else
    info "Starting Ollama service..."
    # Try systemd first, fall back to background process
    if command -v systemctl &>/dev/null; then
        sudo systemctl start ollama 2>/dev/null || true
        sudo systemctl enable ollama 2>/dev/null || true
    fi

    # Verify or start manually
    if ! systemctl is-active --quiet ollama 2>/dev/null; then
        info "Starting Ollama in background..."
        nohup ollama serve &>/dev/null &
        sleep 2
    fi

    if curl -s http://localhost:11434/api/tags &>/dev/null; then
        ok "Ollama is running"
    else
        warn "Could not start Ollama automatically. Run 'ollama serve' manually."
    fi
fi

# ── 5. Pull the LLM model ─────────────────────────────────────────────────

info "Checking for text model: ${BOLD}$TEXT_MODEL${RESET}"

if ollama list 2>/dev/null | grep -q "$TEXT_MODEL"; then
    ok "Model '$TEXT_MODEL' already available"
else
    info "Pulling model '$TEXT_MODEL' (this may take a few minutes)..."
    ollama pull "$TEXT_MODEL"
    ok "Model '$TEXT_MODEL' ready"
fi

info "Checking for vision model: ${BOLD}$VISION_MODEL${RESET}"

if ollama list 2>/dev/null | grep -q "$VISION_MODEL"; then
    ok "Model '$VISION_MODEL' already available"
else
    info "Pulling model '$VISION_MODEL' (this may take a few minutes)..."
    ollama pull "$VISION_MODEL"
    ok "Model '$VISION_MODEL' ready"
fi

# ── 6. Build TorchSight ───────────────────────────────────────────────────

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

info "Building TorchSight (release mode)..."
cargo build --release 2>&1 | tail -1
ok "Built successfully"

# ── 7. Install binary ─────────────────────────────────────────────────────

INSTALL_DIR="$HOME/.local/bin"
mkdir -p "$INSTALL_DIR"
cp target/release/torchsight "$INSTALL_DIR/torchsight"

# Check if ~/.local/bin is in PATH
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
echo -e "    ${CYAN}torchsight${RESET}                    Interactive mode"
echo -e "    ${CYAN}torchsight /path/to/scan${RESET}      Direct scan"
echo -e "    ${CYAN}torchsight --fast-only .${RESET}      Pattern-only (no LLM)"
echo -e "    ${CYAN}torchsight --help${RESET}             All options"
echo ""
