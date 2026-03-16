#!/bin/bash
set -e

# ============================================================
#  TorchSight Beam v1.0 — Full Training Pipeline
#  Target: Qwen 3.5 27B + LoRA → GGUF (q4_K_M + q8_0)
#  Run on: Vast.ai B200 / H100 / A100 (80GB+ VRAM)
# ============================================================

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
TRAINING_DIR="$SCRIPT_DIR"
REPO_DIR="$(dirname "$TRAINING_DIR")"

echo "============================================================"
echo "  TorchSight Beam v1.0 — Full Training Pipeline"
echo "============================================================"
echo ""
echo "  Training dir: $TRAINING_DIR"
echo "  GPU:          $(nvidia-smi --query-gpu=name,memory.total --format=csv,noheader 2>/dev/null || echo 'not detected')"
echo ""

# ------------------------------------------------------------
# Step 0: Create venv and install dependencies
# ------------------------------------------------------------
echo "[0/8] Setting up Python virtual environment..."

cd "$TRAINING_DIR"

if [ ! -d ".venv" ]; then
    python3 -m venv --system-site-packages .venv
fi
source .venv/bin/activate

pip install --upgrade pip wheel setuptools

# Core training deps (--system-site-packages inherits CUDA torch if present)
pip install transformers peft datasets accelerate bitsandbytes trl

# Data download/processing deps
pip install requests tqdm beautifulsoup4 lxml

# GGUF export deps
pip install sentencepiece protobuf

# Fix common Pillow version issue
pip install --upgrade Pillow

echo ""
echo "  Python: $(python --version)"
echo "  Torch:  $(python -c 'import torch; print(torch.__version__)')"
echo "  CUDA:   $(python -c 'import torch; print(torch.cuda.is_available())')"
echo ""

# ------------------------------------------------------------
# Step 1: Download all datasets
# ------------------------------------------------------------
echo "[1/8] Downloading datasets..."
cd "$TRAINING_DIR/scripts"
python download_all.py

# ------------------------------------------------------------
# Step 2: Process all real data
# ------------------------------------------------------------
echo ""
echo "[2/8] Processing real datasets..."
cd "$TRAINING_DIR/scripts/processors"
python process_all.py

# ------------------------------------------------------------
# Step 3: Generate synthetic data
# ------------------------------------------------------------
echo ""
echo "[3/8] Generating synthetic training data..."
python modern_attacks_generator.py
python hard_negatives_generator.py
python synth_generator.py

# ------------------------------------------------------------
# Step 4: Rebalance dataset
# ------------------------------------------------------------
echo ""
echo "[4/8] Rebalancing dataset..."
cd "$TRAINING_DIR/scripts"
python rebalance_dataset.py

# ------------------------------------------------------------
# Step 5: Convert to SFT format
# ------------------------------------------------------------
echo ""
echo "[5/8] Converting to SFT format..."
python sft_converter.py

# ------------------------------------------------------------
# Step 6: Train LoRA
# ------------------------------------------------------------
echo ""
echo "[6/8] Training LoRA on Qwen 3.5 27B..."
echo "  This will take 2-6 hours depending on GPU"
echo ""

NUM_GPUS=$(python -c "import torch; print(torch.cuda.device_count())" 2>/dev/null || echo "1")
VRAM_GB=$(python -c "import torch; print(int(torch.cuda.get_device_properties(0).total_mem / 1e9))" 2>/dev/null || echo "0")
TOTAL_VRAM=$((VRAM_GB * NUM_GPUS))

echo "  GPUs:  ${NUM_GPUS}x ${VRAM_GB}GB (${TOTAL_VRAM}GB total)"

if [ "$NUM_GPUS" -gt 1 ] && [ "$VRAM_GB" -gt 120 ]; then
    # Multi-GPU with 140GB+ VRAM (H200/B200) — max throughput
    echo "  Strategy: DDP across ${NUM_GPUS} GPUs (${VRAM_GB}GB each)"
    torchrun --nproc_per_node="$NUM_GPUS" train_lora.py \
        --batch-size 8 \
        --grad-accum 2 \
        --epochs 3 \
        --max-seq-length 1024
elif [ "$NUM_GPUS" -gt 1 ] && [ "$VRAM_GB" -gt 70 ]; then
    # Multi-GPU with 80GB VRAM (A100/H100)
    echo "  Strategy: DDP across ${NUM_GPUS} GPUs (${VRAM_GB}GB each)"
    torchrun --nproc_per_node="$NUM_GPUS" train_lora.py \
        --batch-size 3 \
        --grad-accum 4 \
        --epochs 3 \
        --max-seq-length 1024
elif [ "$VRAM_GB" -gt 120 ]; then
    echo "  Strategy: Single GPU, batch_size=8"
    python train_lora.py --batch-size 8 --max-seq-length 1024
elif [ "$VRAM_GB" -gt 70 ]; then
    echo "  Strategy: Single GPU, batch_size=4"
    python train_lora.py --batch-size 4 --max-seq-length 1024
else
    echo "  Strategy: Single GPU, QLoRA 4-bit"
    python train_lora.py --quantize 4bit --batch-size 4 --max-seq-length 1024
fi

# ------------------------------------------------------------
# Step 7: Export to GGUF (q4_K_M + q8_0)
# ------------------------------------------------------------
echo ""
echo "[7/8] Exporting to GGUF..."

# Install llama.cpp for GGUF conversion
if [ ! -d "$HOME/llama.cpp" ]; then
    echo "  Cloning llama.cpp..."
    git clone https://github.com/ggerganov/llama.cpp "$HOME/llama.cpp"
fi
pip install -r "$HOME/llama.cpp/requirements.txt" 2>/dev/null || true

python export_gguf.py --adapter "$TRAINING_DIR/output/torchsight-qwen-lora"

# ------------------------------------------------------------
# Step 8: Package into archive
# ------------------------------------------------------------
echo ""
echo "[8/8] Creating archive..."

ARCHIVE_DIR="$TRAINING_DIR/output/beam-1.0-release"
mkdir -p "$ARCHIVE_DIR"

# Copy GGUFs
cp "$TRAINING_DIR/output/beam-1.0-q4_K_M.gguf" "$ARCHIVE_DIR/" 2>/dev/null || true
cp "$TRAINING_DIR/output/beam-1.0-q8_0.gguf" "$ARCHIVE_DIR/" 2>/dev/null || true

# Copy Modelfile
cp "$TRAINING_DIR/output/Modelfile" "$ARCHIVE_DIR/" 2>/dev/null || true

# Copy training config for reference
cp "$TRAINING_DIR/output/torchsight-qwen-lora/training_config.json" "$ARCHIVE_DIR/" 2>/dev/null || true

# Create install instructions
cat > "$ARCHIVE_DIR/README.txt" << 'READMEEOF'
TorchSight Beam v1.0
====================
Base: Qwen 3.5 27B (dense) + LoRA fine-tune
Task: Cybersecurity document classification

Files:
  beam-1.0-q4_K_M.gguf  — Quantized 4-bit (~17GB) — fits 32GB Mac
  beam-1.0-q8_0.gguf    — Quantized 8-bit (~28GB) — 48GB+ GPU or 64GB Mac
  Modelfile              — Ollama model definition (defaults to q4_K_M)

Install:
  1. Install Ollama: https://ollama.ai
  2. Create the model:
     ollama create torchsight/beam -f Modelfile
  3. Test:
     ollama run torchsight/beam "Analyze this text for security issues"

For q8 quality (if you have enough RAM):
  Edit Modelfile, change the FROM line to: FROM ./beam-1.0-q8_0.gguf
  Then re-run: ollama create torchsight/beam -f Modelfile
READMEEOF

# Create tar archive
cd "$TRAINING_DIR/output"
tar -czf beam-1.0-release.tar.gz beam-1.0-release/

ARCHIVE_SIZE=$(du -sh beam-1.0-release.tar.gz | cut -f1)

echo ""
echo "============================================================"
echo "  Training Complete!"
echo "============================================================"
echo ""
echo "  Archive: $TRAINING_DIR/output/beam-1.0-release.tar.gz ($ARCHIVE_SIZE)"
echo ""
echo "  Contents:"
ls -lh "$ARCHIVE_DIR/"
echo ""
echo "  Download the archive and run:"
echo "    tar xzf beam-1.0-release.tar.gz"
echo "    cd beam-1.0-release"
echo "    ollama create torchsight/beam -f Modelfile"
echo ""
