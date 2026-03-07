#!/bin/bash
# Package everything needed for training into a single tarball.
# Upload this to Lambda/cloud GPU and run train.sh inside it.
#
# Usage:
#   ./package_training.sh
#   scp torchsight-training.tar.gz user@lambda-host:~/
#   ssh user@lambda-host 'tar xzf torchsight-training.tar.gz && cd torchsight-training && ./train.sh'

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
TRAINING_DIR="$(dirname "$SCRIPT_DIR")"
PACKAGE_DIR="/tmp/torchsight-training"

rm -rf "$PACKAGE_DIR"
mkdir -p "$PACKAGE_DIR/data"

echo "Packaging TorchSight training bundle..."

# Copy training data (SFT format — ready to train)
echo "  Copying training data..."
cp "$TRAINING_DIR/data/sft/train_chatml.jsonl" "$PACKAGE_DIR/data/"
cp "$TRAINING_DIR/data/sft/val_chatml.jsonl" "$PACKAGE_DIR/data/"

# Copy scripts
echo "  Copying scripts..."
cp "$SCRIPT_DIR/train_lora.py" "$PACKAGE_DIR/"
cp "$SCRIPT_DIR/export_gguf.py" "$PACKAGE_DIR/"
cp "$SCRIPT_DIR/eval_model.py" "$PACKAGE_DIR/"

# Create the self-contained train script that patches paths
cat > "$PACKAGE_DIR/train.sh" << 'TRAINEOF'
#!/bin/bash
set -e

echo "============================================"
echo "  TorchSight Training Setup"
echo "============================================"

# Install dependencies
pip install torch transformers peft datasets accelerate bitsandbytes trl scikit-learn tabulate

# Patch train_lora.py to use local data paths
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

export TORCHSIGHT_DATA_DIR="$SCRIPT_DIR/data"
export TORCHSIGHT_OUTPUT_DIR="$SCRIPT_DIR/output"

mkdir -p "$TORCHSIGHT_OUTPUT_DIR"

echo ""
echo "Data directory: $TORCHSIGHT_DATA_DIR"
echo "Output directory: $TORCHSIGHT_OUTPUT_DIR"
echo ""

# Full-precision LoRA on Llama 3.1 8B (tuned for 90GB VRAM cluster)
# All defaults are already maxed in train_lora.py — just pass overrides if needed
python3 "$SCRIPT_DIR/train_lora.py" \
    "$@"

echo ""
echo "Training complete! LoRA adapter saved to: $TORCHSIGHT_OUTPUT_DIR"
echo ""
echo "Running evaluation..."
python3 "$SCRIPT_DIR/eval_model.py" \
    --adapter "$TORCHSIGHT_OUTPUT_DIR/torchsight-llama-lora" \
    --val-data "$TORCHSIGHT_DATA_DIR/val_chatml.jsonl"

echo ""
echo "To export GGUF:"
echo "  python3 export_gguf.py --adapter ./output/torchsight-llama-lora"
TRAINEOF
chmod +x "$PACKAGE_DIR/train.sh"

# Create tarball
echo "  Creating tarball..."
cd /tmp
tar czf torchsight-training.tar.gz torchsight-training/

# Move to training dir
mv /tmp/torchsight-training.tar.gz "$TRAINING_DIR/"
rm -rf "$PACKAGE_DIR"

SIZE=$(du -h "$TRAINING_DIR/torchsight-training.tar.gz" | cut -f1)
echo ""
echo "Done! Package: $TRAINING_DIR/torchsight-training.tar.gz ($SIZE)"
echo ""
echo "Upload to Lambda:"
echo "  scp torchsight-training.tar.gz user@lambda-host:~/"
echo ""
echo "Then on Lambda:"
echo "  tar xzf torchsight-training.tar.gz"
echo "  cd torchsight-training"
echo "  ./train.sh"
echo ""
echo "Optional overrides:"
echo "  ./train.sh --base-model meta-llama/Llama-3.1-8B-Instruct"
echo "  ./train.sh --quantize 4bit --epochs 3 --lr 1e-4"
