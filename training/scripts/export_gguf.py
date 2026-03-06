#!/usr/bin/env python3
"""
TorchSight GGUF Export

Merges LoRA adapter with base model and exports to GGUF format
for use with Ollama.

Requirements:
    pip install torch transformers peft
    # For GGUF conversion, llama.cpp must be installed:
    git clone https://github.com/ggerganov/llama.cpp && cd llama.cpp && make

Usage:
    python export_gguf.py --adapter ./output/torchsight-llama-lora
    python export_gguf.py --adapter ./output/torchsight-llama-lora --quant q4_k_m
"""

import json
import subprocess
import sys
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
OUTPUT_DIR = SCRIPT_DIR.parent / "output"


def parse_args():
    config = {
        "adapter": None,
        "quant": "q4_k_m",  # Good balance of quality/size
        "llama_cpp": None,  # Auto-detect
    }
    args = sys.argv[1:]
    i = 0
    while i < len(args):
        key = args[i].lstrip("-").replace("-", "_")
        if i + 1 < len(args):
            config[key] = args[i + 1]
            i += 2
        else:
            i += 1
    return config


def find_llama_cpp():
    """Find llama.cpp convert script."""
    candidates = [
        Path.home() / "llama.cpp" / "convert_hf_to_gguf.py",
        Path("/usr/local/bin/convert_hf_to_gguf.py"),
        Path("./llama.cpp/convert_hf_to_gguf.py"),
    ]
    for p in candidates:
        if p.exists():
            return p

    # Try to find via which
    try:
        result = subprocess.run(["which", "convert_hf_to_gguf.py"],
                                capture_output=True, text=True)
        if result.returncode == 0:
            return Path(result.stdout.strip())
    except Exception:
        pass

    return None


def main():
    config = parse_args()

    if not config["adapter"]:
        print("Usage: python export_gguf.py --adapter <path-to-lora-adapter>")
        print("\nExample:")
        print("  python export_gguf.py --adapter ./output/torchsight-llama-lora")
        sys.exit(1)

    adapter_path = Path(config["adapter"])
    if not adapter_path.exists():
        print(f"ERROR: Adapter not found at {adapter_path}")
        sys.exit(1)

    # Load training config to get base model
    training_config_path = adapter_path / "training_config.json"
    if training_config_path.exists():
        with open(training_config_path) as f:
            training_config = json.load(f)
        base_model = training_config.get("base_model")
    else:
        base_model = input("Base model name (e.g., meta-llama/Llama-3.2-3B-Instruct): ")

    print("=" * 60)
    print("  TorchSight GGUF Export")
    print("=" * 60)
    print(f"\nAdapter:    {adapter_path}")
    print(f"Base model: {base_model}")
    print(f"Quant:      {config['quant']}")

    # Step 1: Merge LoRA with base model
    merged_path = adapter_path.parent / f"{adapter_path.name}-merged"
    print(f"\n[1/3] Merging LoRA adapter with base model...")

    try:
        import torch
        from transformers import AutoModelForCausalLM, AutoTokenizer
        from peft import PeftModel
    except ImportError as e:
        print(f"Missing dependency: {e}")
        print("pip install torch transformers peft")
        sys.exit(1)

    tokenizer = AutoTokenizer.from_pretrained(base_model, trust_remote_code=True)
    model = AutoModelForCausalLM.from_pretrained(
        base_model,
        torch_dtype=torch.float16,
        device_map="cpu",
        trust_remote_code=True,
    )
    model = PeftModel.from_pretrained(model, str(adapter_path))
    model = model.merge_and_unload()

    print(f"  Saving merged model to {merged_path}")
    model.save_pretrained(str(merged_path))
    tokenizer.save_pretrained(str(merged_path))
    del model
    if torch.cuda.is_available():
        torch.cuda.empty_cache()

    # Step 2: Convert to GGUF
    print(f"\n[2/3] Converting to GGUF format...")
    gguf_path = merged_path.parent / f"torchsight-security-{config['quant']}.gguf"

    convert_script = find_llama_cpp() if not config.get("llama_cpp") else Path(config["llama_cpp"])

    if convert_script and convert_script.exists():
        subprocess.run([
            sys.executable, str(convert_script),
            str(merged_path),
            "--outtype", config["quant"],
            "--outfile", str(gguf_path),
        ], check=True)
    else:
        print(f"\n  WARNING: llama.cpp convert script not found.")
        print(f"  To convert manually:")
        print(f"    git clone https://github.com/ggerganov/llama.cpp")
        print(f"    cd llama.cpp && pip install -r requirements.txt")
        print(f"    python convert_hf_to_gguf.py {merged_path} --outtype {config['quant']} --outfile {gguf_path}")
        return

    # Step 3: Create Ollama Modelfile
    print(f"\n[3/3] Creating Ollama Modelfile...")
    modelfile_path = merged_path.parent / "Modelfile"
    modelfile_content = f"""FROM {gguf_path}

SYSTEM \"\"\"You are TorchSight, a cybersecurity document classifier. Analyze text for security threats, sensitive data, credentials, malicious content, and policy violations. Output findings as a JSON array with category, subcategory, severity, and explanation for each finding.\"\"\"

PARAMETER temperature 0.1
PARAMETER top_p 0.9
PARAMETER num_predict 2048
"""
    with open(modelfile_path, "w") as f:
        f.write(modelfile_content)

    print(f"\n{'=' * 60}")
    print(f"  Export Complete!")
    print(f"{'=' * 60}")
    print(f"\nGGUF model:  {gguf_path}")
    print(f"Modelfile:   {modelfile_path}")
    print(f"\nTo use with Ollama:")
    print(f"  ollama create torchsight/security -f {modelfile_path}")
    print(f"  ollama run torchsight/security")


if __name__ == "__main__":
    main()
