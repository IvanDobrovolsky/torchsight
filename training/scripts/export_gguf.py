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
    python export_gguf.py --adapter ./output/torchsight-qwen-lora
    # Exports both q4_K_M (~17GB) and q8_0 (~28GB) for Qwen 3.5 27B
"""

import json
import os
import subprocess
import sys
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
OUTPUT_DIR = Path(os.environ.get("TORCHSIGHT_OUTPUT_DIR", SCRIPT_DIR.parent / "output"))


def parse_args():
    config = {
        "adapter": None,
        "quant": "q8_0",  # Default: q8 (~34GB for 32B model). Use f16 for max quality (~64GB)
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

    # Step 2: Convert to GGUF — export q4_K_M (32GB Mac) and q8_0 (48GB+ GPU / 64GB Mac)
    quant_levels = ["q4_K_M", "q8_0"]
    convert_script = find_llama_cpp() if not config.get("llama_cpp") else Path(config["llama_cpp"])

    if not (convert_script and convert_script.exists()):
        print(f"\n  WARNING: llama.cpp convert script not found.")
        print(f"  To convert manually:")
        print(f"    git clone https://github.com/ggerganov/llama.cpp")
        print(f"    cd llama.cpp && pip install -r requirements.txt")
        for q in quant_levels:
            gguf_path = merged_path.parent / f"beam-1.0-{q}.gguf"
            print(f"    python convert_hf_to_gguf.py {merged_path} --outtype {q} --outfile {gguf_path}")
        return

    gguf_paths = {}
    for i, quant in enumerate(quant_levels):
        gguf_path = merged_path.parent / f"beam-1.0-{quant}.gguf"
        gguf_paths[quant] = gguf_path
        print(f"\n[2.{i+1}/3] Converting to GGUF ({quant})...")
        subprocess.run([
            sys.executable, str(convert_script),
            str(merged_path),
            "--outtype", quant,
            "--outfile", str(gguf_path),
        ], check=True)

    # Step 3: Create Ollama Modelfile (points to q4_K_M — fits 32GB Mac)
    print(f"\n[3/3] Creating Ollama Modelfile...")
    default_gguf = gguf_paths["q4_K_M"]
    modelfile_path = merged_path.parent / "Modelfile"
    modelfile_content = f"""FROM {default_gguf}

SYSTEM \"\"\"You are TorchSight, a cybersecurity document classifier. Analyze the provided text and identify ALL security-relevant findings.

For each finding, output a JSON object with:
- category: one of [pii, credentials, financial, medical, confidential, malicious, safe]
- subcategory: specific type (e.g., pii.identity, malicious.injection, credentials.api_key)
- severity: one of [critical, high, medium, low, info]
- explanation: detailed explanation including specific values found (redact sensitive parts, e.g., SSN: 412-XX-7890, API key: sk_live_51HG...). Explain what was found, why it matters, and the risk.

If a document contains multiple types of sensitive data, return a finding for EACH one.
If the text is clean/safe, output a single finding with category "safe".

Respond ONLY with a JSON array of findings.\"\"\"

PARAMETER temperature 0.1
PARAMETER top_p 0.9
PARAMETER num_predict 2048
"""
    with open(modelfile_path, "w") as f:
        f.write(modelfile_content)

    print(f"\n{'=' * 60}")
    print(f"  Export Complete!")
    print(f"{'=' * 60}")
    for quant, path in gguf_paths.items():
        size_gb = path.stat().st_size / (1024**3) if path.exists() else 0
        print(f"\n  {quant}: {path} ({size_gb:.1f} GB)")
    print(f"\n  Modelfile: {modelfile_path}")
    print(f"\nTo use with Ollama (q4_K_M default, fits 32GB Mac):")
    print(f"  ollama create torchsight/beam -f {modelfile_path}")
    print(f"\nFor q8 quality (edit Modelfile FROM line to beam-1.0-q8_0.gguf):")
    print(f"  q8_0 (~28GB) — requires 48GB+ GPU or 64GB Mac")


if __name__ == "__main__":
    main()
