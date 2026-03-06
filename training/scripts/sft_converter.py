#!/usr/bin/env python3
"""
TorchSight SFT Converter

Converts the combined training JSONL into prompt/completion pairs
suitable for supervised fine-tuning with LoRA/QLoRA.

Supports multiple output formats:
- alpaca: instruction/input/output (most common for LoRA)
- chatml: messages array (ChatML format)
- completion: simple prompt/completion pairs

Usage:
    python sft_converter.py                          # Default: alpaca format
    python sft_converter.py --format chatml           # ChatML format
    python sft_converter.py --format completion       # Simple completion
    python sft_converter.py --max-length 2048         # Truncate long texts
    python sft_converter.py --val-split 0.05          # 5% validation split
"""

import json
import random
import sys
from pathlib import Path
from typing import Any

SCRIPT_DIR = Path(__file__).resolve().parent
DATA_DIR = SCRIPT_DIR.parent / "data"
COMBINED_PATH = DATA_DIR / "processed" / "combined_train.jsonl"
OUTPUT_DIR = DATA_DIR / "sft"

# System prompt for the model
SYSTEM_PROMPT = """You are TorchSight, a cybersecurity document classifier. Analyze the provided text and identify any security-relevant findings.

For each finding, output a JSON object with:
- category: one of [pii, credentials, financial, medical, confidential, malicious, safe]
- subcategory: specific type (e.g., pii.identity, malicious.injection, credentials.api_key)
- severity: one of [critical, high, medium, low, info]
- explanation: brief explanation of what was found

If the text is clean/safe, output a finding with category "safe" and appropriate subcategory.

Respond ONLY with a JSON array of findings."""

# Instruction templates (randomly selected for variety)
INSTRUCTION_TEMPLATES = [
    "Analyze the following text for security threats, sensitive data, and policy violations.",
    "Classify the security content in this document.",
    "Scan this text and identify any sensitive information, credentials, or malicious content.",
    "Review the following content for security findings.",
    "Identify any PII, credentials, malicious payloads, or classified information in this text.",
    "Perform a security analysis of this document.",
    "Examine this content for data leakage, threats, and compliance issues.",
]


def format_findings_output(findings: list[dict]) -> str:
    """Format findings as the expected model output."""
    output_findings = []
    for f in findings:
        entry = {
            "category": f.get("category", "unknown"),
            "subcategory": f.get("subcategory", "unknown"),
            "severity": f.get("severity", "medium"),
        }
        # Include explanation if available
        if f.get("explanation"):
            entry["explanation"] = f["explanation"]
        elif f.get("evidence"):
            entry["explanation"] = f"Found: {f['evidence'][:150]}"
        else:
            entry["explanation"] = f"Detected {entry['subcategory']} content."
        output_findings.append(entry)
    return json.dumps(output_findings, indent=2)


def truncate_text(text: str, max_length: int) -> str:
    """Truncate text to max_length characters, breaking at word boundary."""
    if len(text) <= max_length:
        return text
    truncated = text[:max_length]
    # Break at last space
    last_space = truncated.rfind(" ")
    if last_space > max_length * 0.7:
        truncated = truncated[:last_space]
    return truncated + "\n[...truncated...]"


def convert_alpaca(record: dict, max_length: int) -> dict:
    """Convert to Alpaca format: instruction/input/output."""
    text = truncate_text(record["text"], max_length)
    instruction = random.choice(INSTRUCTION_TEMPLATES)
    output = format_findings_output(record.get("findings", []))

    return {
        "instruction": instruction,
        "input": text,
        "output": output,
    }


def convert_chatml(record: dict, max_length: int) -> dict:
    """Convert to ChatML messages format."""
    text = truncate_text(record["text"], max_length)
    instruction = random.choice(INSTRUCTION_TEMPLATES)
    output = format_findings_output(record.get("findings", []))

    return {
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": f"{instruction}\n\n{text}"},
            {"role": "assistant", "content": output},
        ]
    }


def convert_completion(record: dict, max_length: int) -> dict:
    """Convert to simple prompt/completion format."""
    text = truncate_text(record["text"], max_length)
    instruction = random.choice(INSTRUCTION_TEMPLATES)
    output = format_findings_output(record.get("findings", []))

    prompt = f"### System:\n{SYSTEM_PROMPT}\n\n### User:\n{instruction}\n\n{text}\n\n### Assistant:\n"
    return {
        "prompt": prompt,
        "completion": output,
    }


def main():
    # Parse args
    fmt = "alpaca"
    max_length = 4096
    val_split = 0.05
    seed = 42

    args = sys.argv[1:]
    i = 0
    while i < len(args):
        if args[i] == "--format" and i + 1 < len(args):
            fmt = args[i + 1]
            i += 2
        elif args[i] == "--max-length" and i + 1 < len(args):
            max_length = int(args[i + 1])
            i += 2
        elif args[i] == "--val-split" and i + 1 < len(args):
            val_split = float(args[i + 1])
            i += 2
        elif args[i] == "--seed" and i + 1 < len(args):
            seed = int(args[i + 1])
            i += 2
        else:
            print(f"Unknown arg: {args[i]}")
            sys.exit(1)

    converters = {
        "alpaca": convert_alpaca,
        "chatml": convert_chatml,
        "completion": convert_completion,
    }

    if fmt not in converters:
        print(f"Unknown format: {fmt}. Available: {', '.join(converters.keys())}")
        sys.exit(1)

    convert_fn = converters[fmt]
    random.seed(seed)

    # Read all records
    print(f"Reading {COMBINED_PATH}...")
    records = []
    with open(COMBINED_PATH) as f:
        for line in f:
            line = line.strip()
            if line:
                records.append(json.loads(line))

    print(f"  Loaded {len(records):,} records")

    # Shuffle
    random.shuffle(records)

    # Split
    val_count = int(len(records) * val_split)
    train_records = records[val_count:]
    val_records = records[:val_count]

    print(f"  Train: {len(train_records):,} | Validation: {len(val_records):,}")

    # Convert
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    train_path = OUTPUT_DIR / f"train_{fmt}.jsonl"
    val_path = OUTPUT_DIR / f"val_{fmt}.jsonl"

    skipped = 0
    for split_name, split_records, out_path in [
        ("train", train_records, train_path),
        ("val", val_records, val_path),
    ]:
        with open(out_path, "w") as f:
            for record in split_records:
                if not record.get("findings"):
                    skipped += 1
                    continue
                converted = convert_fn(record, max_length)
                f.write(json.dumps(converted) + "\n")

        count = sum(1 for _ in open(out_path))
        print(f"  Wrote {count:,} samples to {out_path.name}")

    if skipped:
        print(f"  Skipped {skipped} records with no findings")

    # Stats
    print(f"\nOutput format: {fmt}")
    print(f"Max text length: {max_length}")
    print(f"Output directory: {OUTPUT_DIR}")

    # Show a sample
    print(f"\n{'=' * 60}")
    print("Sample output:")
    print(f"{'=' * 60}")
    sample = convert_fn(records[0], max_length)
    print(json.dumps(sample, indent=2)[:1000])


if __name__ == "__main__":
    main()
