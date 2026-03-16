"""
Download ai4privacy/pii-masking-300k — 300K PII-labeled examples.
Source: ai4privacy (Apache 2.0)
"""

import json
import os

RAW_DIR = os.path.join(os.path.dirname(__file__), "..", "data", "raw")
OUTPUT = os.path.join(RAW_DIR, "ai4privacy")


def download():
    os.makedirs(OUTPUT, exist_ok=True)

    out_file = os.path.join(OUTPUT, "pii_masking_300k.jsonl")
    if os.path.exists(out_file):
        print(f"[OK] ai4privacy already downloaded at {out_file}")
        return

    from datasets import load_dataset

    print("[>>] Downloading ai4privacy/pii-masking-300k from HuggingFace...")
    ds = load_dataset("ai4privacy/pii-masking-300k", split="train")

    print(f"[>>] Writing {len(ds)} examples to {out_file}...")
    with open(out_file, "w") as f:
        for row in ds:
            f.write(json.dumps(row, ensure_ascii=False) + "\n")

    print(f"[OK] Saved {len(ds)} examples to {out_file}")


if __name__ == "__main__":
    download()
