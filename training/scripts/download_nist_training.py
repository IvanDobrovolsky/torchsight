"""
Download ethanolivertroy/nist-cybersecurity-training — NIST cybersecurity training materials.
Source: NIST / US Government (public domain)
"""

import json
import os

RAW_DIR = os.path.join(os.path.dirname(__file__), "..", "data", "raw")
OUTPUT = os.path.join(RAW_DIR, "nist_training")


def download():
    os.makedirs(OUTPUT, exist_ok=True)

    out_file = os.path.join(OUTPUT, "nist_cybersecurity_training.jsonl")
    if os.path.exists(out_file):
        print(f"[OK] NIST training already downloaded at {out_file}")
        return

    from datasets import load_dataset

    print("[>>] Downloading ethanolivertroy/nist-cybersecurity-training...")
    ds = load_dataset("ethanolivertroy/nist-cybersecurity-training", split="train")

    print(f"[>>] Writing {len(ds)} examples to {out_file}...")
    with open(out_file, "w") as f:
        for row in ds:
            f.write(json.dumps(row, ensure_ascii=False) + "\n")

    print(f"[OK] Saved {len(ds)} examples to {out_file}")


if __name__ == "__main__":
    download()
