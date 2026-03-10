"""
Download AlicanKiraz0/Cybersecurity-Dataset-Fenrir-v2.0 — cybersecurity dataset.
Source: AlicanKiraz0 (Apache 2.0)
"""

import json
import os

RAW_DIR = os.path.join(os.path.dirname(__file__), "..", "data", "raw")
OUTPUT = os.path.join(RAW_DIR, "fenrir")


def download():
    os.makedirs(OUTPUT, exist_ok=True)

    out_file = os.path.join(OUTPUT, "fenrir_v2.jsonl")
    if os.path.exists(out_file):
        print(f"[OK] Fenrir already downloaded at {out_file}")
        return

    from datasets import load_dataset

    print("[>>] Downloading AlicanKiraz0/Cybersecurity-Dataset-Fenrir-v2.0...")
    ds = load_dataset("AlicanKiraz0/Cybersecurity-Dataset-Fenrir-v2.0", split="train")

    print(f"[>>] Writing {len(ds)} examples to {out_file}...")
    with open(out_file, "w") as f:
        for row in ds:
            f.write(json.dumps(row, ensure_ascii=False) + "\n")

    print(f"[OK] Saved {len(ds)} examples to {out_file}")


if __name__ == "__main__":
    download()
