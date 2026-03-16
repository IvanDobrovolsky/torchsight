"""
Download SEC EDGAR filings via eloukas/edgar-corpus HuggingFace dataset.
Source: US Government (public domain)
Downloads ~5000 samples from a single year's JSONL files.
"""

import json
import os

RAW_DIR = os.path.join(os.path.dirname(__file__), "..", "data", "raw")
OUTPUT = os.path.join(RAW_DIR, "edgar")

MAX_SAMPLES = 5000


def download():
    os.makedirs(OUTPUT, exist_ok=True)

    out_file = os.path.join(OUTPUT, "edgar_filings.jsonl")
    if os.path.exists(out_file):
        print(f"[OK] EDGAR corpus already downloaded at {out_file}")
        return

    from huggingface_hub import hf_hub_download

    # Download train.jsonl from 2020 (most recent year available)
    print("[>>] Downloading eloukas/edgar-corpus 2020/train.jsonl...")
    downloaded = hf_hub_download(
        repo_id="eloukas/edgar-corpus",
        filename="2020/train.jsonl",
        repo_type="dataset",
    )

    print(f"[>>] Extracting first {MAX_SAMPLES} samples...")
    count = 0
    with open(downloaded, "r") as fin, open(out_file, "w") as fout:
        for line in fin:
            line = line.strip()
            if not line:
                continue
            fout.write(line + "\n")
            count += 1
            if count % 1000 == 0:
                print(f"     {count}/{MAX_SAMPLES} samples...")
            if count >= MAX_SAMPLES:
                break

    print(f"[OK] Saved {count} examples to {out_file}")


if __name__ == "__main__":
    download()
