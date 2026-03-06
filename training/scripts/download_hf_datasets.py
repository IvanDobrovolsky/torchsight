#!/usr/bin/env python3
"""Download prompt injection and phishing datasets from HuggingFace.

Uses the HuggingFace API directly (no datasets library required).
Downloads parquet files and converts to JSONL.
"""

import json
import urllib.request
import struct
import io
from pathlib import Path

DATA_DIR = Path(__file__).resolve().parent.parent / "data"

# HuggingFace datasets API endpoints
DATASETS = {
    "prompt_injection_deepset": {
        "repo": "deepset/prompt-injections",
        "config": "default",
        "splits": ["train", "test"],
        "max_rows": 5000,
    },
    "phishing_emails": {
        "repo": "zefang-liu/phishing-email-dataset",
        "config": "default",
        "splits": ["train"],
        "max_rows": 5000,
    },
}


def fetch_json(url: str) -> dict:
    req = urllib.request.Request(url, headers={"User-Agent": "TorchSight/1.0"})
    with urllib.request.urlopen(req, timeout=30) as resp:
        return json.loads(resp.read())


def download_parquet(url: str, dest: Path):
    """Download a file."""
    req = urllib.request.Request(url, headers={"User-Agent": "TorchSight/1.0"})
    with urllib.request.urlopen(req, timeout=120) as resp:
        with open(dest, "wb") as f:
            while True:
                chunk = resp.read(65536)
                if not chunk:
                    break
                f.write(chunk)


def fetch_rows_api(repo: str, split: str, config: str = "default", max_rows: int = 10000) -> list:
    """Fetch rows using HuggingFace rows API (returns JSON, no parquet needed)."""
    rows = []
    offset = 0
    batch_size = 100

    while offset < max_rows:
        url = f"https://datasets-server.huggingface.co/rows?dataset={repo}&config={config}&split={split}&offset={offset}&length={batch_size}"

        try:
            data = fetch_json(url)
            batch = data.get("rows", [])
            if not batch:
                break
            for item in batch:
                rows.append(item.get("row", item))
            offset += len(batch)
            if len(batch) < batch_size:
                break
        except Exception as e:
            print(f"    Error at offset {offset}: {e}")
            break

    return rows


def download_dataset(name: str, cfg: dict):
    dest_dir = DATA_DIR / name
    dest_dir.mkdir(parents=True, exist_ok=True)
    out_file = dest_dir / "data.jsonl"

    if out_file.exists():
        lines = sum(1 for _ in open(out_file))
        if lines > 100:
            print(f"  Already have {lines} rows in {out_file}, skipping")
            return

    repo = cfg["repo"]
    ds_config = cfg.get("config", "default")
    max_rows = cfg.get("max_rows", 10000)

    all_rows = []
    for split in cfg["splits"]:
        print(f"  Fetching {repo} split={split} config={ds_config}...")
        rows = fetch_rows_api(repo, split, config=ds_config, max_rows=max_rows)
        all_rows.extend(rows)
        print(f"    Got {len(rows)} rows")

    with open(out_file, "w") as f:
        for row in all_rows:
            f.write(json.dumps(row, default=str) + "\n")

    print(f"  Total: {len(all_rows)} rows saved to {out_file}")


def main():
    for name, cfg in DATASETS.items():
        print(f"\n=== {name} ===")
        download_dataset(name, cfg)

    print("\nDone!")


if __name__ == "__main__":
    main()
