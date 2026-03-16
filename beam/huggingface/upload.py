#!/usr/bin/env python3
"""Upload TorchSight security dataset to HuggingFace Hub."""

import shutil
from pathlib import Path
from huggingface_hub import HfApi, login

REPO_ID = "torchsight/security-dataset"
SFT_DIR = Path(__file__).parent.parent / "data" / "sft"
HF_DIR = Path(__file__).parent

def main():
    login()  # prompts for token if not cached

    api = HfApi()

    # Create dataset repo (no-op if exists)
    api.create_repo(repo_id=REPO_ID, repo_type="dataset", exist_ok=True)

    # Copy data files into HF structure
    data_dir = HF_DIR / "data"
    data_dir.mkdir(exist_ok=True)

    for fname in ["train_chatml.jsonl", "val_chatml.jsonl", "train_alpaca.jsonl", "val_alpaca.jsonl"]:
        src = SFT_DIR / fname
        dst = data_dir / fname
        if not dst.exists() or dst.stat().st_size != src.stat().st_size:
            print(f"Copying {fname}...")
            shutil.copy2(src, dst)

    # Upload everything
    print(f"\nUploading to {REPO_ID}...")
    api.upload_folder(
        folder_path=str(HF_DIR),
        repo_id=REPO_ID,
        repo_type="dataset",
        ignore_patterns=["upload.py", "__pycache__", "*.pyc"],
    )

    print(f"\nDone! https://huggingface.co/datasets/{REPO_ID}")

if __name__ == "__main__":
    main()
