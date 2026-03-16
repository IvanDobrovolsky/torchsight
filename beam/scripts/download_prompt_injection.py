"""
Download prompt injection datasets from HuggingFace.
Sources:
  - deepset/prompt-injections (Apache 2.0)
  - geekyrakshit/prompt-injection-dataset (Apache 2.0)
"""

import json
import os

RAW_DIR = os.path.join(os.path.dirname(__file__), "..", "data", "raw")


def download():
    from datasets import load_dataset

    # 1. deepset/prompt-injections
    out_dir = os.path.join(RAW_DIR, "prompt_injection_deepset")
    out_file = os.path.join(out_dir, "data.jsonl")
    if os.path.exists(out_file):
        print(f"[OK] deepset/prompt-injections already downloaded")
    else:
        os.makedirs(out_dir, exist_ok=True)
        print("[>>] Downloading deepset/prompt-injections from HuggingFace...")
        ds = load_dataset("deepset/prompt-injections", split="train")
        with open(out_file, "w") as f:
            for row in ds:
                f.write(json.dumps(dict(row), ensure_ascii=False) + "\n")
        print(f"[OK] Saved {len(ds)} examples to {out_file}")

    # 2. geekyrakshit/prompt-injection-dataset
    out_dir2 = os.path.join(RAW_DIR, "prompt_injection_geekyrakshit")
    out_file2 = os.path.join(out_dir2, "data.jsonl")
    if os.path.exists(out_file2):
        print(f"[OK] geekyrakshit/prompt-injection-dataset already downloaded")
    else:
        os.makedirs(out_dir2, exist_ok=True)
        print("[>>] Downloading geekyrakshit/prompt-injection-dataset from HuggingFace...")
        ds2 = load_dataset("geekyrakshit/prompt-injection-dataset", split="train")
        with open(out_file2, "w") as f:
            for row in ds2:
                f.write(json.dumps(dict(row), ensure_ascii=False) + "\n")
        print(f"[OK] Saved {len(ds2)} examples to {out_file2}")


if __name__ == "__main__":
    download()
