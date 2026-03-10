"""
Download ealvaradob/phishing-dataset — phishing email and SMS text.
Source: ealvaradob (Apache 2.0)
Downloads texts.json which contains email and SMS phishing examples.
"""

import json
import os

RAW_DIR = os.path.join(os.path.dirname(__file__), "..", "data", "raw")
OUTPUT = os.path.join(RAW_DIR, "phishing")


def download():
    os.makedirs(OUTPUT, exist_ok=True)

    out_file = os.path.join(OUTPUT, "phishing_texts.jsonl")
    if os.path.exists(out_file):
        print(f"[OK] phishing texts already downloaded at {out_file}")
        return

    from huggingface_hub import hf_hub_download

    print("[>>] Downloading ealvaradob/phishing-dataset texts.json...")
    downloaded = hf_hub_download(
        repo_id="ealvaradob/phishing-dataset",
        filename="texts.json",
        repo_type="dataset",
    )

    print("[>>] Converting to JSONL...")
    with open(downloaded, "r") as f:
        data = json.load(f)

    count = 0
    with open(out_file, "w") as f:
        for row in data:
            f.write(json.dumps(row, ensure_ascii=False) + "\n")
            count += 1

    print(f"[OK] Saved {count} examples to {out_file}")


if __name__ == "__main__":
    download()
