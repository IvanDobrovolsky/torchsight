#!/usr/bin/env python3
"""Download OpenSSF malicious-packages dataset.

License: Apache 2.0
Source: https://github.com/ossf/malicious-packages
Contains advisory JSON files for known malicious npm/pypi/etc packages.
"""

import json
import os
import subprocess
from pathlib import Path

DATA_DIR = Path(__file__).resolve().parent.parent / "data" / "ossf_malicious"
REPO_DIR = DATA_DIR / "repo"


def main():
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    out_file = DATA_DIR / "advisories.jsonl"

    if out_file.exists():
        lines = sum(1 for _ in open(out_file))
        if lines > 100:
            print(f"Already have {lines} advisories, skipping")
            return

    # Shallow clone (only MAL directory has the advisories)
    if not REPO_DIR.exists():
        print("Shallow cloning ossf/malicious-packages (sparse checkout)...")
        subprocess.run([
            "git", "clone", "--depth", "1", "--filter=blob:none", "--sparse",
            "https://github.com/ossf/malicious-packages.git",
            str(REPO_DIR)
        ], check=True)
        subprocess.run(
            ["git", "sparse-checkout", "set", "malicious"],
            cwd=str(REPO_DIR), check=True
        )
    else:
        print("Repo already cloned, pulling latest...")
        subprocess.run(["git", "pull"], cwd=str(REPO_DIR), check=False)

    # Walk through osv/malicious directory for advisory JSONs
    mal_dir = REPO_DIR / "osv" / "malicious"
    if not mal_dir.exists():
        mal_dir = REPO_DIR / "malicious"
    if not mal_dir.exists():
        print(f"No advisory dir found at {mal_dir}")
        return

    count = 0
    with open(out_file, "w") as f:
        for root, dirs, files in os.walk(mal_dir):
            for fname in files:
                if not fname.endswith(".json"):
                    continue
                fpath = Path(root) / fname
                try:
                    with open(fpath) as jf:
                        adv = json.load(jf)
                    # Extract key fields
                    record = {
                        "id": adv.get("id", ""),
                        "summary": adv.get("summary", ""),
                        "details": adv.get("details", ""),
                        "aliases": adv.get("aliases", []),
                        "severity": (adv.get("database_specific", {}) or {}).get("severity", ""),
                        "affected": [],
                    }
                    for affected in adv.get("affected", []):
                        pkg = affected.get("package", {}) or {}
                        record["affected"].append({
                            "ecosystem": pkg.get("ecosystem", ""),
                            "name": pkg.get("name", ""),
                        })
                    f.write(json.dumps(record) + "\n")
                    count += 1
                except Exception as e:
                    pass

    print(f"Extracted {count} malicious package advisories to {out_file}")


if __name__ == "__main__":
    main()
