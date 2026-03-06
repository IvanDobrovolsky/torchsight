"""
Download MITRE ATT&CK dataset (STIX format).
Source: MITRE Corporation (Apache 2.0)
"""

import os
import subprocess

RAW_DIR = os.path.join(os.path.dirname(__file__), "..", "data", "raw")
OUTPUT = os.path.join(RAW_DIR, "mitre-cti")


def download():
    os.makedirs(RAW_DIR, exist_ok=True)

    if os.path.exists(OUTPUT):
        print(f"[OK] MITRE ATT&CK already cloned at {OUTPUT}")
        return

    print("[>>] Cloning MITRE ATT&CK CTI repo...")
    subprocess.run(
        ["git", "clone", "--depth", "1",
         "https://github.com/mitre/cti.git", OUTPUT],
        check=True,
    )
    print(f"[OK] MITRE ATT&CK cloned to {OUTPUT}")


if __name__ == "__main__":
    download()
