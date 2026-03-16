"""
Download PayloadsAllTheThings — web attack payloads and bypass techniques.
Source: swisskyrepo (MIT license)
"""

import os
import subprocess

RAW_DIR = os.path.join(os.path.dirname(__file__), "..", "data", "raw")
OUTPUT = os.path.join(RAW_DIR, "PayloadsAllTheThings")


def download():
    os.makedirs(RAW_DIR, exist_ok=True)

    if os.path.exists(OUTPUT):
        print(f"[OK] PayloadsAllTheThings already cloned at {OUTPUT}")
        return

    print("[>>] Cloning PayloadsAllTheThings (shallow)...")
    subprocess.run(
        ["git", "clone", "--depth", "1",
         "https://github.com/swisskyrepo/PayloadsAllTheThings.git", OUTPUT],
        check=True,
    )
    print(f"[OK] PayloadsAllTheThings cloned to {OUTPUT}")


if __name__ == "__main__":
    download()
