"""
Download SecLists — injection payloads, fuzzing strings, attack patterns.
Source: Daniel Miessler (MIT license)
"""

import os
import subprocess

RAW_DIR = os.path.join(os.path.dirname(__file__), "..", "data", "raw")
OUTPUT = os.path.join(RAW_DIR, "SecLists")


def download():
    os.makedirs(RAW_DIR, exist_ok=True)

    if os.path.exists(OUTPUT):
        print(f"[OK] SecLists already cloned at {OUTPUT}")
        return

    print("[>>] Cloning SecLists (shallow, ~200MB)...")
    subprocess.run(
        ["git", "clone", "--depth", "1",
         "https://github.com/danielmiessler/SecLists.git", OUTPUT],
        check=True,
    )
    print(f"[OK] SecLists cloned to {OUTPUT}")


if __name__ == "__main__":
    download()
