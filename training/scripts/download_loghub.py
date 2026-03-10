"""
Download logpai/loghub — system log datasets for anomaly detection research.
Source: logpai (free for research)
"""

import os
import subprocess

RAW_DIR = os.path.join(os.path.dirname(__file__), "..", "data", "raw")
OUTPUT = os.path.join(RAW_DIR, "loghub")


def download():
    os.makedirs(RAW_DIR, exist_ok=True)

    if os.path.exists(OUTPUT):
        print(f"[OK] loghub already cloned at {OUTPUT}")
        return

    print("[>>] Cloning logpai/loghub (shallow)...")
    subprocess.run(
        ["git", "clone", "--depth", "1",
         "https://github.com/logpai/loghub.git", OUTPUT],
        check=True,
    )
    print(f"[OK] loghub cloned to {OUTPUT}")


if __name__ == "__main__":
    download()
