"""
Download OWASP Web Security Testing Guide payloads.
Source: OWASP Foundation (Apache 2.0 / CC-BY-SA)
"""

import os
import subprocess

RAW_DIR = os.path.join(os.path.dirname(__file__), "..", "data", "raw")
OUTPUT = os.path.join(RAW_DIR, "owasp-wstg")


def download():
    os.makedirs(RAW_DIR, exist_ok=True)

    if os.path.exists(OUTPUT):
        print(f"[OK] OWASP WSTG already cloned at {OUTPUT}")
        return

    print("[>>] Cloning OWASP Web Security Testing Guide...")
    subprocess.run(
        ["git", "clone", "--depth", "1",
         "https://github.com/OWASP/wstg.git", OUTPUT],
        check=True,
    )
    print(f"[OK] OWASP WSTG cloned to {OUTPUT}")


if __name__ == "__main__":
    download()
