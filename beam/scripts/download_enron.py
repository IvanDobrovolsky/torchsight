"""
Download and extract Enron Email Corpus.
Source: Carnegie Mellon (public domain, FERC release)
~1.7GB compressed, ~500K emails
"""

import os
import tarfile
import urllib.request
import sys

URL = "https://www.cs.cmu.edu/~enron/enron_mail_20150507.tar.gz"
RAW_DIR = os.path.join(os.path.dirname(__file__), "..", "data", "raw")
OUTPUT = os.path.join(RAW_DIR, "enron_mail_20150507.tar.gz")
EXTRACT_DIR = os.path.join(RAW_DIR, "enron")


def download():
    os.makedirs(RAW_DIR, exist_ok=True)

    if os.path.exists(EXTRACT_DIR):
        print(f"[OK] Enron already extracted at {EXTRACT_DIR}")
        return

    if not os.path.exists(OUTPUT):
        print(f"[>>] Downloading Enron corpus (~1.7GB)...")
        print(f"     {URL}")

        def progress(block, block_size, total):
            downloaded = block * block_size
            pct = downloaded * 100 / total if total > 0 else 0
            mb = downloaded / (1024 * 1024)
            sys.stdout.write(f"\r     {mb:.0f} MB ({pct:.1f}%)")
            sys.stdout.flush()

        urllib.request.urlretrieve(URL, OUTPUT, reporthook=progress)
        print("\n[OK] Download complete")
    else:
        print(f"[OK] Archive already exists at {OUTPUT}")

    print("[>>] Extracting...")
    with tarfile.open(OUTPUT, "r:gz") as tar:
        tar.extractall(path=RAW_DIR)

    os.rename(os.path.join(RAW_DIR, "maildir"), EXTRACT_DIR)
    print(f"[OK] Extracted to {EXTRACT_DIR}")


if __name__ == "__main__":
    download()
