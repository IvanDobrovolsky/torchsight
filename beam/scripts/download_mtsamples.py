"""
Download MTSamples medical transcription samples.
Source: mtsamples.com (free, publicly available)
Scraped datasets available on Kaggle — we use the CSV mirror.
"""

import os
import urllib.request

RAW_DIR = os.path.join(os.path.dirname(__file__), "..", "data", "raw")
OUTPUT = os.path.join(RAW_DIR, "mtsamples.csv")

# Kaggle public mirror (no auth needed for this direct link)
URL = "https://raw.githubusercontent.com/socd06/medical-nlp/master/data/mtsamples.csv"


def download():
    os.makedirs(RAW_DIR, exist_ok=True)

    if os.path.exists(OUTPUT):
        print(f"[OK] MTSamples already downloaded at {OUTPUT}")
        return

    print("[>>] Downloading MTSamples medical transcriptions...")
    urllib.request.urlretrieve(URL, OUTPUT)

    size_mb = os.path.getsize(OUTPUT) / (1024 * 1024)
    print(f"[OK] MTSamples saved ({size_mb:.1f} MB)")


if __name__ == "__main__":
    download()
