"""
Download declassified intelligence documents.
Sources:
  - FAS Intelligence Resource Program (irp.fas.org): mirrors declassified docs
  - CIA Historical Collection references: public domain (US Gov)
All sources: US Government works — public domain (17 U.S.C. § 105)

The CIA FOIA site blocks automated access, so we use FAS mirrors
which host the same declassified documents in an accessible format.
"""

import json
import os
import re
import time
import urllib.request

RAW_DIR = os.path.join(os.path.dirname(__file__), "..", "data", "raw")
OUTPUT_DIR = os.path.join(RAW_DIR, "cia_foia")

# FAS intelligence resource pages with declassified documents
FAS_INTEL_PAGES = [
    ("offdocs", "Official intelligence community documents"),
    ("news", "Intelligence news and releases"),
    ("congress", "Congressional intelligence oversight"),
]

# CIA Historical Collections — metadata only (requires browser for docs)
CIA_COLLECTIONS = [
    {
        "collection": "President's Daily Brief (declassified)",
        "years": "1961-1969",
        "covers": ["confidential.intelligence", "confidential.classified"],
        "url": "https://www.cia.gov/readingroom/collection/presidents-daily-brief-1961-1969",
    },
    {
        "collection": "STARGATE (remote viewing program)",
        "years": "1972-1995",
        "covers": ["confidential.classified", "confidential.intelligence"],
        "url": "https://www.cia.gov/readingroom/collection/stargate",
    },
    {
        "collection": "Bay of Pigs",
        "years": "1960-1998",
        "covers": ["confidential.military", "confidential.intelligence"],
        "url": "https://www.cia.gov/readingroom/collection/bay-pigs-release",
    },
    {
        "collection": "National Intelligence Estimates on the Soviet Union",
        "years": "1946-1991",
        "covers": ["confidential.intelligence", "confidential.nuclear"],
        "url": "https://www.cia.gov/readingroom/collection/national-intelligence-estimates-soviet-union",
    },
    {
        "collection": "Cold War Intelligence",
        "years": "1947-1991",
        "covers": ["confidential.classified", "confidential.intelligence"],
        "url": "https://www.cia.gov/readingroom/collection/cold-war",
    },
    {
        "collection": "Vietnam Histories",
        "years": "1954-1975",
        "covers": ["confidential.military", "confidential.intelligence"],
        "url": "https://www.cia.gov/readingroom/collection/vietnam-histories",
    },
]

MAX_PDFS = 50


def download():
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    existing = [f for f in os.listdir(OUTPUT_DIR) if f.endswith(".pdf")]
    if len(existing) > 10:
        print(f"[OK] Intelligence documents already downloaded ({len(existing)} files)")
        return

    print("[>>] Downloading declassified intelligence documents from FAS...")

    # Save CIA collection references
    with open(os.path.join(OUTPUT_DIR, "_cia_collections.json"), "w") as f:
        json.dump(CIA_COLLECTIONS, f, indent=2)

    # Download from FAS intelligence resources
    all_pdfs = []
    for section, desc in FAS_INTEL_PAGES:
        url = f"https://irp.fas.org/{section}/"
        print(f"     Scanning {section}...")

        try:
            req = urllib.request.Request(url)
            req.add_header("User-Agent", "TorchSight-Research/1.0 (academic)")
            with urllib.request.urlopen(req, timeout=15) as resp:
                html = resp.read().decode("utf-8", errors="ignore")

            pdfs = re.findall(r'href="([^"]+\.pdf)"', html, re.IGNORECASE)
            for pdf in pdfs:
                if pdf.startswith("http"):
                    full_url = pdf
                else:
                    full_url = f"https://irp.fas.org/{section}/{pdf}"
                all_pdfs.append({
                    "url": full_url,
                    "filename": pdf.split("/")[-1],
                    "section": section,
                })

            print(f"     Found {len(pdfs)} documents in {section}")
        except Exception as e:
            print(f"     [WARN] Could not scan {section}: {e}")

    # Also scan the official documents index
    for sub in ["offdocs/int", "offdocs/pdd", "offdocs/nsc"]:
        url = f"https://irp.fas.org/{sub}/"
        try:
            req = urllib.request.Request(url)
            req.add_header("User-Agent", "TorchSight-Research/1.0 (academic)")
            with urllib.request.urlopen(req, timeout=15) as resp:
                html = resp.read().decode("utf-8", errors="ignore")
            pdfs = re.findall(r'href="([^"]+\.pdf)"', html, re.IGNORECASE)
            for pdf in pdfs:
                full_url = pdf if pdf.startswith("http") else f"https://irp.fas.org/{sub}/{pdf}"
                all_pdfs.append({
                    "url": full_url,
                    "filename": pdf.split("/")[-1],
                    "section": sub,
                })
        except Exception:
            continue

    # Download PDFs
    download_queue = all_pdfs[:MAX_PDFS]
    print(f"     Downloading {len(download_queue)} intelligence documents...")

    downloaded = 0
    for pdf in download_queue:
        out_file = os.path.join(OUTPUT_DIR, pdf["filename"])
        if os.path.exists(out_file):
            downloaded += 1
            continue

        try:
            req = urllib.request.Request(pdf["url"])
            req.add_header("User-Agent", "TorchSight-Research/1.0 (academic)")
            with urllib.request.urlopen(req, timeout=30) as resp:
                data = resp.read()
                if len(data) > 1000:
                    with open(out_file, "wb") as f:
                        f.write(data)
                    downloaded += 1

                    if downloaded % 10 == 0:
                        print(f"     Downloaded {downloaded}/{len(download_queue)}")

            time.sleep(0.5)
        except Exception:
            continue

    print(f"[OK] {downloaded} intelligence docs + {len(CIA_COLLECTIONS)} CIA collection refs saved to {OUTPUT_DIR}")


if __name__ == "__main__":
    download()
