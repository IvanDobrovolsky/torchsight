"""
Download US military doctrinal publications via FAS (Federation of American Scientists).
Source: US Government (public domain — 17 U.S.C. § 105)

FAS mirrors publicly available Army, DoD, and Joint publications at irp.fas.org.
These include field manuals, doctrine publications, and regulations that contain
OPORD formats, tactical terminology, MGRS coordinate references, classification
marking procedures, and military communication standards.
"""

import json
import os
import re
import time
import urllib.request

RAW_DIR = os.path.join(os.path.dirname(__file__), "..", "data", "raw")
OUTPUT_DIR = os.path.join(RAW_DIR, "army_doctrine")

# FAS mirrors of military publications (all public domain US Gov works)
FAS_SECTIONS = [
    ("doddir/army", "Army doctrine, field manuals, regulations"),
    ("doddir/dod", "DoD directives and instructions"),
]

# Priority keywords — these are the publications most relevant to our taxonomy
PRIORITY_KEYWORDS = [
    # Army field manuals (various naming: fm5-0, fm5_0, fm-5-0)
    "fm5-0", "fm5_0", "fm6-0", "fm6_0", "fm6-99", "fm3-0", "fm3_0",
    "fm3-12", "fm3-13", "fm3-14", "fm3-90", "fm27-10",
    # Army doctrine publications
    "adp1", "adp2", "adp3", "adp5", "adp6",
    # Army techniques publications
    "atp2-01", "atp2-22", "atp3-09", "atp6-02",
    # Regulations
    "ar380", "ar381",
    # DoD directives
    "dodd5200", "dodi5200", "dodd5230",
    # Joint pubs
    "jp2-0", "jp3-0", "jp2_0", "jp3_0",
]

MAX_PDFS = 50  # Download up to 50 PDFs (most relevant ones)


def download():
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    existing_pdfs = [f for f in os.listdir(OUTPUT_DIR) if f.endswith(".pdf")]
    if len(existing_pdfs) > 10:
        print(f"[OK] Army doctrine already downloaded ({len(existing_pdfs)} PDFs)")
        return

    print("[>>] Downloading military doctrine from FAS (irp.fas.org)...")

    all_pdfs = []

    for section, desc in FAS_SECTIONS:
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
                    "description": desc,
                })

            print(f"     Found {len(pdfs)} publications in {section}")
        except Exception as e:
            print(f"     [WARN] Could not scan {section}: {e}")

    # Prioritize: download priority keyword matches first, then others
    priority = []
    others = []
    for pdf in all_pdfs:
        fname = pdf["filename"].lower()
        if any(kw in fname for kw in PRIORITY_KEYWORDS):
            priority.append(pdf)
        else:
            others.append(pdf)

    download_queue = priority + others[:MAX_PDFS - len(priority)]
    print(f"     Downloading {len(download_queue)} publications ({len(priority)} priority)...")

    # Save the full index
    index_file = os.path.join(OUTPUT_DIR, "doctrine_index.json")
    with open(index_file, "w") as f:
        json.dump({
            "total_available": len(all_pdfs),
            "downloaded": len(download_queue),
            "source": "irp.fas.org",
            "license": "public_domain",
            "legal_basis": "17 U.S.C. § 105 — US Government works",
            "publications": [p["filename"] for p in download_queue],
        }, f, indent=2)

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
                if len(data) > 1000:  # Skip tiny error pages
                    with open(out_file, "wb") as f:
                        f.write(data)
                    downloaded += 1

                    if downloaded % 10 == 0:
                        print(f"     Downloaded {downloaded}/{len(download_queue)}")

            time.sleep(0.5)
        except Exception:
            continue

    print(f"[OK] {downloaded} military doctrine PDFs saved to {OUTPUT_DIR}")


if __name__ == "__main__":
    download()
