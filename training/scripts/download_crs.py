"""
Download CRS (Congressional Research Service) defense/military reports.
Source: US Congress (public domain — 17 U.S.C. § 105)

Uses EveryCRSReport.com CSV index to find defense/military reports,
then downloads their metadata JSON files.
CRS reports are US Government works — not subject to copyright.
"""

import csv
import io
import json
import os
import time
import urllib.request

RAW_DIR = os.path.join(os.path.dirname(__file__), "..", "data", "raw")
OUTPUT_DIR = os.path.join(RAW_DIR, "crs_reports")

# EveryCRSReport.com CSV listing of all reports
CSV_URL = "https://www.everycrsreport.com/reports.csv"

# Defense/military keywords to filter by
DEFENSE_KEYWORDS = [
    "defense", "military", "army", "navy", "air force", "marine corps",
    "nuclear weapon", "missile defense", "nato", "intelligence",
    "cybersecurity", "homeland security", "national security",
    "dod", "pentagon", "weapons", "special operations",
    "drone", "space force", "indo-pacific", "counterterrorism",
    "classified", "arms control", "chemical weapon", "biological weapon",
]

MAX_REPORTS = 200


def download():
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    existing = [f for f in os.listdir(OUTPUT_DIR) if f.endswith(".json") and not f.startswith("_")]
    if len(existing) > 20:
        print(f"[OK] CRS reports already downloaded ({len(existing)} files)")
        return

    print("[>>] Fetching CRS report index from EveryCRSReport.com...")

    req = urllib.request.Request(CSV_URL)
    req.add_header("User-Agent", "TorchSight-Research/1.0 (academic)")

    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            csv_text = resp.read().decode("utf-8", errors="ignore")
    except Exception as e:
        print(f"[WARN] Could not fetch CSV index: {e}")
        print("       Using fallback known reports list.")
        _save_fallback()
        return

    # Parse CSV and filter for defense/military reports
    reader = csv.DictReader(io.StringIO(csv_text))
    defense_reports = []

    for row in reader:
        title = row.get("title", "").lower()
        if any(kw in title for kw in DEFENSE_KEYWORDS):
            defense_reports.append(row)
            if len(defense_reports) >= MAX_REPORTS:
                break

    print(f"     Found {len(defense_reports)} defense/military reports")

    # Download metadata JSON for each report
    downloaded = 0
    for report in defense_reports:
        number = report.get("number", "").strip()
        if not number:
            continue

        safe_name = number.replace("/", "_").replace(" ", "_")
        out_file = os.path.join(OUTPUT_DIR, f"{safe_name}.json")

        if os.path.exists(out_file):
            downloaded += 1
            continue

        # Fetch metadata JSON
        meta_url = f"https://www.everycrsreport.com/reports/{number}.json"
        try:
            req = urllib.request.Request(meta_url)
            req.add_header("User-Agent", "TorchSight-Research/1.0 (academic)")
            with urllib.request.urlopen(req, timeout=15) as resp:
                data = json.loads(resp.read().decode())

            # Add our source metadata
            data["_torchsight"] = {
                "source": "crs_reports",
                "license": "public_domain",
                "legal_basis": "17 U.S.C. § 105 — US Government work",
            }

            with open(out_file, "w") as f:
                json.dump(data, f, indent=2)

            downloaded += 1
            if downloaded % 25 == 0:
                print(f"     Downloaded {downloaded}/{len(defense_reports)}")

            time.sleep(0.5)
        except Exception:
            continue

    print(f"[OK] {downloaded} CRS defense reports saved to {OUTPUT_DIR}")


def download_pdfs():
    """Download actual PDF content for existing CRS metadata files."""
    pdf_dir = os.path.join(OUTPUT_DIR, "pdfs")
    os.makedirs(pdf_dir, exist_ok=True)

    json_files = [f for f in os.listdir(OUTPUT_DIR) if f.endswith(".json") and not f.startswith("_")]
    if not json_files:
        print("[WARN] No CRS metadata files found. Run download() first.")
        return

    downloaded = 0
    skipped = 0
    failed = 0

    for jf in sorted(json_files):
        report_id = jf.replace(".json", "")
        pdf_path = os.path.join(pdf_dir, f"{report_id}.pdf")

        if os.path.exists(pdf_path):
            skipped += 1
            continue

        try:
            with open(os.path.join(OUTPUT_DIR, jf)) as f:
                data = json.load(f)
        except Exception:
            continue

        # Find PDF URL in latest version
        versions = data.get("versions", [])
        if not versions:
            continue

        pdf_url = None
        for fmt in versions[0].get("formats", []):
            if fmt.get("format") == "PDF" and fmt.get("url"):
                pdf_url = fmt["url"]
                break

        if not pdf_url:
            continue

        try:
            req = urllib.request.Request(pdf_url)
            req.add_header("User-Agent", "TorchSight-Research/1.0 (academic)")
            with urllib.request.urlopen(req, timeout=30) as resp:
                with open(pdf_path, "wb") as out:
                    out.write(resp.read())
            downloaded += 1
            if downloaded % 10 == 0:
                print(f"     Downloaded {downloaded} PDFs...")
            time.sleep(0.5)
        except Exception as e:
            failed += 1

    print(f"[OK] CRS PDFs: {downloaded} downloaded, {skipped} already existed, {failed} failed")
    print(f"     Saved to {pdf_dir}")


def _save_fallback():
    """Save a curated list of known defense CRS report numbers."""
    known = [
        {"number": "RL33110", "title": "Defense Primer: National Defense Strategy"},
        {"number": "IF10542", "title": "Defense Primer: The Department of Defense"},
        {"number": "R44039", "title": "The Defense Budget and the Budget Control Act"},
        {"number": "RL32492", "title": "Nuclear Weapons: Comprehensive Test Ban Treaty"},
        {"number": "R41129", "title": "Conventional Arms Transfers to Developing Nations"},
        {"number": "R46554", "title": "Intelligence Community Overview"},
        {"number": "IF11493", "title": "Defense Primer: Cyberspace Operations"},
        {"number": "R44891", "title": "Intelligence Authorization Legislation"},
        {"number": "IF10546", "title": "Defense Primer: Special Operations Forces"},
        {"number": "R46968", "title": "Hypersonic Weapons: Background and Issues for Congress"},
    ]
    with open(os.path.join(OUTPUT_DIR, "_known_reports.json"), "w") as f:
        json.dump(known, f, indent=2)
    print(f"[OK] Saved {len(known)} known defense report references")


if __name__ == "__main__":
    import sys
    if "--pdfs" in sys.argv:
        download_pdfs()
    else:
        download()
        download_pdfs()
