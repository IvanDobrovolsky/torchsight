#!/usr/bin/env python3
"""
CRS Reports Processor for TorchSight Training

Downloads report PDFs, extracts text, classifies by defense topic,
and outputs labeled JSONL.

Targets: confidential.military, confidential.weapons_systems,
         confidential.nuclear, confidential.intelligence
"""

import json
import random
import re
import subprocess
import sys
import urllib.request
from pathlib import Path

RAW_DIR = Path(__file__).parent.parent.parent / "data" / "raw" / "crs_reports"
OUT_DIR = Path(__file__).parent.parent.parent / "data" / "processed"
PDF_DIR = RAW_DIR / "pdfs"

# Topic classification keywords
WEAPONS_KEYWORDS = [
    "missile", "icbm", "ssbn", "submarine", "destroyer", "ddg", "frigate", "ffg",
    "carrier", "cvn", "aircraft", "fighter", "bomber", "f-35", "f-22", "b-21",
    "ngad", "thaad", "patriot", "aegis", "bmd", "ballistic missile defense",
    "hypersonic", "lrhw", "directed energy", "laser", "munitions", "torpedo",
    "abrams", "bradley", "stryker", "javelin", "sentinel", "minuteman",
    "columbia-class", "virginia-class", "ford-class", "constellation-class",
]

NUCLEAR_KEYWORDS = [
    "nuclear", "warhead", "nonproliferation", "arms control", "icbm",
    "triad", "new start", "nnsa", "stockpile", "nc3", "cnwdi",
    "enrichment", "centrifuge", "plutonium", "uranium", "fissile",
]

INTELLIGENCE_KEYWORDS = [
    "intelligence community", "dni", "cia", "nsa", "dia", "nro", "nga",
    "fisa", "surveillance", "counterintelligence", "cybercom", "cyber command",
    "sigint", "humint", "imint", "osint", "declassification", "classified",
    "covert action", "espionage",
]

MILITARY_KEYWORDS = [
    "special operations", "sof", "socom", "combatant command", "eucom",
    "indopacom", "centcom", "africom", "southcom", "northcom", "spacecom",
    "force structure", "ndaa", "defense budget", "acquisition", "brac",
    "readiness", "recruiting", "retention", "mobilization", "deployment",
    "military construction", "defense industrial base", "dod",
]


def classify_report(title: str, summary: str = "") -> list[dict]:
    """Classify a CRS report into taxonomy subcategories."""
    text = (title + " " + summary).lower()
    findings = []

    # Check each category
    weapons_score = sum(1 for kw in WEAPONS_KEYWORDS if kw in text)
    nuclear_score = sum(1 for kw in NUCLEAR_KEYWORDS if kw in text)
    intel_score = sum(1 for kw in INTELLIGENCE_KEYWORDS if kw in text)
    military_score = sum(1 for kw in MILITARY_KEYWORDS if kw in text)

    if weapons_score >= 2:
        findings.append({
            "category": "confidential",
            "subcategory": "confidential.weapons_systems",
            "severity": "critical",
            "compliance": ["ITAR", "EO-13526"],
            "fields": {"matched_keywords": weapons_score},
        })

    if nuclear_score >= 2:
        findings.append({
            "category": "confidential",
            "subcategory": "confidential.nuclear",
            "severity": "critical",
            "compliance": ["10-CFR-1045", "EO-13526"],
            "fields": {"matched_keywords": nuclear_score},
        })

    if intel_score >= 2:
        findings.append({
            "category": "confidential",
            "subcategory": "confidential.intelligence",
            "severity": "critical",
            "compliance": ["EO-13526", "NIST-800-53"],
            "fields": {"matched_keywords": intel_score},
        })

    if military_score >= 2 or (not findings and any(
        kw in text for kw in ["defense", "military", "army", "navy", "air force", "marine"]
    )):
        findings.append({
            "category": "confidential",
            "subcategory": "confidential.military",
            "severity": "high",
            "compliance": ["NIST-800-53"],
            "fields": {"matched_keywords": military_score},
        })

    return findings


def download_pdf(url: str, dest: Path) -> bool:
    """Download a PDF from a URL."""
    if dest.exists():
        return True
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "TorchSight/1.0"})
        with urllib.request.urlopen(req, timeout=30) as resp:
            dest.write_bytes(resp.read())
        return True
    except Exception as e:
        print(f"  Failed to download {url}: {e}")
        return False


def extract_text_from_pdf(pdf_path: Path) -> str:
    """Extract text from PDF using pdftotext (poppler)."""
    try:
        result = subprocess.run(
            ["pdftotext", "-layout", str(pdf_path), "-"],
            capture_output=True, text=True, timeout=30,
        )
        return result.stdout[:5000]
    except FileNotFoundError:
        print("WARNING: pdftotext not found. Install poppler-utils.")
        return ""
    except Exception:
        return ""


def process(download_pdfs: bool = False, seed: int = 42):
    """Process CRS Reports into labeled JSONL."""
    random.seed(seed)
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    out_path = OUT_DIR / "crs_reports.jsonl"

    if not RAW_DIR.exists():
        print(f"ERROR: CRS data not found at {RAW_DIR}")
        sys.exit(1)

    all_samples = []
    counts = {}

    for json_file in sorted(RAW_DIR.glob("*.json")):
        try:
            with open(json_file) as f:
                data = json.load(f)
        except Exception:
            continue

        report_id = data.get("id", "")
        versions = data.get("versions", [])
        if not versions:
            continue

        # Use latest version
        latest = versions[0]
        title = latest.get("title", "")
        summary = latest.get("summary") or ""

        # Classify
        findings = classify_report(title, summary)
        if not findings:
            continue

        # Build text from available data
        text = f"CRS Report: {report_id}\n"
        text += f"Title: {title}\n"
        if summary:
            text += f"\n{summary[:4000]}"

        # Try to extract text from existing or newly downloaded PDF
        pdf_dest = PDF_DIR / f"{report_id}.pdf"
        if pdf_dest.exists():
            pdf_text = extract_text_from_pdf(pdf_dest)
            if pdf_text:
                text += f"\n\n{pdf_text}"
                # Re-classify with full text for better coverage
                findings = classify_report(title, text) or findings
        elif download_pdfs:
            PDF_DIR.mkdir(parents=True, exist_ok=True)
            for fmt in latest.get("formats", []):
                if fmt.get("format") == "PDF":
                    pdf_url = fmt.get("url", "")
                    if pdf_url and download_pdf(pdf_url, pdf_dest):
                        pdf_text = extract_text_from_pdf(pdf_dest)
                        if pdf_text:
                            text += f"\n\n{pdf_text}"
                            findings = classify_report(title, text) or findings
                    break

        for f in findings:
            counts[f["subcategory"]] = counts.get(f["subcategory"], 0) + 1

        all_samples.append({
            "report_id": report_id,
            "text": text,
            "findings": findings,
        })

    with open(out_path, "w") as fout:
        for i, sample in enumerate(all_samples):
            record = {
                "id": f"crs_{i:05d}",
                "source": "crs_reports",
                "source_license": "public_domain_usc105",
                "text": sample["text"],
                "findings": sample["findings"],
            }
            fout.write(json.dumps(record) + "\n")

    print(f"Wrote {len(all_samples):,} samples to {out_path}")
    print("\nCategory distribution:")
    for sub, count in sorted(counts.items()):
        print(f"  {sub}: {count}")
    print(f"\nNote: Only {sum(1 for s in all_samples if 'summary' in s.get('text', ''))} reports have summary text.")
    print("Run with --download-pdfs to fetch full report content.")


if __name__ == "__main__":
    do_download = "--download-pdfs" in sys.argv
    process(download_pdfs=do_download)
