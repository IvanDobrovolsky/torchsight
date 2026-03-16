#!/usr/bin/env python3
"""Download GitHub Security Advisories (GHSA) via the public API.

No authentication required for the public advisory database.
Covers supply chain attacks across npm, pypi, rubygems, go, etc.
"""

import json
import time
import urllib.request
from pathlib import Path

DATA_DIR = Path(__file__).resolve().parent.parent / "data" / "ghsa"
OUT_FILE = DATA_DIR / "advisories.jsonl"

# GitHub Advisory Database REST API (public, no auth)
API_URL = "https://api.github.com/advisories"
PER_PAGE = 100
MAX_PAGES = 30  # ~3000 advisories


def fetch_page(page: int) -> list:
    url = f"{API_URL}?per_page={PER_PAGE}&page={page}&type=reviewed"
    req = urllib.request.Request(url, headers={
        "Accept": "application/vnd.github+json",
        "User-Agent": "TorchSight-Dataset-Builder/1.0"
    })
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.loads(resp.read())
    except Exception as e:
        print(f"  Page {page} failed: {e}")
        return []


def main():
    DATA_DIR.mkdir(parents=True, exist_ok=True)

    # Resume support
    existing = 0
    if OUT_FILE.exists():
        existing = sum(1 for _ in open(OUT_FILE))
        if existing >= 2000:
            print(f"Already have {existing} advisories, skipping")
            return
        print(f"Resuming from {existing} existing advisories")

    mode = "a" if existing > 0 else "w"
    start_page = (existing // PER_PAGE) + 1
    total = existing

    with open(OUT_FILE, mode) as f:
        for page in range(start_page, MAX_PAGES + 1):
            advisories = fetch_page(page)
            if not advisories:
                print(f"  No more results at page {page}")
                break

            for adv in advisories:
                record = {
                    "ghsa_id": adv.get("ghsa_id", ""),
                    "cve_id": adv.get("cve_id", ""),
                    "summary": adv.get("summary", ""),
                    "description": adv.get("description", ""),
                    "severity": adv.get("severity", ""),
                    "cvss_score": (adv.get("cvss", {}) or {}).get("score"),
                    "cwe_ids": [c.get("cwe_id", "") for c in (adv.get("cwes", []) or [])],
                    "published_at": adv.get("published_at", ""),
                    "vulnerabilities": [
                        {
                            "package": (v.get("package", {}) or {}).get("name", ""),
                            "ecosystem": (v.get("package", {}) or {}).get("ecosystem", ""),
                            "vulnerable_range": v.get("vulnerable_version_range", ""),
                        }
                        for v in (adv.get("vulnerabilities", []) or [])
                    ],
                }
                f.write(json.dumps(record) + "\n")
                total += 1

            print(f"  Page {page}: {len(advisories)} advisories (total: {total})")
            time.sleep(1)  # Rate limiting

    print(f"\nDone! {total} advisories saved to {OUT_FILE}")


if __name__ == "__main__":
    main()
