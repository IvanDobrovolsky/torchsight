"""
Download NVD (National Vulnerability Database) CVE feeds.
Source: NIST (public domain, US government)
Uses the NVD 2.0 API — no API key needed for low-rate requests.
"""

import json
import os
import time
import urllib.request

RAW_DIR = os.path.join(os.path.dirname(__file__), "..", "data", "raw")
OUTPUT_DIR = os.path.join(RAW_DIR, "nvd")

# NVD 2.0 API — paginated, 2000 per page, no key needed (6 req/min limit)
BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
MAX_PAGES = 5  # ~10K CVEs, enough for training data


def download():
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    existing = [f for f in os.listdir(OUTPUT_DIR) if f.endswith(".json")]
    if existing:
        print(f"[OK] NVD data already exists ({len(existing)} files)")
        return

    print("[>>] Downloading NVD CVE data via API...")

    start_index = 0
    page = 0

    while page < MAX_PAGES:
        url = f"{BASE_URL}?startIndex={start_index}&resultsPerPage=2000"
        print(f"     Page {page + 1}/{MAX_PAGES} (startIndex={start_index})")

        req = urllib.request.Request(url)
        req.add_header("User-Agent", "TorchSight-Research/1.0")

        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                data = json.loads(resp.read().decode())
        except Exception as e:
            print(f"     [WARN] Failed page {page + 1}: {e}")
            break

        out_file = os.path.join(OUTPUT_DIR, f"nvd_page_{page:03d}.json")
        with open(out_file, "w") as f:
            json.dump(data, f)

        total = data.get("totalResults", 0)
        fetched = len(data.get("vulnerabilities", []))
        print(f"     Got {fetched} CVEs (total available: {total})")

        if fetched == 0:
            break

        start_index += 2000
        page += 1

        # Rate limit: 6 requests per rolling 30s window without API key
        if page < MAX_PAGES:
            time.sleep(6)

    print(f"[OK] NVD data saved to {OUTPUT_DIR}")


if __name__ == "__main__":
    download()
