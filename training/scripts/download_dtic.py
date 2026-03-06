"""
Download DTIC (Defense Technical Information Center) public reports.
Source: US Department of Defense (public domain — 17 U.S.C. § 105)

DTIC hosts technical reports, after-action reviews, and research papers
from all DoD organizations. Public (Distribution A) reports are freely
available and in the public domain.
"""

import json
import os
import time
import urllib.request
import urllib.parse

RAW_DIR = os.path.join(os.path.dirname(__file__), "..", "data", "raw")
OUTPUT_DIR = os.path.join(RAW_DIR, "dtic")

# Search terms for military/defense technical reports
SEARCH_TERMS = [
    "after action review operations",
    "tactical communications",
    "military intelligence analysis",
    "electronic warfare",
    "cyber operations defense",
    "unmanned systems",
    "force protection",
    "joint operations",
    "special operations",
    "information security classification",
]

MAX_PER_TERM = 30


def download():
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    existing = [f for f in os.listdir(OUTPUT_DIR) if f.endswith(".json")]
    if len(existing) > 10:
        print(f"[OK] DTIC reports already downloaded ({len(existing)} files)")
        return

    print("[>>] Downloading DTIC public defense reports...")
    print("     Note: DTIC search may require browser-based access for some docs.")

    total = 0

    for term in SEARCH_TERMS:
        print(f"     Searching: '{term}'...")
        reports = _search_dtic(term, MAX_PER_TERM)

        for report in reports:
            report_id = report.get("id", f"dtic_{total}")
            safe_id = str(report_id).replace("/", "_").replace(" ", "_")
            out_file = os.path.join(OUTPUT_DIR, f"dtic_{safe_id}.json")

            if os.path.exists(out_file):
                continue

            with open(out_file, "w") as f:
                json.dump(report, f, indent=2)
            total += 1

        time.sleep(2)

    print(f"[OK] {total} DTIC reports saved to {OUTPUT_DIR}")


def _search_dtic(query, max_results=30):
    """Search DTIC discover portal for public reports."""
    encoded = urllib.parse.quote(query)
    url = f"https://discover.dtic.mil/results/?q={encoded}&s=Relevance"

    reports = []
    try:
        req = urllib.request.Request(url)
        req.add_header("User-Agent", "TorchSight-Research/1.0 (academic)")

        with urllib.request.urlopen(req, timeout=30) as resp:
            html = resp.read().decode("utf-8", errors="ignore")

        import re
        # Parse DTIC search results
        # Look for report links and titles
        links = re.findall(
            r'href="(https://apps\.dtic\.mil/sti/citations/[^"]+)"[^>]*>\s*([^<]+)<',
            html,
            re.DOTALL
        )

        seen = set()
        for link, title in links:
            doc_id = link.split("/")[-1]
            if doc_id in seen:
                continue
            seen.add(doc_id)

            reports.append({
                "id": doc_id,
                "title": title.strip(),
                "url": link,
                "search_term": query,
                "source": "dtic",
                "license": "public_domain",
                "distribution": "A (public release)",
            })

            if len(reports) >= max_results:
                break

    except Exception as e:
        print(f"     [WARN] Search failed for '{query}': {e}")

    return reports


if __name__ == "__main__":
    download()
