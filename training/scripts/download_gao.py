"""
Download GAO (Government Accountability Office) defense/nuclear reports.
Source: US Government (public domain — 17 U.S.C. § 105)

GAO publishes audit reports on defense programs, weapons systems,
nuclear enterprise, and intelligence community. All are public domain.
"""

import json
import os
import time
import urllib.request
import urllib.parse

RAW_DIR = os.path.join(os.path.dirname(__file__), "..", "data", "raw")
OUTPUT_DIR = os.path.join(RAW_DIR, "gao")

# GAO API endpoint for reports
GAO_API = "https://www.gao.gov/api/search"

# Defense/military/nuclear search terms
SEARCH_TERMS = [
    "nuclear weapons modernization",
    "missile defense",
    "weapons systems cost",
    "cybersecurity defense",
    "intelligence community",
    "special operations forces",
    "defense acquisition",
    "classified information protection",
    "nuclear security enterprise",
    "space force",
]

MAX_PER_TERM = 20


def download():
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    existing = [f for f in os.listdir(OUTPUT_DIR) if f.endswith(".json")]
    if len(existing) > 10:
        print(f"[OK] GAO reports already downloaded ({len(existing)} files)")
        return

    print("[>>] Downloading GAO defense/nuclear reports...")

    total = 0

    for term in SEARCH_TERMS:
        print(f"     Searching: '{term}'...")
        reports = _search_gao(term, MAX_PER_TERM)

        for report in reports:
            report_id = report.get("id", f"gao_{total}")
            safe_id = str(report_id).replace("/", "_").replace(" ", "_")
            out_file = os.path.join(OUTPUT_DIR, f"gao_{safe_id}.json")

            if os.path.exists(out_file):
                continue

            with open(out_file, "w") as f:
                json.dump(report, f, indent=2)
            total += 1

        time.sleep(2)

    print(f"[OK] {total} GAO reports saved to {OUTPUT_DIR}")


def _search_gao(query, max_results=20):
    """Search GAO reports via their website."""
    encoded = urllib.parse.quote(query)
    url = f"https://www.gao.gov/search?query={encoded}&topic=national_defense"

    reports = []
    try:
        req = urllib.request.Request(url)
        req.add_header("User-Agent", "TorchSight-Research/1.0 (academic)")

        with urllib.request.urlopen(req, timeout=30) as resp:
            html = resp.read().decode("utf-8", errors="ignore")

        import re
        # Parse GAO search results for report links and titles
        # GAO URLs typically: /products/gao-XX-XXX
        links = re.findall(
            r'href="(/products/[Gg][Aa][Oo]-\d+-\d+)"[^>]*>.*?([^<]+)<',
            html,
            re.DOTALL
        )

        seen = set()
        for link, title in links:
            report_id = link.split("/")[-1]
            if report_id in seen:
                continue
            seen.add(report_id)

            reports.append({
                "id": report_id,
                "title": title.strip(),
                "url": f"https://www.gao.gov{link}",
                "search_term": query,
                "source": "gao",
                "license": "public_domain",
            })

            if len(reports) >= max_results:
                break

    except Exception as e:
        print(f"     [WARN] Search failed for '{query}': {e}")

    return reports


if __name__ == "__main__":
    download()
