#!/usr/bin/env python3
"""
EDGAR SEC 10-K Filing Processor for TorchSight Training

Processes SEC annual filings with structured sections.
Maps to financial subcategories based on section content.

Targets: financial.investment, financial.bank_statement,
         financial.tax
"""

import json
import random
import re
import sys
from collections import defaultdict
from pathlib import Path

RAW_DIR = Path(__file__).parent.parent.parent / "data" / "raw" / "edgar"
OUT_DIR = Path(__file__).parent.parent.parent / "data" / "processed"

# Section mappings to our financial subcategories
# section_1A = Risk Factors → financial.investment
# section_7 = MD&A → financial.investment
# section_8 = Financial Statements → financial.bank_statement
# section_6 = Selected Financial Data → financial.bank_statement
# section_7A = Market Risk → financial.investment

SECTION_CONFIGS = {
    "section_1A": {
        "subcategory": "financial.investment",
        "severity": "high",
        "label": "SEC 10-K Risk Factors",
        "explanation_prefix": "SEC filing risk factors section containing investment-relevant disclosures",
    },
    "section_7": {
        "subcategory": "financial.investment",
        "severity": "high",
        "label": "SEC 10-K MD&A",
        "explanation_prefix": "Management Discussion and Analysis section with financial performance data",
    },
    "section_7A": {
        "subcategory": "financial.investment",
        "severity": "medium",
        "label": "SEC 10-K Market Risk",
        "explanation_prefix": "Quantitative and qualitative market risk disclosures",
    },
    "section_8": {
        "subcategory": "financial.bank_statement",
        "severity": "high",
        "label": "SEC 10-K Financial Statements",
        "explanation_prefix": "Audited financial statements and supplementary data",
    },
    "section_6": {
        "subcategory": "financial.bank_statement",
        "severity": "medium",
        "label": "SEC 10-K Selected Financial Data",
        "explanation_prefix": "Selected financial data and key metrics",
    },
    "section_11": {
        "subcategory": "financial.bank_statement",
        "severity": "medium",
        "label": "SEC 10-K Executive Compensation",
        "explanation_prefix": "Executive compensation disclosures with financial details",
    },
}

# Tax-related keywords to detect tax content in any section
TAX_KEYWORDS = [
    "income tax", "tax expense", "deferred tax", "tax rate",
    "tax provision", "tax benefit", "tax liability", "tax credit",
    "tax reform", "tax law", "irs", "internal revenue",
]


def extract_section_sample(record: dict, section_key: str, config: dict) -> dict | None:
    """Extract a training sample from a specific section."""
    text = record.get(section_key, "")
    if not text or len(text) < 100:
        return None

    # Skip placeholder sections
    if "not applicable" in text.lower()[:100] or "omitted" in text.lower()[:100]:
        return None

    text = text[:4000]
    text_lower = text.lower()

    # Check for tax content override
    tax_matches = [kw for kw in TAX_KEYWORDS if kw in text_lower]
    if len(tax_matches) >= 2:
        subcategory = "financial.tax"
        severity = "high"
        explanation = (
            f"SEC 10-K filing section containing tax-related disclosures. "
            f"Tax references found: {', '.join(tax_matches[:4])}. "
            f"Contains regulated financial information subject to SEC disclosure requirements."
        )
    else:
        subcategory = config["subcategory"]
        severity = config["severity"]
        explanation = (
            f"{config['explanation_prefix']}. "
            f"Source: {record.get('filename', 'unknown')} (CIK: {record.get('cik', 'N/A')}, "
            f"Year: {record.get('year', 'N/A')}). "
            f"Contains regulated financial information subject to SEC disclosure requirements."
        )

    return {
        "text": text,
        "subcategory": subcategory,
        "findings": [{
            "category": "financial",
            "subcategory": subcategory,
            "severity": severity,
            "explanation": explanation,
        }],
    }


def process(max_samples: int = 6000, seed: int = 42):
    """Process EDGAR 10-K filings and output labeled JSONL."""
    random.seed(seed)
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    out_path = OUT_DIR / "edgar.jsonl"

    raw_file = RAW_DIR / "edgar_filings.jsonl"
    if not raw_file.exists():
        print(f"ERROR: EDGAR data not found at {raw_file}")
        sys.exit(1)

    print("Scanning EDGAR filings...")

    # Collect samples by subcategory for balanced output
    by_subcat = defaultdict(list)
    total_read = 0

    with open(raw_file) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            total_read += 1
            if total_read % 5000 == 0:
                print(f"  ...scanned {total_read:,}")

            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                continue

            # Extract from each target section
            for section_key, config in SECTION_CONFIGS.items():
                sample = extract_section_sample(record, section_key, config)
                if sample:
                    by_subcat[sample["subcategory"]].append(sample)

    print(f"Scanned {total_read:,} filings")
    print(f"Found samples by subcategory:")
    for sub, items in sorted(by_subcat.items()):
        print(f"  {sub}: {len(items):,}")

    # Balanced sampling
    per_subcat = max_samples // len(by_subcat) if by_subcat else 0
    selected = []
    seen_texts = set()

    for subcat in sorted(by_subcat.keys()):
        items = by_subcat[subcat]
        random.shuffle(items)
        count = 0
        for item in items:
            if count >= per_subcat:
                break
            text_hash = hash(item["text"][:200])
            if text_hash in seen_texts:
                continue
            seen_texts.add(text_hash)
            selected.append(item)
            count += 1

    # Fill remaining
    remaining = max_samples - len(selected)
    if remaining > 0:
        all_items = []
        for items in by_subcat.values():
            all_items.extend(items)
        random.shuffle(all_items)
        for item in all_items:
            if remaining <= 0:
                break
            text_hash = hash(item["text"][:200])
            if text_hash in seen_texts:
                continue
            seen_texts.add(text_hash)
            selected.append(item)
            remaining -= 1

    random.shuffle(selected)

    # Write output
    subcat_counts = defaultdict(int)
    with open(out_path, "w") as fout:
        for i, item in enumerate(selected):
            for f in item["findings"]:
                subcat_counts[f["subcategory"]] += 1
            record = {
                "id": f"edgar_{i:05d}",
                "source": "edgar",
                "source_license": "public_domain",
                "text": item["text"],
                "findings": item["findings"],
            }
            fout.write(json.dumps(record) + "\n")

    print(f"\nWrote {len(selected):,} samples to {out_path}")
    print("\nCategory distribution:")
    for sub, count in sorted(subcat_counts.items()):
        print(f"  {sub}: {count}")


if __name__ == "__main__":
    max_n = int(sys.argv[1]) if len(sys.argv) > 1 else 3000
    process(max_samples=max_n)
