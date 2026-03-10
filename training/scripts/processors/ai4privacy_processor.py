#!/usr/bin/env python3
"""
AI4Privacy PII Masking Processor for TorchSight Training

Processes the ai4privacy pii_masking_300k dataset containing
masked/unmasked text with 54 PII label classes.

Targets: pii.identity, pii.contact, pii.financial_id,
         pii.metadata, pii.behavioral
"""

import json
import random
import sys
from collections import defaultdict
from pathlib import Path

RAW_DIR = Path(__file__).parent.parent.parent / "data" / "raw" / "ai4privacy"
OUT_DIR = Path(__file__).parent.parent.parent / "data" / "processed"

# Map AI4Privacy PII labels to our subcategories
LABEL_MAP = {
    # pii.identity
    "GIVENNAME1": "pii.identity",
    "GIVENNAME2": "pii.identity",
    "LASTNAME1": "pii.identity",
    "LASTNAME2": "pii.identity",
    "LASTNAME3": "pii.identity",
    "SOCIALNUMBER": "pii.identity",
    "PASSPORT": "pii.identity",
    "DRIVERLICENSE": "pii.identity",
    "IDCARD": "pii.identity",
    "SEX": "pii.identity",
    "BOD": "pii.identity",
    "TITLE": "pii.identity",
    "USERNAME": "pii.identity",
    # pii.contact
    "EMAIL": "pii.contact",
    "TEL": "pii.contact",
    "STREET": "pii.contact",
    "SECADDRESS": "pii.contact",
    "CITY": "pii.contact",
    "STATE": "pii.contact",
    "POSTCODE": "pii.contact",
    "COUNTRY": "pii.contact",
    "BUILDING": "pii.contact",
    # pii.financial_id
    "PASS": "pii.financial_id",
    # pii.metadata
    "IP": "pii.metadata",
    "DATE": "pii.metadata",
    "TIME": "pii.metadata",
    # pii.behavioral
    "GEOCOORD": "pii.behavioral",
}

# Severity by subcategory
SEVERITY_MAP = {
    "pii.identity": "high",
    "pii.contact": "medium",
    "pii.financial_id": "critical",
    "pii.metadata": "low",
    "pii.behavioral": "medium",
}

# High-severity PII labels that bump to critical
CRITICAL_LABELS = {"SOCIALNUMBER", "PASSPORT", "DRIVERLICENSE", "IDCARD"}


def parse_record(record: dict) -> dict | None:
    """Parse a single ai4privacy record into our training format."""
    text = record.get("source_text", "")
    if not text or len(text) < 50:
        return None

    # Parse privacy mask
    privacy_mask = record.get("privacy_mask", [])
    if isinstance(privacy_mask, str):
        try:
            privacy_mask = json.loads(privacy_mask)
        except (json.JSONDecodeError, TypeError):
            return None

    if not privacy_mask:
        return None

    # Group labels by our subcategory
    subcat_labels = defaultdict(set)
    subcat_values = defaultdict(list)
    for item in privacy_mask:
        label = item.get("label", "")
        value = item.get("value", "")
        subcat = LABEL_MAP.get(label)
        if subcat:
            subcat_labels[subcat].add(label)
            if value and len(value) > 1:
                subcat_values[subcat].append(value)

    if not subcat_labels:
        return None

    # Build findings
    findings = []
    for subcat, labels in subcat_labels.items():
        severity = SEVERITY_MAP.get(subcat, "medium")
        # Bump severity for critical PII types
        if any(lbl in CRITICAL_LABELS for lbl in labels):
            severity = "critical"

        label_list = sorted(labels)
        values = subcat_values.get(subcat, [])[:5]

        explanation_parts = []
        if "pii.identity" == subcat:
            explanation_parts.append(f"Personal identity information detected: {', '.join(label_list)}")
        elif "pii.contact" == subcat:
            explanation_parts.append(f"Contact information detected: {', '.join(label_list)}")
        elif "pii.financial_id" == subcat:
            explanation_parts.append("Financial identifier or password detected")
        elif "pii.metadata" == subcat:
            explanation_parts.append(f"Identifying metadata detected: {', '.join(label_list)}")
        elif "pii.behavioral" == subcat:
            explanation_parts.append("Behavioral/location tracking data detected")

        if values:
            explanation_parts.append(f"Examples: {', '.join(values[:3])}")

        findings.append({
            "category": "pii",
            "subcategory": subcat,
            "severity": severity,
            "explanation": ". ".join(explanation_parts),
        })

    return {
        "text": text[:4000],
        "findings": findings,
        "subcategories": set(f["subcategory"] for f in findings),
    }


def process(max_samples: int = 5000, seed: int = 42):
    """Process AI4Privacy dataset and output labeled JSONL."""
    random.seed(seed)
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    out_path = OUT_DIR / "ai4privacy.jsonl"

    raw_file = RAW_DIR / "pii_masking_300k.jsonl"
    if not raw_file.exists():
        print(f"ERROR: AI4Privacy data not found at {raw_file}")
        sys.exit(1)

    print("Scanning AI4Privacy records...")

    # First pass: bucket by subcategory for balanced sampling
    by_subcat = defaultdict(list)
    total_read = 0

    with open(raw_file) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            total_read += 1
            if total_read % 50000 == 0:
                print(f"  ...scanned {total_read:,}")

            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                continue

            # Only process English records
            if record.get("language", "English") != "English":
                continue

            parsed = parse_record(record)
            if parsed:
                for subcat in parsed["subcategories"]:
                    by_subcat[subcat].append(parsed)

    print(f"Scanned {total_read:,} records")
    print(f"Found records by subcategory:")
    for sub, items in sorted(by_subcat.items()):
        print(f"  {sub}: {len(items):,}")

    # Balanced sampling across subcategories
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

    # Fill remaining slots from any subcategory
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
            findings = item["findings"]
            for f in findings:
                subcat_counts[f["subcategory"]] += 1

            record = {
                "id": f"ai4privacy_{i:05d}",
                "source": "ai4privacy",
                "source_license": "apache_2.0",
                "text": item["text"],
                "findings": findings,
            }
            fout.write(json.dumps(record) + "\n")

    print(f"\nWrote {len(selected):,} samples to {out_path}")
    print("\nCategory distribution:")
    for sub, count in sorted(subcat_counts.items()):
        print(f"  {sub}: {count}")


if __name__ == "__main__":
    max_n = int(sys.argv[1]) if len(sys.argv) > 1 else 5000
    process(max_samples=max_n)
