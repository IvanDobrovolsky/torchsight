#!/usr/bin/env python3
"""
Phishing Email/SMS Processor for TorchSight Training

Processes phishing text dataset with binary labels (0=legit, 1=phishing).
Labels phishing as malicious.phishing, legitimate samples as safe.documentation.

Targets: malicious.phishing, safe.documentation
"""

import json
import random
import re
import sys
from collections import defaultdict
from pathlib import Path

RAW_DIR = Path(__file__).parent.parent.parent / "data" / "raw" / "phishing"
OUT_DIR = Path(__file__).parent.parent.parent / "data" / "processed"

# Phishing indicators for severity grading
CRITICAL_INDICATORS = [
    "verify your account", "confirm your identity", "suspended",
    "unauthorized access", "click here immediately", "within 24 hours",
    "credit card", "bank account", "social security",
]

HIGH_INDICATORS = [
    "urgent", "act now", "limited time", "password", "login",
    "update your", "verify your", "confirm your", "winner",
    "congratulations", "claim your prize",
]


def classify_phishing(text: str) -> dict:
    """Classify a phishing text and determine severity."""
    text_lower = text.lower()

    critical_matches = [kw for kw in CRITICAL_INDICATORS if kw in text_lower]
    high_matches = [kw for kw in HIGH_INDICATORS if kw in text_lower]

    if critical_matches:
        severity = "critical"
        explanation = (
            f"Phishing attempt detected with high-risk indicators: "
            f"{', '.join(critical_matches[:3])}. "
            f"This message attempts to deceive the recipient into revealing sensitive information."
        )
    elif high_matches:
        severity = "high"
        explanation = (
            f"Phishing attempt detected with social engineering tactics: "
            f"{', '.join(high_matches[:3])}. "
            f"Uses urgency and deception to manipulate the recipient."
        )
    else:
        severity = "high"
        explanation = (
            "Phishing attempt detected. Message uses deceptive language "
            "to trick recipients into taking harmful actions."
        )

    # Check for URLs (common in phishing)
    urls = re.findall(r'https?://\S+', text)
    if urls:
        explanation += f" Contains {len(urls)} URL(s) that may lead to malicious sites."

    return {
        "category": "malicious",
        "subcategory": "malicious.phishing",
        "severity": severity,
        "explanation": explanation,
    }


def classify_safe(text: str) -> dict:
    """Classify a legitimate text as safe."""
    return {
        "category": "safe",
        "subcategory": "safe.documentation",
        "severity": "info",
        "explanation": (
            "Legitimate message with no phishing indicators, "
            "social engineering tactics, or malicious intent detected."
        ),
    }


def process(max_samples: int = 8000, seed: int = 42):
    """Process phishing dataset and output labeled JSONL."""
    random.seed(seed)
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    out_path = OUT_DIR / "phishing.jsonl"

    raw_file = RAW_DIR / "phishing_texts.jsonl"
    if not raw_file.exists():
        print(f"ERROR: Phishing data not found at {raw_file}")
        sys.exit(1)

    print("Scanning phishing dataset...")

    phishing_samples = []
    safe_samples = []
    total_read = 0

    with open(raw_file) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            total_read += 1

            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                continue

            text = record.get("text", "")
            label = record.get("label")

            if not text or len(text) < 30:
                continue

            if str(label) == "1":
                phishing_samples.append(text)
            else:
                safe_samples.append(text)

    print(f"Scanned {total_read:,} records")
    print(f"  Phishing: {len(phishing_samples):,}")
    print(f"  Legitimate: {len(safe_samples):,}")

    # Sample: 2000 phishing, 1000 safe
    max_phishing = min(6000, len(phishing_samples))
    max_safe = min(2000, len(safe_samples))

    random.shuffle(phishing_samples)
    random.shuffle(safe_samples)

    selected_phishing = phishing_samples[:max_phishing]
    selected_safe = safe_samples[:max_safe]

    # Write output
    idx = 0
    subcat_counts = defaultdict(int)

    with open(out_path, "w") as fout:
        for text in selected_phishing:
            finding = classify_phishing(text)
            subcat_counts[finding["subcategory"]] += 1
            record = {
                "id": f"phishing_{idx:05d}",
                "source": "phishing",
                "source_license": "apache_2.0",
                "text": text[:4000],
                "findings": [finding],
            }
            fout.write(json.dumps(record) + "\n")
            idx += 1

        for text in selected_safe:
            finding = classify_safe(text)
            subcat_counts[finding["subcategory"]] += 1
            record = {
                "id": f"phishing_{idx:05d}",
                "source": "phishing",
                "source_license": "apache_2.0",
                "text": text[:4000],
                "findings": [finding],
            }
            fout.write(json.dumps(record) + "\n")
            idx += 1

    print(f"\nWrote {idx:,} samples to {out_path}")
    print("\nCategory distribution:")
    for sub, count in sorted(subcat_counts.items()):
        print(f"  {sub}: {count}")


if __name__ == "__main__":
    max_n = int(sys.argv[1]) if len(sys.argv) > 1 else 3000
    process(max_samples=max_n)
