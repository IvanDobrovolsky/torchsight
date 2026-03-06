#!/usr/bin/env python3
"""Process HuggingFace phishing email datasets into training JSONL."""

import json
import hashlib
import random
from pathlib import Path

DATA_DIR = Path(__file__).resolve().parent.parent.parent / "data" / "phishing_emails"

# Also process safe emails as negative examples
INCLUDE_SAFE = True
SAFE_CAP = 500  # Include some safe emails to balance
OUT_DIR = Path(__file__).resolve().parent.parent.parent / "data" / "processed"


def make_id(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()[:16]


def classify_phishing(text: str) -> dict:
    """Determine phishing sub-type from content."""
    text_lower = text.lower()

    if any(w in text_lower for w in ["password", "credential", "login", "verify your account", "sign in"]):
        explanation = "Credential harvesting phishing — attempts to steal login credentials through deceptive messaging."
    elif any(w in text_lower for w in ["wire transfer", "bank", "payment", "invoice", "urgent payment"]):
        explanation = "Financial phishing — attempts to trick recipient into making fraudulent payments or revealing financial information."
    elif any(w in text_lower for w in ["malware", "attachment", "download", ".exe", ".zip", "click here"]):
        explanation = "Malware delivery phishing — attempts to get recipient to download or execute malicious files."
    elif any(w in text_lower for w in ["ceo", "director", "urgent request", "confidential"]):
        explanation = "Business Email Compromise (BEC) — impersonates executive or authority figure to manipulate recipient."
    else:
        explanation = "Social engineering phishing — uses deceptive tactics to manipulate recipient into taking harmful actions."

    return {
        "category": "malicious",
        "subcategory": "malicious.phishing",
        "severity": "high",
        "compliance": ["NIST-800-53-SI-3", "OWASP-SE-01"],
        "evidence": text[:200],
        "explanation": explanation,
    }


def main():
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    out_file = OUT_DIR / "phishing.jsonl"
    data_file = DATA_DIR / "data.jsonl"

    if not data_file.exists():
        print(f"  {data_file} not found, skipping")
        return 0

    print("Processing phishing email dataset...")
    samples = []
    seen = set()

    with open(data_file) as f:
        for line in f:
            row = json.loads(line)

            # Handle various column names across datasets
            text = (row.get("Email Text", "") or row.get("text", "") or
                    row.get("body", "") or row.get("email_text", "") or "").strip()
            label = (row.get("Email Type", "") or row.get("label", "") or
                     row.get("label_text", "") or "")

            if not text or len(text) < 30:
                continue

            # Determine if phishing
            if isinstance(label, int):
                is_phishing = label == 1
            elif isinstance(label, str):
                is_phishing = label.lower() in ["phishing", "phishing email", "1", "spam"]
            else:
                continue

            if not is_phishing:
                continue

            # Deduplicate
            key = text[:150]
            if key in seen:
                continue
            seen.add(key)

            finding = classify_phishing(text)
            samples.append({
                "id": f"phish-{make_id(text)}",
                "source": "ealvaradob/phishing-dataset",
                "source_license": "CC-BY-4.0",
                "text": f"Email content:\n\n{text}",
                "findings": [finding],
            })

    # Cap at 2000
    if len(samples) > 2000:
        random.shuffle(samples)
        samples = samples[:2000]

    with open(out_file, "w") as f:
        for s in samples:
            f.write(json.dumps(s) + "\n")

    print(f"Saved {len(samples)} phishing samples to {out_file}")
    return len(samples)


if __name__ == "__main__":
    main()
