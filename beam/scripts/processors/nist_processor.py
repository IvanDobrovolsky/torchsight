#!/usr/bin/env python3
"""
NIST Cybersecurity Training Processor for TorchSight Training

Processes NIST cybersecurity publications (very large dataset).
Uses streaming to handle 9.6GB file efficiently.

Targets: safe.documentation, confidential.classified,
         credentials (context), malicious (context)
"""

import json
import random
import sys
from collections import defaultdict
from pathlib import Path

RAW_DIR = Path(__file__).parent.parent.parent / "data" / "raw" / "nist_training"
OUT_DIR = Path(__file__).parent.parent.parent / "data" / "processed"

# Keywords for classifying NIST content
CONFIDENTIAL_KEYWORDS = [
    "classified", "secret", "top secret", "controlled unclassified",
    "cui", "fouo", "for official use only", "sensitive but unclassified",
    "security clearance", "need to know", "compartmented",
    "national security", "defense information",
]

CREDENTIALS_KEYWORDS = [
    "access control", "authentication", "authorization", "identity management",
    "multi-factor", "mfa", "password policy", "credential management",
    "pki", "certificate authority", "key management", "token",
    "single sign-on", "sso", "privileged access",
]

VULNERABILITY_KEYWORDS = [
    "vulnerability", "exploit", "attack vector", "threat actor",
    "malware", "ransomware", "zero-day", "cve-", "penetration test",
    "red team", "adversary", "intrusion detection", "incident response",
]

FRAMEWORK_KEYWORDS = [
    "nist sp", "nist 800", "cybersecurity framework", "csf",
    "risk management framework", "rmf", "fips", "control family",
    "security control", "assessment", "continuous monitoring",
]


def classify_nist_text(text: str) -> tuple[str, str, str, str]:
    """Classify NIST text and return (category, subcategory, severity, explanation)."""
    text_lower = text.lower()

    conf_matches = [kw for kw in CONFIDENTIAL_KEYWORDS if kw in text_lower]
    cred_matches = [kw for kw in CREDENTIALS_KEYWORDS if kw in text_lower]
    vuln_matches = [kw for kw in VULNERABILITY_KEYWORDS if kw in text_lower]
    framework_matches = [kw for kw in FRAMEWORK_KEYWORDS if kw in text_lower]

    # Prioritize classification
    if len(conf_matches) >= 2:
        return (
            "confidential", "confidential.classified", "high",
            f"NIST publication discussing classified information handling. "
            f"References: {', '.join(conf_matches[:3])}. "
            f"Contains guidance on protecting sensitive government information."
        )

    if len(vuln_matches) >= 2:
        return (
            "confidential", "confidential.classified", "medium",
            f"NIST cybersecurity publication covering vulnerability management. "
            f"Topics: {', '.join(vuln_matches[:3])}. "
            f"Contains technical security guidance that could inform defensive posture."
        )

    if len(cred_matches) >= 2:
        return (
            "confidential", "confidential.classified", "medium",
            f"NIST publication on credential and access management. "
            f"Topics: {', '.join(cred_matches[:3])}. "
            f"Contains security framework guidance for authentication systems."
        )

    # Default: safe documentation
    context = ""
    if framework_matches:
        context = f" Topics: {', '.join(framework_matches[:3])}."
    return (
        "safe", "safe.documentation", "info",
        f"NIST cybersecurity documentation and standards guidance.{context} "
        f"General security reference material without sensitive content."
    )


def process(max_samples: int = 8000, seed: int = 42):
    """Process NIST cybersecurity dataset and output labeled JSONL."""
    random.seed(seed)
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    out_path = OUT_DIR / "nist.jsonl"

    raw_file = RAW_DIR / "nist_cybersecurity_training.jsonl"
    if not raw_file.exists():
        print(f"ERROR: NIST data not found at {raw_file}")
        sys.exit(1)

    print("Streaming NIST cybersecurity dataset (large file)...")

    # Target: 5000 safe, 3000 confidential
    max_safe = 5000
    max_confidential = 3000

    safe_samples = []
    confidential_samples = []
    total_read = 0

    with open(raw_file) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            total_read += 1
            if total_read % 100000 == 0:
                print(f"  ...streamed {total_read:,}")

            # Early exit if we have enough candidates to sample from
            if (len(safe_samples) >= max_safe * 5 and
                    len(confidential_samples) >= max_confidential * 5):
                break

            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                continue

            text = record.get("text", "")
            if not text or len(text) < 100:
                continue

            # Extract source metadata if available
            metadata = record.get("metadata", "")
            if isinstance(metadata, str):
                try:
                    metadata = json.loads(metadata)
                except (json.JSONDecodeError, TypeError):
                    metadata = {}

            source_name = ""
            if isinstance(metadata, dict):
                source_name = metadata.get("source", "")

            text = text[:4000]
            category, subcategory, severity, explanation = classify_nist_text(text)

            if source_name:
                explanation += f" Source: {source_name}."

            sample = {
                "text": text,
                "findings": [{
                    "category": category,
                    "subcategory": subcategory,
                    "severity": severity,
                    "explanation": explanation,
                }],
            }

            if subcategory == "safe.documentation":
                safe_samples.append(sample)
            else:
                confidential_samples.append(sample)

    print(f"Streamed {total_read:,} records")
    print(f"  Safe candidates: {len(safe_samples):,}")
    print(f"  Confidential candidates: {len(confidential_samples):,}")

    # Sample
    random.shuffle(safe_samples)
    random.shuffle(confidential_samples)

    selected_safe = safe_samples[:max_safe]
    selected_conf = confidential_samples[:max_confidential]

    selected = selected_safe + selected_conf
    random.shuffle(selected)

    # Write output
    subcat_counts = defaultdict(int)
    with open(out_path, "w") as fout:
        for i, item in enumerate(selected):
            for f in item["findings"]:
                subcat_counts[f["subcategory"]] += 1
            record_out = {
                "id": f"nist_{i:05d}",
                "source": "nist",
                "source_license": "public_domain",
                "text": item["text"],
                "findings": item["findings"],
            }
            fout.write(json.dumps(record_out) + "\n")

    print(f"\nWrote {len(selected):,} samples to {out_path}")
    print("\nCategory distribution:")
    for sub, count in sorted(subcat_counts.items()):
        print(f"  {sub}: {count}")


if __name__ == "__main__":
    max_n = int(sys.argv[1]) if len(sys.argv) > 1 else 8000
    process(max_samples=max_n)
