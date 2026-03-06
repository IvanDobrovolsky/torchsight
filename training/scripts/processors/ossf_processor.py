#!/usr/bin/env python3
"""Process OpenSSF malicious-packages advisories into training JSONL.

License: Apache 2.0
Source: https://github.com/ossf/malicious-packages

Maps malicious npm/pypi/etc packages to taxonomy subcategories.
Primary value: real supply chain attack data.
"""

import json
import hashlib
import random
from pathlib import Path

DATA_FILE = Path(__file__).resolve().parent.parent.parent / "data" / "ossf_malicious" / "advisories.jsonl"
OUT_DIR = Path(__file__).resolve().parent.parent.parent / "data" / "processed"

# Keywords for subcategory classification
SUPPLY_CHAIN_KEYWORDS = [
    "typosquat", "dependency confusion", "malicious package", "backdoor",
    "trojan", "exfiltrat", "data theft", "credential steal", "token steal",
    "reverse shell", "cryptocurrency", "crypto min", "bitcoin", "monero",
]
SHELL_KEYWORDS = ["reverse shell", "shell command", "os.system", "subprocess", "exec("]
CREDENTIAL_KEYWORDS = ["credential", "password", "token", "api key", "secret", "env var", ".env"]
PHISHING_KEYWORDS = ["phishing", "social engineer", "impersonat", "spoof"]


def make_id(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()[:16]


def classify_advisory(adv: dict) -> list:
    """Classify advisory into taxonomy findings."""
    findings = []
    text = f"{adv.get('summary', '')} {adv.get('details', '')}".lower()
    ecosystems = [a.get("ecosystem", "") for a in adv.get("affected", [])]
    packages = [a.get("name", "") for a in adv.get("affected", [])]

    # Always a supply chain attack (it's a malicious package)
    pkg_str = ", ".join(packages[:3]) if packages else "unknown"
    eco_str = ", ".join(set(ecosystems))[:30] if ecosystems else "unknown"

    severity = "high"
    if any(kw in text for kw in ["backdoor", "reverse shell", "credential", "exfiltrat"]):
        severity = "critical"

    findings.append({
        "category": "malicious",
        "subcategory": "malicious.supply_chain",
        "severity": severity,
        "compliance": ["NIST-800-53-SA-12", "SLSA"],
        "evidence": adv.get("summary", "")[:200],
        "explanation": f"Malicious {eco_str} package: {pkg_str}. {adv.get('summary', '')[:150]}"
    })

    # Additional findings based on content
    if any(kw in text for kw in SHELL_KEYWORDS):
        findings.append({
            "category": "malicious",
            "subcategory": "malicious.shell",
            "severity": "critical",
            "compliance": ["CWE-78"],
            "evidence": adv.get("summary", "")[:200],
            "explanation": "Malicious package executes shell commands or opens reverse shell."
        })

    if any(kw in text for kw in CREDENTIAL_KEYWORDS):
        findings.append({
            "category": "credentials",
            "subcategory": "credentials.token",
            "severity": "critical",
            "compliance": ["CWE-522"],
            "evidence": adv.get("summary", "")[:200],
            "explanation": "Malicious package attempts to steal credentials, tokens, or secrets."
        })

    return findings


def format_advisory_text(adv: dict) -> str:
    """Format advisory as document text."""
    parts = []

    adv_id = adv.get("id", "unknown")
    parts.append(f"Malicious Package Advisory: {adv_id}")

    if adv.get("summary"):
        parts.append(f"\nSummary: {adv['summary']}")

    affected = adv.get("affected", [])
    if affected:
        parts.append("\nAffected Packages:")
        for a in affected[:5]:
            eco = a.get("ecosystem", "unknown")
            name = a.get("name", "unknown")
            parts.append(f"  - {eco}/{name}")

    aliases = adv.get("aliases", [])
    if aliases:
        parts.append(f"\nAliases: {', '.join(aliases[:5])}")

    if adv.get("details"):
        details = adv["details"]
        if len(details) > 2000:
            details = details[:2000] + "..."
        parts.append(f"\nDetails:\n{details}")

    return "\n".join(parts)


def main():
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    out_file = OUT_DIR / "ossf_malicious.jsonl"

    if not DATA_FILE.exists():
        print(f"  {DATA_FILE} not found, run download_ossf_malicious.py first")
        return 0

    print("Processing OSSF malicious-packages...")

    # Read all advisories, filter to ones with meaningful content
    advisories = []
    with open(DATA_FILE) as f:
        for line in f:
            adv = json.loads(line)
            # Skip empty/minimal advisories
            summary = adv.get("summary", "")
            details = adv.get("details", "")
            if len(summary) + len(details) < 50:
                continue
            advisories.append(adv)

    print(f"  {len(advisories)} advisories with content (from {sum(1 for _ in open(DATA_FILE))} total)")

    # Sample a diverse subset — take all with good details, cap at 5000
    random.seed(42)
    if len(advisories) > 5000:
        # Prioritize those with longer details
        advisories.sort(key=lambda a: len(a.get("details", "")), reverse=True)
        advisories = advisories[:5000]

    samples = []
    for adv in advisories:
        text = format_advisory_text(adv)
        if len(text) < 50:
            continue

        findings = classify_advisory(adv)
        samples.append({
            "id": f"ossf-{adv.get('id', make_id(text))}",
            "source": "ossf/malicious-packages",
            "source_license": "Apache-2.0",
            "text": text,
            "findings": findings,
        })

    with open(out_file, "w") as f:
        for s in samples:
            f.write(json.dumps(s) + "\n")

    # Count subcategories
    subcat_counts = {}
    for s in samples:
        for finding in s["findings"]:
            sub = finding["subcategory"]
            subcat_counts[sub] = subcat_counts.get(sub, 0) + 1

    print(f"Saved {len(samples)} samples to {out_file}")
    for sub, count in sorted(subcat_counts.items()):
        print(f"  {sub}: {count}")
    return len(samples)


if __name__ == "__main__":
    main()
