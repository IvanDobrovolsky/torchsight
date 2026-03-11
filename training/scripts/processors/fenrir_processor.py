#!/usr/bin/env python3
"""
Fenrir Cybersecurity Processor for TorchSight Training

Processes the Fenrir v2 cybersecurity instruction dataset
containing system/user/assistant triples on security topics.

Targets: malicious.injection, malicious.shell, malicious.obfuscation,
         malicious.ssrf, malicious.ssti, malicious.phishing,
         malicious.supply_chain, malicious.prompt_injection
"""

import json
import random
import re
import sys
from collections import defaultdict
from pathlib import Path

RAW_DIR = Path(__file__).parent.parent.parent / "data" / "raw" / "fenrir"
OUT_DIR = Path(__file__).parent.parent.parent / "data" / "processed"

# Keyword-based classification into malicious subcategories
SUBCAT_RULES = [
    # (subcategory, severity, keywords)
    ("malicious.injection", "critical", [
        "sql injection", "xss", "cross-site scripting", "command injection",
        "code injection", "ldap injection", "xpath injection", "nosql injection",
        "injection attack", "injection vulnerability", "owasp injection",
        "input validation", "parameterized", "prepared statement",
    ]),
    ("malicious.ssrf", "high", [
        "ssrf", "server-side request forgery", "server side request forgery",
        "internal network", "metadata endpoint", "cloud metadata",
        "request forgery",
    ]),
    ("malicious.ssti", "high", [
        "ssti", "server-side template injection", "server side template injection",
        "template injection", "jinja2", "freemarker", "twig injection",
        "template engine",
    ]),
    ("malicious.shell", "critical", [
        "reverse shell", "web shell", "backdoor", "remote code execution",
        "rce", "command execution", "privilege escalation", "rootkit",
        "bind shell", "payload execution", "post-exploitation",
        "lateral movement", "persistence mechanism",
    ]),
    ("malicious.obfuscation", "high", [
        "obfuscation", "encoding bypass", "evasion", "anti-detection",
        "polymorphic", "metamorphic", "packing", "crypter",
        "anti-forensic", "log tampering", "defense evasion",
        "steganography", "covert channel",
    ]),
    ("malicious.phishing", "high", [
        "phishing", "social engineering", "spear phishing", "whaling",
        "credential harvesting", "pretexting", "vishing", "smishing",
        "business email compromise", "bec",
    ]),
    ("malicious.supply_chain", "critical", [
        "supply chain", "dependency confusion", "typosquatting",
        "package hijack", "compromised library", "third-party risk",
        "software composition", "sca", "sbom",
    ]),
    ("malicious.prompt_injection", "high", [
        "prompt injection", "llm attack", "ai safety", "jailbreak",
        "adversarial prompt", "indirect prompt injection",
    ]),
]


def classify_text(text: str) -> tuple[str, str] | None:
    """Classify text into a malicious subcategory based on keywords."""
    text_lower = text.lower()

    best_match = None
    best_count = 0

    for subcat, severity, keywords in SUBCAT_RULES:
        count = sum(1 for kw in keywords if kw in text_lower)
        if count > best_count:
            best_count = count
            best_match = (subcat, severity)

    if best_count >= 1:
        return best_match
    return None


def process(max_samples: int = 10000, seed: int = 42):
    """Process Fenrir cybersecurity dataset and output labeled JSONL."""
    random.seed(seed)
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    out_path = OUT_DIR / "fenrir.jsonl"

    raw_file = RAW_DIR / "fenrir_v2.jsonl"
    if not raw_file.exists():
        print(f"ERROR: Fenrir data not found at {raw_file}")
        sys.exit(1)

    print("Scanning Fenrir cybersecurity dataset...")

    # Bucket by subcategory
    by_subcat = defaultdict(list)
    unclassified = 0
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

            # Combine user question and assistant response as training text
            user_text = record.get("user", "")
            assistant_text = record.get("assistant", "")

            # Use both for classification but primarily the combined text
            combined = f"{user_text}\n\n{assistant_text}"
            if len(combined) < 100:
                continue

            classification = classify_text(combined)
            if classification is None:
                unclassified += 1
                continue

            subcat, severity = classification

            # Build explanation based on content
            explanation = (
                f"Cybersecurity content discussing {subcat.split('.')[1]} techniques. "
                f"Contains technical details about attack vectors, "
                f"defensive strategies, or vulnerability analysis."
            )

            sample = {
                "text": combined[:4000],
                "subcategory": subcat,
                "findings": [{
                    "category": "malicious",
                    "subcategory": subcat,
                    "severity": severity,
                    "explanation": explanation,
                }],
            }
            by_subcat[subcat].append(sample)

    print(f"Scanned {total_read:,} records")
    print(f"Unclassified: {unclassified:,}")
    print(f"Found samples by subcategory:")
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

    # Fill remaining slots
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
                "id": f"fenrir_{i:05d}",
                "source": "fenrir",
                "source_license": "apache_2.0",
                "text": item["text"],
                "findings": item["findings"],
            }
            fout.write(json.dumps(record) + "\n")

    print(f"\nWrote {len(selected):,} samples to {out_path}")
    print("\nCategory distribution:")
    for sub, count in sorted(subcat_counts.items()):
        print(f"  {sub}: {count}")


if __name__ == "__main__":
    max_n = int(sys.argv[1]) if len(sys.argv) > 1 else 5000
    process(max_samples=max_n)
