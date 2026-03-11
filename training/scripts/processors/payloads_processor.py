#!/usr/bin/env python3
"""
PayloadsAllTheThings Processor for TorchSight Training

Processes the PayloadsAllTheThings directory tree of attack payload files.
Maps directory names to malicious subcategories.

Targets: malicious.injection, malicious.ssrf, malicious.ssti,
         malicious.shell, malicious.redos, malicious.prompt_injection,
         malicious.supply_chain, malicious.obfuscation,
         malicious.prototype_pollution
"""

import json
import os
import random
import sys
from collections import defaultdict
from pathlib import Path

RAW_DIR = Path(__file__).parent.parent.parent / "data" / "raw" / "PayloadsAllTheThings"
OUT_DIR = Path(__file__).parent.parent.parent / "data" / "processed"

# Map directory names to subcategories
DIR_MAP = {
    # malicious.injection
    "SQL Injection": ("malicious.injection", "critical", "SQL injection"),
    "NoSQL Injection": ("malicious.injection", "critical", "NoSQL injection"),
    "Command Injection": ("malicious.injection", "critical", "OS command injection"),
    "LDAP Injection": ("malicious.injection", "high", "LDAP injection"),
    "GraphQL Injection": ("malicious.injection", "high", "GraphQL injection"),
    "LaTeX Injection": ("malicious.injection", "medium", "LaTeX injection"),
    "CRLF Injection": ("malicious.injection", "high", "CRLF injection"),
    "CSS Injection": ("malicious.injection", "medium", "CSS injection"),
    "CSV Injection": ("malicious.injection", "medium", "CSV injection"),
    "XSS Injection": ("malicious.injection", "high", "Cross-site scripting"),
    "File Inclusion": ("malicious.injection", "critical", "File inclusion"),
    "Directory Traversal": ("malicious.injection", "high", "Directory traversal"),
    "HTTP Parameter Pollution": ("malicious.injection", "medium", "HTTP parameter pollution"),
    "Insecure Deserialization": ("malicious.injection", "critical", "Insecure deserialization"),
    "SAML Injection": ("malicious.injection", "high", "SAML injection"),
    "Client Side Path Traversal": ("malicious.injection", "high", "Client-side path traversal"),
    # malicious.ssrf
    "Server Side Request Forgery": ("malicious.ssrf", "high", "Server-side request forgery"),
    "DNS Rebinding": ("malicious.ssrf", "high", "DNS rebinding (SSRF variant)"),
    # malicious.ssti
    "Server Side Template Injection": ("malicious.ssti", "high", "Server-side template injection"),
    "Server Side Include Injection": ("malicious.ssti", "high", "Server-side include injection"),
    # malicious.shell
    "Upload Insecure Files": ("malicious.shell", "critical", "Malicious file upload"),
    "CVE Exploits": ("malicious.shell", "critical", "Known CVE exploits"),
    "Java RMI": ("malicious.shell", "critical", "Java RMI exploitation"),
    # malicious.prompt_injection
    "Prompt Injection": ("malicious.prompt_injection", "high", "AI/LLM prompt injection"),
    # malicious.prototype_pollution
    "Prototype Pollution": ("malicious.prototype_pollution", "high", "JavaScript prototype pollution"),
    # malicious.redos
    "Regular Expression": ("malicious.redos", "medium", "Regular expression denial of service"),
    "Denial of Service": ("malicious.redos", "high", "Denial of service payloads"),
    # malicious.obfuscation
    "Encoding Transformations": ("malicious.obfuscation", "medium", "Encoding-based obfuscation"),
    # malicious.supply_chain
    "Dependency Confusion": ("malicious.supply_chain", "critical", "Dependency confusion attack"),
    # Additional mappings
    "Cross-Site Request Forgery": ("malicious.injection", "high", "Cross-site request forgery"),
    "Clickjacking": ("malicious.injection", "medium", "Clickjacking"),
    "DOM Clobbering": ("malicious.injection", "medium", "DOM clobbering"),
    "Request Smuggling": ("malicious.injection", "high", "HTTP request smuggling"),
    "Type Juggling": ("malicious.injection", "medium", "Type juggling"),
    "Web Cache Deception": ("malicious.injection", "medium", "Web cache deception"),
    "Mass Assignment": ("malicious.injection", "high", "Mass assignment"),
    "Insecure Direct Object References": ("malicious.injection", "high", "IDOR"),
    "Race Condition": ("malicious.injection", "high", "Race condition"),
    "ORM Leak": ("malicious.injection", "medium", "ORM leak"),
    "JSON Web Token": ("malicious.obfuscation", "high", "JWT manipulation"),
    "OAuth Misconfiguration": ("malicious.obfuscation", "high", "OAuth misconfiguration"),
    "Open Redirect": ("malicious.phishing", "medium", "Open redirect"),
    "Account Takeover": ("malicious.phishing", "critical", "Account takeover"),
    "API Key Leaks": ("malicious.obfuscation", "high", "API key leak patterns"),
    "Headless Browser": ("malicious.shell", "high", "Headless browser exploitation"),
}

# Skip these directories
SKIP_DIRS = {
    "_LEARNING_AND_SOCIALS", "_template_vuln", "Methodology and Resources",
    "Images", "Intruder", ".git", ".github",
}

# Valid file extensions for payload files
PAYLOAD_EXTENSIONS = {
    ".md", ".txt", ".py", ".rb", ".php", ".js", ".sh", ".ps1",
    ".xml", ".json", ".yaml", ".yml", ".html", ".sql", ".csv",
    ".java", ".c", ".pl", ".lua", ".go", ".rs",
}


def read_payload_file(path: Path) -> str | None:
    """Read a payload file and return its content."""
    try:
        text = path.read_text(errors="ignore")
    except Exception:
        return None

    if not text or len(text) < 20:
        return None

    return text[:4000]


def process(max_samples: int = 15000, seed: int = 42):
    """Process PayloadsAllTheThings and output labeled JSONL."""
    random.seed(seed)
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    out_path = OUT_DIR / "payloads.jsonl"

    if not RAW_DIR.exists():
        print(f"ERROR: PayloadsAllTheThings not found at {RAW_DIR}")
        sys.exit(1)

    print("Scanning PayloadsAllTheThings directory tree...")

    # Collect samples by subcategory
    by_subcat = defaultdict(list)
    total_files = 0

    for dir_entry in sorted(RAW_DIR.iterdir()):
        if not dir_entry.is_dir():
            continue
        dir_name = dir_entry.name
        if dir_name in SKIP_DIRS:
            continue

        mapping = DIR_MAP.get(dir_name)
        if not mapping:
            continue

        subcat, severity, attack_type = mapping

        # Walk the directory for payload files
        for root, _, files in os.walk(dir_entry):
            for fname in files:
                fpath = Path(root) / fname
                ext = fpath.suffix.lower()

                if ext not in PAYLOAD_EXTENSIONS:
                    continue

                text = read_payload_file(fpath)
                if not text:
                    continue

                total_files += 1
                rel_path = fpath.relative_to(RAW_DIR)

                explanation = (
                    f"{attack_type} payload from {dir_name}/{fname}. "
                    f"Contains attack vectors, exploitation techniques, "
                    f"or proof-of-concept code that could be used for malicious purposes."
                )

                sample = {
                    "text": text,
                    "subcategory": subcat,
                    "findings": [{
                        "category": "malicious",
                        "subcategory": subcat,
                        "severity": severity,
                        "explanation": explanation,
                    }],
                }
                by_subcat[subcat].append(sample)

    print(f"Found {total_files:,} payload files")
    print(f"Samples by subcategory:")
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
                "id": f"payloads_{i:05d}",
                "source": "payloads_all_the_things",
                "source_license": "MIT",
                "text": item["text"],
                "findings": item["findings"],
            }
            fout.write(json.dumps(record) + "\n")

    print(f"\nWrote {len(selected):,} samples to {out_path}")
    print("\nCategory distribution:")
    for sub, count in sorted(subcat_counts.items()):
        print(f"  {sub}: {count}")


if __name__ == "__main__":
    max_n = int(sys.argv[1]) if len(sys.argv) > 1 else 15000
    process(max_samples=max_n)
