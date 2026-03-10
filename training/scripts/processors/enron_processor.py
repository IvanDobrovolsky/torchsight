#!/usr/bin/env python3
"""
Enron Email Processor for TorchSight Training

Extracts PII-rich emails, parses structured fields,
and outputs labeled JSONL samples.

Targets: pii.identity, pii.contact, credentials.password,
         confidential.internal, financial.transaction
"""

import json
import os
import random
import re
import sys
from pathlib import Path

RAW_DIR = Path(__file__).parent.parent.parent / "data" / "raw" / "enron"
OUT_DIR = Path(__file__).parent.parent.parent / "data" / "processed"

# Regex patterns for field extraction
PATTERNS = {
    "email": re.compile(r'[\w.+-]+@[\w-]+\.[\w.-]+'),
    "phone": re.compile(r'(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}'),
    "ssn": re.compile(r'\b\d{3}-\d{2}-\d{4}\b'),
    "address": re.compile(
        r'\d+\s+[\w\s]+(?:Street|St|Avenue|Ave|Boulevard|Blvd|Drive|Dr|Road|Rd|Lane|Ln|Way|Court|Ct|Circle|Cir|Place|Pl)\b'
        r'[,.\s]*(?:Suite|Ste|Apt|Unit|#)?\s*\d*',
        re.IGNORECASE
    ),
    "zip_code": re.compile(r'\b\d{5}(?:-\d{4})?\b'),
    "password_line": re.compile(r'(?:password|passwd|pwd)\s*[:=]\s*\S+', re.IGNORECASE),
    "dollar_amount": re.compile(r'\$[\d,]+(?:\.\d{2})?'),
}

# Keywords for confidential/internal detection
CONFIDENTIAL_KEYWORDS = [
    "confidential", "do not distribute", "do not disclose", "internal only",
    "privileged", "attorney-client", "trade secret", "not for distribution",
    "document retention", "litigation hold", "executive committee",
]

# Keywords for financial content
FINANCIAL_KEYWORDS = [
    "invoice", "payment", "wire transfer", "credit card", "bank account",
    "million", "billion", "settlement", "damages", "compensation",
]


def parse_email(path: Path) -> dict | None:
    """Parse a single Enron email file into structured data."""
    try:
        text = path.read_text(errors="ignore")
    except Exception:
        return None

    if len(text) < 50:
        return None

    # Split headers and body
    parts = text.split("\n\n", 1)
    headers_text = parts[0] if parts else ""
    body = parts[1] if len(parts) > 1 else ""

    # Parse headers
    headers = {}
    for line in headers_text.split("\n"):
        if ": " in line and not line.startswith(" ") and not line.startswith("\t"):
            key, _, val = line.partition(": ")
            headers[key.strip()] = val.strip()

    # Extract display names from X-From/X-To
    x_from = headers.get("X-From", "")
    x_to = headers.get("X-To", "")
    from_addr = headers.get("From", "")
    subject = headers.get("Subject", "")

    # Extract fields from full text
    full_text = text
    fields = {}
    findings = []

    # Names
    names = set()
    for field in [x_from, x_to]:
        # Extract "Last, First" or "First Last" before any LDAP path
        name = re.sub(r'\s*<.*', '', field)
        name = re.sub(r'\s*/.*', '', name)
        name = name.strip().strip('"').strip("'")
        if name and len(name) > 3 and not name.startswith("/"):
            names.add(name)

    # Emails
    emails = set(PATTERNS["email"].findall(full_text))
    emails = {e for e in emails if not e.endswith(".gif") and not e.endswith(".jpg")}

    # Phones
    phones = set(PATTERNS["phone"].findall(body))

    # SSNs
    ssns = set(PATTERNS["ssn"].findall(full_text))

    # Addresses
    addresses = set(PATTERNS["address"].findall(body))

    # Passwords
    passwords = set(PATTERNS["password_line"].findall(full_text))

    # Dollar amounts
    amounts = set(PATTERNS["dollar_amount"].findall(full_text))

    # Build findings
    if names or ssns:
        fields_identity = {}
        if names:
            fields_identity["full_name"] = list(names)[:5]
        if ssns:
            fields_identity["ssn"] = list(ssns)
        findings.append({
            "category": "pii",
            "subcategory": "pii.identity",
            "severity": "critical" if ssns else "medium",
            "compliance": ["GDPR", "CCPA"] + (["HIPAA"] if ssns else []),
            "fields": fields_identity,
        })

    if emails or phones or addresses:
        fields_contact = {}
        if emails:
            fields_contact["email"] = list(emails)[:5]
        if phones:
            fields_contact["phone"] = list(phones)[:3]
        if addresses:
            fields_contact["address"] = list(addresses)[:2]
        findings.append({
            "category": "pii",
            "subcategory": "pii.contact",
            "severity": "medium",
            "compliance": ["GDPR", "CCPA"],
            "fields": fields_contact,
        })

    if passwords:
        findings.append({
            "category": "credentials",
            "subcategory": "credentials.password",
            "severity": "critical",
            "compliance": ["NIST-800-53"],
            "fields": {"password_reference": list(passwords)[:3]},
        })

    # Check for confidential content
    body_lower = body.lower()
    conf_matches = [kw for kw in CONFIDENTIAL_KEYWORDS if kw in body_lower]
    if conf_matches:
        findings.append({
            "category": "confidential",
            "subcategory": "confidential.internal",
            "severity": "high",
            "compliance": [],
            "fields": {"markers": conf_matches},
        })

    # Check for financial content
    fin_matches = [kw for kw in FINANCIAL_KEYWORDS if kw in body_lower]
    if fin_matches and amounts:
        findings.append({
            "category": "financial",
            "subcategory": "financial.transaction",
            "severity": "high",
            "compliance": ["SOX"],
            "fields": {"amounts": list(amounts)[:5], "keywords": fin_matches},
        })

    if not findings:
        return None

    return {
        "source_path": str(path.relative_to(RAW_DIR)),
        "subject": subject,
        "text": full_text[:4000],
        "findings": findings,
    }


def score_email(parsed: dict) -> int:
    """Score an email by PII richness for sampling priority."""
    score = 0
    for f in parsed["findings"]:
        if f["subcategory"] == "pii.identity":
            score += 10
            if "ssn" in f["fields"]:
                score += 100
        elif f["subcategory"] == "pii.contact":
            score += 5
            if "phone" in f["fields"]:
                score += 3
            if "address" in f["fields"]:
                score += 5
        elif f["subcategory"] == "credentials.password":
            score += 50
        elif f["subcategory"] == "confidential.internal":
            score += 20
        elif f["subcategory"] == "financial.transaction":
            score += 15
    return score


def process(max_samples: int = 2000, seed: int = 42):
    """Process Enron emails and output labeled JSONL."""
    random.seed(seed)
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    out_path = OUT_DIR / "enron.jsonl"

    if not RAW_DIR.exists():
        print(f"ERROR: Enron data not found at {RAW_DIR}")
        sys.exit(1)

    # Collect all email file paths
    print("Scanning Enron mailboxes...")
    all_paths = []
    for root, _, files in os.walk(RAW_DIR):
        for f in files:
            p = Path(root) / f
            if p.is_file() and not p.name.endswith((".tar.gz", ".zip")):
                all_paths.append(p)

    print(f"Found {len(all_paths):,} email files")

    # Sample a manageable subset for initial pass
    sample_size = min(50_000, len(all_paths))
    sampled = random.sample(all_paths, sample_size)

    print(f"Parsing {sample_size:,} sampled emails...")
    parsed_emails = []
    for i, path in enumerate(sampled):
        if i % 10000 == 0 and i > 0:
            print(f"  ...parsed {i:,}")
        result = parse_email(path)
        if result:
            parsed_emails.append(result)

    print(f"Found {len(parsed_emails):,} emails with findings")

    # Sort by richness score and take top N
    parsed_emails.sort(key=score_email, reverse=True)
    selected = parsed_emails[:max_samples]

    # Ensure category diversity
    by_subcat = {}
    for email in selected:
        for f in email["findings"]:
            sub = f["subcategory"]
            if sub not in by_subcat:
                by_subcat[sub] = 0
            by_subcat[sub] += 1

    # Write output
    with open(out_path, "w") as fout:
        for i, email in enumerate(selected):
            record = {
                "id": f"enron_{i:05d}",
                "source": "enron",
                "source_license": "public_ferc",
                "text": email["text"],
                "findings": email["findings"],
            }
            fout.write(json.dumps(record) + "\n")

    print(f"\nWrote {len(selected):,} samples to {out_path}")
    print("\nCategory distribution:")
    for sub, count in sorted(by_subcat.items()):
        print(f"  {sub}: {count}")


if __name__ == "__main__":
    max_n = int(sys.argv[1]) if len(sys.argv) > 1 else 2000
    process(max_samples=max_n)
