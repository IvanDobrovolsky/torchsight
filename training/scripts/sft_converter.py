#!/usr/bin/env python3
"""
TorchSight SFT Converter

Converts the combined training JSONL into prompt/completion pairs
suitable for supervised fine-tuning with LoRA/QLoRA.

Supports multiple output formats:
- alpaca: instruction/input/output (most common for LoRA)
- chatml: messages array (ChatML format)
- completion: simple prompt/completion pairs

Usage:
    python sft_converter.py                          # Default: alpaca format
    python sft_converter.py --format chatml           # ChatML format
    python sft_converter.py --format completion       # Simple completion
    python sft_converter.py --max-length 2048         # Truncate long texts
    python sft_converter.py --val-split 0.05          # 5% validation split
"""

import json
import random
import sys
from pathlib import Path
from typing import Any

SCRIPT_DIR = Path(__file__).resolve().parent
DATA_DIR = SCRIPT_DIR.parent / "data"
COMBINED_PATH = DATA_DIR / "processed" / "combined_train.jsonl"
OUTPUT_DIR = DATA_DIR / "sft"

# System prompt for the model
SYSTEM_PROMPT = """You are TorchSight, a cybersecurity document classifier. Analyze the provided text and identify any security-relevant findings.

For each finding, output a JSON object with:
- category: one of [pii, credentials, financial, medical, confidential, malicious, safe]
- subcategory: specific type (e.g., pii.identity, malicious.injection, credentials.api_key)
- severity: one of [critical, high, medium, low, info]
- explanation: brief explanation of what was found

If the text is clean/safe, output a finding with category "safe" and appropriate subcategory.

Respond ONLY with a JSON array of findings."""

# Instruction templates (randomly selected for variety)
INSTRUCTION_TEMPLATES = [
    "Analyze the following text for security threats, sensitive data, and policy violations.",
    "Classify the security content in this document.",
    "Scan this text and identify any sensitive information, credentials, or malicious content.",
    "Review the following content for security findings.",
    "Identify any PII, credentials, malicious payloads, or classified information in this text.",
    "Perform a security analysis of this document.",
    "Examine this content for data leakage, threats, and compliance issues.",
]


def format_findings_output(findings: list[dict], source_text: str = "") -> str:
    """Format findings as the expected model output with rich explanations."""
    output_findings = []
    for f in findings:
        entry = {
            "category": f.get("category", "unknown"),
            "subcategory": f.get("subcategory", "unknown"),
            "severity": f.get("severity", "medium"),
        }
        entry["explanation"] = build_explanation(f, source_text)
        output_findings.append(entry)
    return json.dumps(output_findings, indent=2)


def build_explanation(finding: dict, source_text: str) -> str:
    """Build a descriptive explanation from finding fields and source text."""
    category = finding.get("category", "")
    subcategory = finding.get("subcategory", "")
    fields = finding.get("fields", {})
    evidence = finding.get("evidence", "")
    explanation = finding.get("explanation", "")

    # If we already have a good explanation, use it
    if explanation and len(explanation) > 30:
        return explanation[:200]

    # --- SAFE: describe the document ---
    if category == "safe":
        return build_safe_description(fields, source_text)

    # --- MALICIOUS: use evidence or explanation ---
    if category == "malicious":
        if evidence:
            return f"Found: {evidence[:180]}"
        if explanation:
            return explanation[:200]
        return build_from_text_context(subcategory, source_text)

    # --- PII ---
    if category == "pii":
        return build_pii_explanation(subcategory, fields, source_text)

    # --- CREDENTIALS ---
    if category == "credentials":
        return build_credentials_explanation(subcategory, fields, source_text)

    # --- FINANCIAL ---
    if category == "financial":
        return build_financial_explanation(subcategory, fields, source_text)

    # --- MEDICAL ---
    if category == "medical":
        return build_medical_explanation(subcategory, fields, source_text)

    # --- CONFIDENTIAL ---
    if category == "confidential":
        return build_confidential_explanation(subcategory, fields, source_text)

    # Fallback
    return build_from_text_context(subcategory, source_text)


def get_first_line(text: str) -> str:
    """Get meaningful first line from text."""
    for line in text.strip().split("\n"):
        line = line.strip()
        if line and len(line) > 5 and not line.startswith(("=", "-", "#", "*", "/")):
            return line[:120]
    return text.strip()[:120]


def build_safe_description(fields: dict, source_text: str) -> str:
    """Describe what a clean/safe document contains."""
    content_type = fields.get("content_type", "")
    first_line = get_first_line(source_text)

    type_labels = {
        "business_document": "Business document",
        "technical_documentation": "Technical documentation",
        "code": "Source code file",
        "configuration": "Configuration file",
        "creative_writing": "Creative writing",
        "news_article": "News article",
        "academic_paper": "Academic paper",
        "personal_correspondence": "Personal correspondence",
        "legal_boilerplate": "Legal boilerplate text",
    }

    label = type_labels.get(content_type, "Document")
    # Combine type with first line for a rich description
    if first_line:
        return f"{label}: {first_line}. No sensitive data detected."
    return f"{label} with no sensitive or malicious content."


def build_pii_explanation(subcategory: str, fields: dict, source_text: str) -> str:
    """Build explanation for PII findings."""
    parts = []

    if subcategory == "pii.identity":
        names = fields.get("full_name", [])
        ssns = fields.get("ssn", [])
        if names:
            name_str = ", ".join(names[:3])
            parts.append(f"personal identity information for {name_str}")
        if ssns:
            parts.append(f"Social Security Number(s) found")
        if not parts:
            parts.append("personally identifiable information (names, IDs)")

    elif subcategory == "pii.contact":
        emails = fields.get("email", [])
        phones = fields.get("phone", [])
        addresses = fields.get("address", [])
        if emails:
            parts.append(f"{len(emails)} email address(es)")
        if phones:
            parts.append(f"phone number(s)")
        if addresses:
            parts.append(f"physical address(es)")
        if not parts:
            parts.append("contact information (email, phone, address)")

    elif subcategory == "pii.government_id":
        ssns = fields.get("ssn", [])
        dl = fields.get("driver_license", [])
        if ssns:
            parts.append(f"{len(ssns)} Social Security Number(s)")
        if dl:
            parts.append("driver's license number(s)")
        if not parts:
            parts.append("government-issued identification number(s)")

    elif subcategory == "pii.biometric":
        parts.append("biometric data")

    else:
        parts.append(subcategory.replace("pii.", "") + " data")

    context = get_document_context(source_text)
    result = "Found " + " and ".join(parts)
    if context:
        result += f" in {context}"
    return result[:200]


def build_credentials_explanation(subcategory: str, fields: dict, source_text: str) -> str:
    """Build explanation for credential findings."""
    pw_refs = fields.get("password_reference", [])
    api_keys = fields.get("api_key", [])

    if subcategory == "credentials.password":
        if pw_refs:
            # Show the password reference but redact the actual value
            ref = pw_refs[0][:80]
            return f"Password credential exposed: '{ref}'"
        return "Plaintext password found in document"

    elif subcategory == "credentials.api_key":
        if api_keys:
            key_preview = api_keys[0][:20] + "..."
            return f"API key exposed: {key_preview}"
        return "API key or access token found in document"

    elif subcategory == "credentials.private_key":
        return "Private cryptographic key found (SSH, TLS, or PGP)"

    elif subcategory == "credentials.connection_string":
        return "Database connection string with credentials found"

    elif subcategory == "credentials.token":
        return "Authentication token or session token found"

    context = get_document_context(source_text)
    desc = subcategory.replace("credentials.", "")
    result = f"Credential found: {desc}"
    if context:
        result += f" in {context}"
    return result[:200]


def build_financial_explanation(subcategory: str, fields: dict, source_text: str) -> str:
    """Build explanation for financial findings."""
    amounts = fields.get("amounts", [])
    keywords = fields.get("keywords", [])

    if subcategory == "financial.transaction":
        if amounts:
            amt_str = ", ".join(amounts[:3])
            desc = f"Financial transaction(s) with amounts: {amt_str}"
        else:
            desc = "Financial transaction data"
        if keywords:
            desc += f" ({', '.join(keywords[:3])})"
        return desc[:200]

    elif subcategory == "financial.bank_account":
        return "Bank account number(s) found in document"

    elif subcategory == "financial.credit_card":
        return "Credit card number(s) found in document"

    elif subcategory == "financial.government_id":
        return "Government financial identifier (SSN, TIN, EIN) found"

    context = get_document_context(source_text)
    desc = subcategory.replace("financial.", "")
    result = f"Financial data: {desc}"
    if context:
        result += f" in {context}"
    return result[:200]


def build_medical_explanation(subcategory: str, fields: dict, source_text: str) -> str:
    """Build explanation for medical findings."""
    specialty = fields.get("medical_specialty", "")
    keywords = fields.get("keywords", "")

    if subcategory == "medical.diagnosis":
        if specialty:
            return f"{specialty} medical record with patient diagnosis and treatment information"
        return "Medical record containing patient diagnosis information"

    elif subcategory == "medical.prescription":
        if specialty:
            return f"Prescription record from {specialty} department"
        return "Prescription or medication record found"

    elif subcategory == "medical.lab_results":
        return "Laboratory test results with patient health data"

    elif subcategory == "medical.insurance":
        return "Health insurance information with policy details"

    context = get_document_context(source_text)
    desc = subcategory.replace("medical.", "")
    result = f"Protected health information: {desc}"
    if context and specialty:
        result += f" ({specialty})"
    return result[:200]


def build_confidential_explanation(subcategory: str, fields: dict, source_text: str) -> str:
    """Build explanation for confidential findings."""
    first_line = get_first_line(source_text)

    if subcategory == "confidential.military":
        return f"Military/defense document: {first_line}"

    elif subcategory == "confidential.intelligence":
        return f"Intelligence-related content: {first_line}"

    elif subcategory == "confidential.weapons_systems":
        return f"Weapons systems or technical defense data: {first_line}"

    elif subcategory == "confidential.internal":
        return f"Internal/confidential document: {first_line}"

    elif subcategory == "confidential.classified":
        return f"Classified document with security markings: {first_line}"

    return f"Confidential content: {first_line}"[:200]


def get_document_context(source_text: str) -> str:
    """Extract brief document context from first line."""
    first = get_first_line(source_text)
    if not first or len(first) < 10:
        return ""
    # Try to identify document type from first line
    lower = first.lower()
    if "message-id" in lower or "from:" in lower:
        return "email message"
    if "patient" in lower or "dob:" in lower:
        return "medical record"
    if "crs report" in lower:
        return "CRS report"
    if "advisory" in lower or "cve" in lower:
        return "security advisory"
    if "meeting" in lower:
        return "meeting notes"
    if "job description" in lower:
        return "job posting"
    return ""


def build_from_text_context(subcategory: str, source_text: str) -> str:
    """Fallback: build explanation from subcategory and text context."""
    context = get_document_context(source_text)
    sub_label = subcategory.split(".")[-1].replace("_", " ") if "." in subcategory else subcategory
    result = f"Found {sub_label} content"
    if context:
        result += f" in {context}"
    return result


def truncate_text(text: str, max_length: int) -> str:
    """Truncate text to max_length characters, breaking at word boundary."""
    if len(text) <= max_length:
        return text
    truncated = text[:max_length]
    # Break at last space
    last_space = truncated.rfind(" ")
    if last_space > max_length * 0.7:
        truncated = truncated[:last_space]
    return truncated + "\n[...truncated...]"


def convert_alpaca(record: dict, max_length: int) -> dict:
    """Convert to Alpaca format: instruction/input/output."""
    text = truncate_text(record["text"], max_length)
    instruction = random.choice(INSTRUCTION_TEMPLATES)
    output = format_findings_output(record.get("findings", []), record.get("text", ""))

    return {
        "instruction": instruction,
        "input": text,
        "output": output,
    }


def convert_chatml(record: dict, max_length: int) -> dict:
    """Convert to ChatML messages format."""
    text = truncate_text(record["text"], max_length)
    instruction = random.choice(INSTRUCTION_TEMPLATES)
    output = format_findings_output(record.get("findings", []), record.get("text", ""))

    return {
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": f"{instruction}\n\n{text}"},
            {"role": "assistant", "content": output},
        ]
    }


def convert_completion(record: dict, max_length: int) -> dict:
    """Convert to simple prompt/completion format."""
    text = truncate_text(record["text"], max_length)
    instruction = random.choice(INSTRUCTION_TEMPLATES)
    output = format_findings_output(record.get("findings", []), record.get("text", ""))

    prompt = f"### System:\n{SYSTEM_PROMPT}\n\n### User:\n{instruction}\n\n{text}\n\n### Assistant:\n"
    return {
        "prompt": prompt,
        "completion": output,
    }


def main():
    # Parse args
    fmt = "alpaca"
    max_length = 4096
    val_split = 0.05
    seed = 42

    args = sys.argv[1:]
    i = 0
    while i < len(args):
        if args[i] == "--format" and i + 1 < len(args):
            fmt = args[i + 1]
            i += 2
        elif args[i] == "--max-length" and i + 1 < len(args):
            max_length = int(args[i + 1])
            i += 2
        elif args[i] == "--val-split" and i + 1 < len(args):
            val_split = float(args[i + 1])
            i += 2
        elif args[i] == "--seed" and i + 1 < len(args):
            seed = int(args[i + 1])
            i += 2
        else:
            print(f"Unknown arg: {args[i]}")
            sys.exit(1)

    converters = {
        "alpaca": convert_alpaca,
        "chatml": convert_chatml,
        "completion": convert_completion,
    }

    if fmt not in converters:
        print(f"Unknown format: {fmt}. Available: {', '.join(converters.keys())}")
        sys.exit(1)

    convert_fn = converters[fmt]
    random.seed(seed)

    # Read all records
    print(f"Reading {COMBINED_PATH}...")
    records = []
    with open(COMBINED_PATH) as f:
        for line in f:
            line = line.strip()
            if line:
                records.append(json.loads(line))

    print(f"  Loaded {len(records):,} records")

    # Shuffle
    random.shuffle(records)

    # Split
    val_count = int(len(records) * val_split)
    train_records = records[val_count:]
    val_records = records[:val_count]

    print(f"  Train: {len(train_records):,} | Validation: {len(val_records):,}")

    # Convert
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    train_path = OUTPUT_DIR / f"train_{fmt}.jsonl"
    val_path = OUTPUT_DIR / f"val_{fmt}.jsonl"

    skipped = 0
    for split_name, split_records, out_path in [
        ("train", train_records, train_path),
        ("val", val_records, val_path),
    ]:
        with open(out_path, "w") as f:
            for record in split_records:
                if not record.get("findings"):
                    skipped += 1
                    continue
                converted = convert_fn(record, max_length)
                f.write(json.dumps(converted) + "\n")

        count = sum(1 for _ in open(out_path))
        print(f"  Wrote {count:,} samples to {out_path.name}")

    if skipped:
        print(f"  Skipped {skipped} records with no findings")

    # Stats
    print(f"\nOutput format: {fmt}")
    print(f"Max text length: {max_length}")
    print(f"Output directory: {OUTPUT_DIR}")

    # Show a sample
    print(f"\n{'=' * 60}")
    print("Sample output:")
    print(f"{'=' * 60}")
    sample = convert_fn(records[0], max_length)
    print(json.dumps(sample, indent=2)[:1000])


if __name__ == "__main__":
    main()
