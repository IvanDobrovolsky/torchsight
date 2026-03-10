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
COMBINED_PATH = DATA_DIR / "processed" / "combined_train_balanced.jsonl"
OUTPUT_DIR = DATA_DIR / "sft"

# System prompt for the model
SYSTEM_PROMPT = """You are TorchSight, a cybersecurity document classifier. Analyze the provided text and identify ALL security-relevant findings.

For each finding, output a JSON object with:
- category: one of [pii, credentials, financial, medical, confidential, malicious, safe]
- subcategory: specific type (e.g., pii.identity, malicious.injection, credentials.api_key)
- severity: one of [critical, high, medium, low, info]
- explanation: detailed explanation including specific values found (redact sensitive parts, e.g., SSN: 412-XX-7890, API key: sk_live_51HG...). Explain what was found, why it matters, and the risk.

If a document contains multiple types of sensitive data, return a finding for EACH one.
If the text is clean/safe, output a single finding with category "safe".

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
    """Build a rich explanation with extracted values from finding fields and source text."""
    category = finding.get("category", "")
    subcategory = finding.get("subcategory", "")
    fields = finding.get("fields", {})
    evidence = finding.get("evidence", "")
    explanation = finding.get("explanation", "")

    # --- SAFE: describe the document ---
    if category == "safe":
        return build_safe_description(fields, source_text)

    # --- MALICIOUS ---
    if category == "malicious":
        return build_malicious_explanation(subcategory, fields, evidence, explanation, source_text)

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


def extract_from_text(source_text: str, patterns: list[tuple[str, str]]) -> dict[str, str]:
    """Extract values from source text using simple keyword matching."""
    import re
    found = {}
    text_lower = source_text.lower()
    for label, pattern in patterns:
        match = re.search(pattern, source_text, re.IGNORECASE)
        if match:
            val = match.group(0).strip()
            # Partially redact sensitive values
            if label in ("ssn",) and len(val) >= 7:
                found[label] = val[:3] + "-XX-" + val[-4:]
            elif label in ("api_key", "token", "password") and len(val) > 12:
                found[label] = val[:12] + "..."
            elif label in ("credit_card",) and len(val) >= 12:
                found[label] = val[:4] + "-XXXX-XXXX-" + val[-4:]
            else:
                found[label] = val[:60]
    return found


def build_pii_explanation(subcategory: str, fields: dict, source_text: str) -> str:
    """Build explanation for PII findings with extracted values."""
    parts = []
    extracted = extract_from_text(source_text, [
        ("name", r"(?:Name|name)[:\s]+([A-Z][a-z]+ [A-Z][a-z]+)"),
        ("ssn", r"\d{3}-\d{2}-\d{4}"),
        ("email", r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"),
        ("phone", r"[\(]?\d{3}[\)]?[\s.-]\d{3}[\s.-]\d{4}"),
        ("dob", r"(?:DOB|Date of Birth|dob)[:\s]+[\d/.-]+"),
    ])

    if subcategory == "pii.identity":
        names = fields.get("full_name", [])
        ssns = fields.get("ssn", [])
        name_str = ", ".join(names[:2]) if names else extracted.get("name", "")
        ssn_str = extracted.get("ssn", "")
        if name_str and ssn_str:
            parts.append(f"Identity data for {name_str} with SSN {ssn_str}")
        elif name_str:
            parts.append(f"Identity data for {name_str}")
        elif ssn_str:
            parts.append(f"SSN found: {ssn_str}")
        else:
            parts.append("Personally identifiable information (names, IDs)")
        if extracted.get("dob"):
            parts.append(f"DOB: {extracted['dob']}")

    elif subcategory == "pii.contact":
        if extracted.get("email"):
            parts.append(f"Email: {extracted['email']}")
        if extracted.get("phone"):
            parts.append(f"Phone: {extracted['phone']}")
        if not parts:
            parts.append("Contact information (email, phone, address)")

    elif subcategory == "pii.government_id":
        if extracted.get("ssn"):
            parts.append(f"Government ID — SSN: {extracted['ssn']}")
        else:
            parts.append("Government-issued identification number")

    elif subcategory == "pii.biometric":
        parts.append("Biometric data (fingerprint, iris, or facial recognition template)")

    elif subcategory == "pii.behavioral":
        parts.append("Behavioral tracking data — user activity patterns that can identify individuals")

    elif subcategory == "pii.metadata":
        parts.append("Metadata containing user-identifying information")

    else:
        parts.append(f"{subcategory.replace('pii.', '').replace('_', ' ')} data")

    context = get_document_context(source_text)
    result = ". ".join(parts)
    if context:
        result += f". Found in {context}"
    result += ". Risk: identity theft, privacy violation"
    return result[:300]


def build_credentials_explanation(subcategory: str, fields: dict, source_text: str) -> str:
    """Build explanation for credential findings with extracted values."""
    import re
    extracted = extract_from_text(source_text, [
        ("api_key", r"(?:sk_live_|sk_test_|AKIA|ghp_|xoxb-|SG\.|rk_live_|npm_)[A-Za-z0-9_/+=.-]{8,}"),
        ("password", r"(?:password|passwd|pass|pwd)[=:\s]+['\"]?([^\s'\"]{4,40})"),
        ("token", r"(?:token|bearer|auth)[=:\s]+['\"]?([A-Za-z0-9_/+=.-]{10,})"),
        ("conn_string", r"(?:postgres|mysql|mongodb|redis)://[^\s]{10,80}"),
        ("private_key", r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    ])

    if subcategory == "credentials.password":
        pw = extracted.get("password", "")
        if pw:
            return f"Hardcoded password found: {pw}. Plaintext credentials in source code or config files can be extracted by anyone with read access. Move to environment variables or a secrets manager."
        return "Plaintext password found in document. Credentials should never be stored in plain text — use hashing for storage and environment variables for configuration."

    elif subcategory == "credentials.api_key":
        key = extracted.get("api_key", "")
        if key:
            svc = "Stripe" if "sk_" in key else "AWS" if "AKIA" in key else "GitHub" if "ghp_" in key else "external service"
            return f"{svc} API key exposed: {key}. This key grants access to the {svc} API and should be rotated immediately. Store API keys in environment variables, not source code."
        return "API key or access token found in document. Exposed keys grant unauthorized access to external services and should be rotated."

    elif subcategory == "credentials.private_key":
        return "Private cryptographic key (RSA/EC/SSH) found in file. Private keys enable impersonation, decryption of traffic, and unauthorized access. Never store private keys in repositories or shared locations."

    elif subcategory == "credentials.connection_string":
        cs = extracted.get("conn_string", "")
        if cs:
            return f"Database connection string with embedded credentials: {cs[:40]}... Contains hostname, username, and password for direct database access. Use environment variables or a secrets manager."
        return "Database connection string with embedded credentials found. Contains authentication details for direct database access."

    elif subcategory == "credentials.token":
        tok = extracted.get("token", "")
        if tok:
            return f"Authentication token exposed: {tok}. Session or auth tokens grant access to user accounts and should never be logged or stored in plain text."
        return "Authentication or session token found. Tokens grant access to user sessions and protected resources."

    elif subcategory == "credentials.cloud_config":
        key = extracted.get("api_key", "")
        if key:
            return f"Cloud provider credentials exposed: {key}. These credentials provide access to cloud infrastructure (compute, storage, databases). Rotate immediately and use IAM roles instead."
        return "Cloud provider credentials found (AWS, GCP, or Azure). Cloud keys provide broad infrastructure access and should be managed through IAM roles, not static keys."

    elif subcategory == "credentials.cicd":
        return "CI/CD pipeline credentials found. These grant access to build and deployment systems and could be used to inject malicious code into the software supply chain."

    elif subcategory == "credentials.container":
        return "Container registry or orchestration credentials found. These provide access to container images and cluster management."

    context = get_document_context(source_text)
    desc = subcategory.replace("credentials.", "").replace("_", " ")
    result = f"Credential found: {desc}"
    if context:
        result += f" in {context}"
    return result[:300]


def build_financial_explanation(subcategory: str, fields: dict, source_text: str) -> str:
    """Build explanation for financial findings with extracted values."""
    import re
    extracted = extract_from_text(source_text, [
        ("amount", r"\$[\d,]+(?:\.\d{2})?"),
        ("credit_card", r"\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b"),
        ("routing", r"(?:routing|ABA)[:\s#]+(\d{9})"),
        ("account", r"(?:account|acct)[:\s#]+[\d-]{6,}"),
    ])

    if subcategory == "financial.transaction":
        amt = extracted.get("amount", "")
        if amt:
            return f"Financial transaction detected with amount {amt}. Wire transfer or payment instructions with beneficiary details. Risk: unauthorized fund transfers, financial fraud. Compliance: SOX, PCI-DSS."
        return "Financial transaction data found including payment amounts and transfer details. Risk: unauthorized fund movement if exposed."

    elif subcategory == "financial.bank_account":
        acct = extracted.get("account", "")
        routing = extracted.get("routing", "")
        if acct and routing:
            return f"Bank account details: routing {routing}, account {acct}. Sufficient for initiating unauthorized ACH transfers. Compliance: PCI-DSS, SOX."
        return "Bank account number(s) found. Account and routing numbers enable unauthorized transfers. Compliance: PCI-DSS, SOX."

    elif subcategory == "financial.credit_card":
        cc = extracted.get("credit_card", "")
        if cc:
            return f"Credit card number found: {cc}. Full card numbers enable unauthorized charges. Must be encrypted per PCI-DSS. Immediate risk: financial fraud."
        return "Credit card number found in document. PCI-DSS violation — card data must be encrypted and access-controlled."

    elif subcategory == "financial.tax":
        amt = extracted.get("amount", "")
        return f"Tax document with financial details{' (amounts: ' + amt + ')' if amt else ''}. Contains income, deductions, and potentially SSN. Compliance: IRS regulations, state tax law."

    context = get_document_context(source_text)
    desc = subcategory.replace("financial.", "").replace("_", " ")
    result = f"Financial data: {desc}"
    if context:
        result += f" in {context}"
    return result[:300]


def build_medical_explanation(subcategory: str, fields: dict, source_text: str) -> str:
    """Build explanation for medical findings with extracted values."""
    import re
    specialty = fields.get("medical_specialty", "")

    # Try to extract diagnosis from text
    dx_match = re.search(r"(?:diagnosis|dx|assessment)[:\s]+(.{10,80})", source_text, re.IGNORECASE)
    dx = dx_match.group(1).strip().rstrip(".") if dx_match else ""

    # Try to extract patient name
    name_match = re.search(r"(?:patient|name)[:\s]+([A-Z][a-z]+ [A-Z][a-z]+)", source_text, re.IGNORECASE)
    name = name_match.group(1) if name_match else ""

    if subcategory == "medical.diagnosis":
        parts = ["Protected health information (PHI)"]
        if dx:
            parts.append(f"diagnosis: {dx}")
        if name:
            parts.append(f"patient: {name}")
        if specialty:
            parts.append(f"specialty: {specialty}")
        return ". ".join(parts) + ". HIPAA-protected — unauthorized disclosure may result in penalties up to $50,000 per violation."

    elif subcategory == "medical.prescription":
        parts = ["Prescription/medication record"]
        if name:
            parts.append(f"for {name}")
        med_match = re.search(r"(?:rx|prescription|medication)[:\s]+(.{5,60})", source_text, re.IGNORECASE)
        if med_match:
            parts.append(f"medication: {med_match.group(1).strip()}")
        return " ".join(parts) + ". HIPAA-protected PHI including patient identity and treatment details."

    elif subcategory in ("medical.lab_results", "medical.lab_result"):
        return f"Laboratory test results{' for ' + name if name else ''} with diagnostic values. HIPAA-protected PHI — lab data reveals health conditions and must be secured."

    elif subcategory == "medical.insurance":
        return f"Health insurance information{' for ' + name if name else ''} with policy and member details. HIPAA-protected — includes coverage information tied to patient identity."

    return f"Protected health information ({subcategory.split('.')[-1]}). HIPAA compliance required — unauthorized access or disclosure is a federal violation."


def build_malicious_explanation(subcategory: str, fields: dict, evidence: str, explanation: str, source_text: str) -> str:
    """Build explanation for malicious findings with specific payload details."""
    import re
    first_line = get_first_line(source_text)

    descs = {
        "malicious.injection": "SQL injection, XSS, or command injection payload",
        "malicious.exploit": "Exploit code targeting a known vulnerability",
        "malicious.malware": "Malware, backdoor, or trojan indicator",
        "malicious.phishing": "Phishing or social engineering attempt",
        "malicious.prompt_injection": "LLM prompt injection attempting to override system instructions",
        "malicious.supply_chain": "Supply chain attack — malicious or typosquatted package",
        "malicious.shell": "Reverse shell or remote command execution",
        "malicious.xxe": "XML External Entity (XXE) attack for file read or SSRF",
        "malicious.ssti": "Server-Side Template Injection allowing code execution",
        "malicious.ssrf": "Server-Side Request Forgery targeting internal services",
        "malicious.deserialization": "Insecure deserialization enabling remote code execution",
        "malicious.redos": "Regular Expression Denial of Service (ReDoS) pattern",
        "malicious.steganography": "Steganography — hidden data embedded in media files",
        "malicious.prototype_pollution": "Prototype pollution enabling privilege escalation",
    }

    base = descs.get(subcategory, f"Malicious content ({subcategory.split('.')[-1]})")

    # Add evidence/payload preview
    if evidence and len(evidence) > 10:
        payload_preview = evidence[:100].replace("\n", " ")
        return f"{base}. Payload: {payload_preview}. Immediate security risk — investigate and remediate."
    elif explanation and len(explanation) > 20:
        return f"{base}. {explanation[:150]}. Investigate source and intent."
    else:
        return f"{base}: {first_line}. Review context to determine if this is intentional (e.g., security testing) or a genuine threat."


def build_confidential_explanation(subcategory: str, fields: dict, source_text: str) -> str:
    """Build explanation for confidential findings with context."""
    import re
    first_line = get_first_line(source_text)

    # Try to find classification markings
    marking_match = re.search(r"(TOP SECRET|SECRET|CONFIDENTIAL|RESTRICTED|NOFORN|SCI|FOUO)", source_text, re.IGNORECASE)
    marking = marking_match.group(1).upper() if marking_match else ""

    if subcategory == "confidential.military":
        return f"Military/defense document: {first_line}. Contains operational military information. ITAR/EAR controlled — unauthorized disclosure is a federal offense."

    elif subcategory == "confidential.military_comms":
        return f"Military communications/operations order: {first_line}. Contains tactical information, unit positions, or mission details. Classified under EO 13526."

    elif subcategory == "confidential.intelligence":
        mark_str = f" Marking: {marking}." if marking else ""
        return f"Intelligence report: {first_line}.{mark_str} Contains source information and assessments. Dissemination restricted per EO 13526."

    elif subcategory == "confidential.weapons_systems":
        return f"Weapons systems data: {first_line}. Technical specifications for defense systems. ITAR Category IV — export controlled."

    elif subcategory == "confidential.nuclear":
        return f"Nuclear facility/weapons information: {first_line}. Restricted Data under the Atomic Energy Act. Extremely sensitive — mishandling is a criminal offense."

    elif subcategory == "confidential.classified":
        mark_str = f" Classification: {marking}." if marking else ""
        return f"Classified document: {first_line}.{mark_str} Requires appropriate clearance and need-to-know for access."

    elif subcategory == "confidential.internal":
        return f"Internal/confidential business document: {first_line}. Contains proprietary information not intended for public disclosure. Risk: competitive harm, insider trading."

    elif subcategory == "confidential.geospatial":
        return f"Classified geospatial data: {first_line}. Contains facility coordinates or military mapping data. Disclosure could compromise operational security."

    elif subcategory == "confidential.education":
        return f"Education record (FERPA-protected): {first_line}. Student records require written consent for disclosure under federal law."

    return f"Confidential content: {first_line}"[:300]


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
