#!/usr/bin/env python3
"""Process GitHub Security Advisories into training JSONL.

Maps advisories to taxonomy subcategories based on ecosystem, CWE, and content.
Particularly valuable for supply_chain attacks (npm/pypi dependency vulnerabilities).
"""

import json
import hashlib
import random
from pathlib import Path

DATA_FILE = Path(__file__).resolve().parent.parent.parent / "data" / "ghsa" / "advisories.jsonl"
OUT_DIR = Path(__file__).resolve().parent.parent.parent / "data" / "processed"

# CWE to subcategory mapping
CWE_MAP = {
    "CWE-79": "malicious.injection",   # XSS
    "CWE-89": "malicious.injection",   # SQL injection
    "CWE-78": "malicious.shell",       # OS command injection
    "CWE-77": "malicious.shell",       # Command injection
    "CWE-94": "malicious.injection",   # Code injection
    "CWE-611": "malicious.xxe",
    "CWE-502": "malicious.deserialization",
    "CWE-918": "malicious.ssrf",
    "CWE-1321": "malicious.prototype_pollution",
    "CWE-1333": "malicious.redos",
    "CWE-400": "malicious.redos",      # Uncontrolled resource consumption
    "CWE-91": "malicious.injection",   # XML injection
    "CWE-90": "malicious.injection",   # LDAP injection
    "CWE-943": "malicious.injection",  # NoSQL injection
    "CWE-434": "malicious.exploit",    # Unrestricted upload
    "CWE-22": "malicious.exploit",     # Path traversal
    "CWE-352": "malicious.exploit",    # CSRF
    "CWE-287": "credentials.token",    # Auth bypass
    "CWE-798": "credentials.password", # Hardcoded credentials
    "CWE-522": "credentials.password", # Insufficient credential protection
    "CWE-200": "confidential.internal",# Information exposure
    "CWE-312": "credentials.password", # Cleartext storage
    "CWE-327": "credentials.token",    # Broken crypto
}

# Ecosystem-based supply chain mapping
SUPPLY_CHAIN_ECOSYSTEMS = {"npm", "pip", "PyPI", "RubyGems", "Go", "crates.io", "NuGet", "Maven"}

SEVERITY_MAP = {
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "low": "low",
}


def make_id(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()[:16]


def classify_advisory(adv: dict) -> list:
    """Map advisory to taxonomy findings."""
    findings = []
    cwes = adv.get("cwe_ids", [])
    ecosystems = [v["ecosystem"] for v in adv.get("vulnerabilities", []) if v.get("ecosystem")]
    packages = [v["package"] for v in adv.get("vulnerabilities", []) if v.get("package")]
    desc = (adv.get("description", "") or "").lower()
    summary = (adv.get("summary", "") or "").lower()
    severity = SEVERITY_MAP.get(adv.get("severity", ""), "medium")

    # Check for supply chain indicators
    is_supply_chain = False
    supply_chain_keywords = ["supply chain", "malicious package", "typosquat", "dependency confusion",
                             "backdoor", "trojan", "malicious code in", "compromised"]
    if any(kw in desc or kw in summary for kw in supply_chain_keywords):
        is_supply_chain = True
    if any(eco in SUPPLY_CHAIN_ECOSYSTEMS for eco in ecosystems):
        # Packages in these ecosystems with certain patterns suggest supply chain
        if any(kw in desc for kw in ["malicious", "backdoor", "trojan", "exfiltrat"]):
            is_supply_chain = True

    if is_supply_chain:
        pkg_names = ", ".join(packages[:3]) if packages else "unknown"
        findings.append({
            "category": "malicious",
            "subcategory": "malicious.supply_chain",
            "severity": severity,
            "compliance": ["NIST-800-53-SA-12", "SLSA"],
            "evidence": adv.get("summary", "")[:200],
            "explanation": f"Supply chain vulnerability in package(s): {pkg_names}. {adv.get('summary', '')[:150]}"
        })

    # Map by CWE
    mapped_subcats = set()
    for cwe in cwes:
        subcat = CWE_MAP.get(cwe)
        if subcat and subcat not in mapped_subcats:
            mapped_subcats.add(subcat)
            cat = subcat.split(".")[0]
            findings.append({
                "category": cat,
                "subcategory": subcat,
                "severity": severity,
                "compliance": [f"CWE-{cwe.split('-')[-1]}"] if cwe.startswith("CWE") else [],
                "evidence": adv.get("summary", "")[:200],
                "explanation": f"{cwe}: {adv.get('summary', '')[:200]}"
            })

    # Default: if no specific mapping, classify as exploit
    if not findings:
        findings.append({
            "category": "malicious",
            "subcategory": "malicious.exploit",
            "severity": severity,
            "compliance": [f"GHSA-{adv.get('ghsa_id', 'unknown')}"],
            "evidence": adv.get("summary", "")[:200],
            "explanation": adv.get("summary", "")[:300] or "Security vulnerability in open-source package."
        })

    return findings


def format_advisory_text(adv: dict) -> str:
    """Format advisory as realistic document text."""
    parts = []

    ghsa = adv.get("ghsa_id", "")
    cve = adv.get("cve_id", "")
    header = f"Security Advisory: {ghsa}"
    if cve:
        header += f" ({cve})"
    parts.append(header)

    if adv.get("summary"):
        parts.append(f"\nSummary: {adv['summary']}")

    if adv.get("severity"):
        score_str = ""
        if adv.get("cvss_score"):
            score_str = f" (CVSS {adv['cvss_score']})"
        parts.append(f"Severity: {adv['severity'].upper()}{score_str}")

    vulns = adv.get("vulnerabilities", [])
    if vulns:
        parts.append("\nAffected Packages:")
        for v in vulns[:5]:
            eco = v.get("ecosystem", "unknown")
            pkg = v.get("package", "unknown")
            vr = v.get("vulnerable_range", "")
            parts.append(f"  - {eco}/{pkg} {vr}")

    if adv.get("description"):
        parts.append(f"\nDescription:\n{adv['description']}")

    if adv.get("cwe_ids"):
        parts.append(f"\nCWEs: {', '.join(adv['cwe_ids'])}")

    return "\n".join(parts)


def main():
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    out_file = OUT_DIR / "ghsa.jsonl"

    if not DATA_FILE.exists():
        print(f"  {DATA_FILE} not found, run download_ghsa.py first")
        return 0

    print("Processing GitHub Security Advisories...")
    samples = []
    supply_chain_count = 0

    with open(DATA_FILE) as f:
        for line in f:
            adv = json.loads(line)
            text = format_advisory_text(adv)

            if len(text) < 50:
                continue

            findings = classify_advisory(adv)
            sample = {
                "id": f"ghsa-{adv.get('ghsa_id', make_id(text))}",
                "source": "GitHub Advisory Database",
                "source_license": "CC-BY-4.0",
                "text": text,
                "findings": findings,
            }
            samples.append(sample)

            if any(f["subcategory"] == "malicious.supply_chain" for f in findings):
                supply_chain_count += 1

    with open(out_file, "w") as f:
        for s in samples:
            f.write(json.dumps(s) + "\n")

    print(f"Saved {len(samples)} GHSA samples to {out_file}")
    print(f"  - Supply chain: {supply_chain_count}")
    print(f"  - Other vulnerabilities: {len(samples) - supply_chain_count}")
    return len(samples)


if __name__ == "__main__":
    main()
