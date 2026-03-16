#!/usr/bin/env python3
"""
NVD Processor for TorchSight Training

Extracts CVE descriptions with CWE mappings,
maps to taxonomy, and outputs labeled JSONL.

Targets: malicious.exploit, malicious.injection
"""

import json
import random
import sys
from pathlib import Path

RAW_DIR = Path(__file__).parent.parent.parent / "data" / "raw" / "nvd"
OUT_DIR = Path(__file__).parent.parent.parent / "data" / "processed"

# CWE to subcategory mapping
CWE_MAP = {
    "CWE-79": ("malicious.injection", "XSS"),
    "CWE-89": ("malicious.injection", "SQL"),
    "CWE-78": ("malicious.injection", "cmd"),
    "CWE-94": ("malicious.injection", "code"),
    "CWE-77": ("malicious.injection", "cmd"),
    "CWE-90": ("malicious.injection", "LDAP"),
    "CWE-91": ("malicious.xxe", "XML"),
    "CWE-611": ("malicious.xxe", "XXE"),
    "CWE-918": ("malicious.ssrf", "SSRF"),
    "CWE-502": ("malicious.deserialization", "deserialization"),
    "CWE-119": ("malicious.exploit", "buffer_overflow"),
    "CWE-120": ("malicious.exploit", "buffer_overflow"),
    "CWE-22": ("malicious.exploit", "path_traversal"),
    "CWE-20": ("malicious.exploit", "input_validation"),
    "CWE-264": ("malicious.exploit", "permission"),
    "CWE-287": ("malicious.exploit", "auth_bypass"),
    "CWE-352": ("malicious.exploit", "csrf"),
    "CWE-434": ("malicious.exploit", "file_upload"),
    "CWE-862": ("malicious.exploit", "missing_auth"),
    "CWE-863": ("malicious.exploit", "incorrect_auth"),
}


def process(seed: int = 42):
    """Process NVD CVE data into labeled JSONL."""
    random.seed(seed)
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    out_path = OUT_DIR / "nvd.jsonl"

    if not RAW_DIR.exists():
        print(f"ERROR: NVD data not found at {RAW_DIR}")
        sys.exit(1)

    all_samples = []
    counts = {}

    for json_file in sorted(RAW_DIR.glob("*.json")):
        try:
            with open(json_file) as f:
                data = json.load(f)
        except Exception:
            continue

        for vuln in data.get("vulnerabilities", []):
            cve = vuln.get("cve", {})
            cve_id = cve.get("id", "")

            # Get English description
            descriptions = cve.get("descriptions", [])
            desc = ""
            for d in descriptions:
                if d.get("lang") == "en":
                    desc = d.get("value", "")
                    break
            if not desc:
                continue

            # Get CVSS severity
            metrics = cve.get("metrics", {})
            severity = "medium"
            cvss_score = None
            for version in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
                if version in metrics:
                    cvss_data = metrics[version][0].get("cvssData", {})
                    base_severity = cvss_data.get("baseSeverity", "MEDIUM")
                    cvss_score = cvss_data.get("baseScore")
                    if base_severity in ("HIGH", "CRITICAL"):
                        severity = "critical"
                    break

            # Get CWE IDs
            weaknesses = cve.get("weaknesses", [])
            cwes = []
            for w in weaknesses:
                for d in w.get("description", []):
                    cwe_id = d.get("value", "")
                    if cwe_id.startswith("CWE-"):
                        cwes.append(cwe_id)

            # Map to taxonomy
            subcategory = "malicious.exploit"
            injection_type = None
            for cwe in cwes:
                if cwe in CWE_MAP:
                    subcategory, injection_type = CWE_MAP[cwe]
                    break

            # Build training text
            text = f"CVE: {cve_id}\n\n{desc}"
            if cvss_score:
                text += f"\n\nCVSS Score: {cvss_score}"
            if cwes:
                text += f"\nCWE: {', '.join(cwes)}"

            fields = {"cve_id": cve_id}
            if cwes:
                fields["cwe"] = cwes
            if cvss_score:
                fields["cvss_score"] = cvss_score
            if injection_type:
                fields["injection_type"] = injection_type

            sample = {
                "text": text,
                "findings": [{
                    "category": "malicious",
                    "subcategory": subcategory,
                    "severity": severity,
                    "compliance": [],
                    "fields": fields,
                }],
            }
            all_samples.append(sample)
            counts[subcategory] = counts.get(subcategory, 0) + 1

    random.shuffle(all_samples)

    with open(out_path, "w") as fout:
        for i, sample in enumerate(all_samples):
            record = {
                "id": f"nvd_{i:05d}",
                "source": "nvd",
                "source_license": "public_domain",
                "text": sample["text"],
                "findings": sample["findings"],
            }
            fout.write(json.dumps(record) + "\n")

    print(f"Wrote {len(all_samples):,} samples to {out_path}")
    print("\nCategory distribution:")
    for sub, count in sorted(counts.items()):
        print(f"  {sub}: {count}")


if __name__ == "__main__":
    process()
