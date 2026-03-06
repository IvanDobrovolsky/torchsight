#!/usr/bin/env python3
"""
TorchSight Dataset Coverage Analyzer

Scans all downloaded datasets, maps them to our label taxonomy,
identifies gaps, and outputs a coverage report with synthesis recommendations.

Usage:
    python analyze_coverage.py
    python analyze_coverage.py --output coverage_report.json
"""

import csv
import json
import os
import sys
from collections import defaultdict
from pathlib import Path

RAW_DIR = Path(__file__).parent.parent / "data" / "raw"

# ── Full taxonomy definition ──────────────────────────────────────────────

TAXONOMY = {
    "pii.identity":          {"target": 800,  "sources": ["enron", "synthetic"]},
    "pii.contact":           {"target": 600,  "sources": ["enron", "synthetic"]},
    "pii.government_id":     {"target": 400,  "sources": ["midv500", "synthetic"]},
    "pii.biometric":         {"target": 200,  "sources": ["synthetic"]},

    "credentials.password":          {"target": 400, "sources": ["seclists", "synthetic"]},
    "credentials.api_key":           {"target": 300, "sources": ["synthetic"]},
    "credentials.token":             {"target": 200, "sources": ["synthetic"]},
    "credentials.private_key":       {"target": 200, "sources": ["synthetic"]},
    "credentials.connection_string": {"target": 200, "sources": ["synthetic"]},

    "financial.credit_card":   {"target": 300, "sources": ["synthetic"]},
    "financial.bank_account":  {"target": 200, "sources": ["synthetic"]},
    "financial.tax":           {"target": 200, "sources": ["synthetic"]},
    "financial.transaction":   {"target": 300, "sources": ["edgar", "synthetic"]},

    "medical.diagnosis":     {"target": 400, "sources": ["mtsamples", "synthetic"]},
    "medical.prescription":  {"target": 300, "sources": ["mtsamples", "synthetic"]},
    "medical.lab_result":    {"target": 300, "sources": ["synthetic"]},
    "medical.insurance":     {"target": 200, "sources": ["synthetic"]},

    "confidential.classified": {"target": 300, "sources": ["cia_foia", "synthetic"]},
    "confidential.internal":   {"target": 300, "sources": ["enron", "synthetic"]},
    "confidential.legal":      {"target": 300, "sources": ["courtlistener", "edgar", "synthetic"]},
    "confidential.military":        {"target": 300, "sources": ["dtic", "army_doctrine", "synthetic"]},
    "confidential.military_comms":   {"target": 250, "sources": ["army_doctrine", "synthetic"]},
    "confidential.weapons_systems":  {"target": 200, "sources": ["crs_reports", "gao", "synthetic"]},
    "confidential.intelligence":     {"target": 300, "sources": ["cia_foia", "synthetic"]},
    "confidential.geospatial":       {"target": 200, "sources": ["army_doctrine", "synthetic"]},
    "confidential.nuclear":          {"target": 150, "sources": ["gao", "synthetic"]},
    "confidential.education":        {"target": 300, "sources": ["synthetic"]},

    "malicious.injection":           {"target": 400, "sources": ["seclists", "owasp"]},
    "malicious.exploit":             {"target": 300, "sources": ["nvd", "synthetic"]},
    "malicious.shell":               {"target": 200, "sources": ["seclists", "synthetic"]},
    "malicious.obfuscated":          {"target": 200, "sources": ["seclists", "synthetic"]},
    "malicious.phishing":            {"target": 200, "sources": ["synthetic"]},
    "malicious.malware":             {"target": 200, "sources": ["mitre", "synthetic"]},
    "malicious.prompt_injection":    {"target": 300, "sources": ["synthetic"]},
    "malicious.supply_chain":        {"target": 200, "sources": ["synthetic"]},
    "malicious.deserialization":     {"target": 200, "sources": ["synthetic"]},
    "malicious.ssrf":                {"target": 200, "sources": ["seclists", "synthetic"]},
    "malicious.redos":               {"target": 150, "sources": ["synthetic"]},
    "malicious.steganography":       {"target": 150, "sources": ["synthetic"]},
    "malicious.prototype_pollution": {"target": 150, "sources": ["seclists", "synthetic"]},
    "malicious.xxe":                 {"target": 200, "sources": ["seclists", "owasp"]},
    "malicious.ssti":                {"target": 200, "sources": ["seclists", "synthetic"]},

    "credentials.cloud_config":  {"target": 300, "sources": ["synthetic"]},
    "credentials.cicd":          {"target": 200, "sources": ["synthetic"]},
    "credentials.container":     {"target": 200, "sources": ["synthetic"]},

    "pii.metadata":    {"target": 300, "sources": ["synthetic"]},
    "pii.behavioral":  {"target": 200, "sources": ["synthetic"]},

    "safe.documentation":  {"target": 300, "sources": ["synthetic"]},
    "safe.code":           {"target": 300, "sources": ["synthetic"]},
    "safe.config":         {"target": 200, "sources": ["synthetic"]},
    "safe.media":          {"target": 200, "sources": ["synthetic"]},
}

TARGET_TOTAL = sum(v["target"] for v in TAXONOMY.values())


# ── Dataset analyzers ─────────────────────────────────────────────────────

def analyze_enron() -> dict:
    """Count Enron emails and estimate usable samples."""
    enron_dir = RAW_DIR / "enron"
    if not enron_dir.exists():
        return {"available": False}

    mailbox_count = 0
    email_count = 0
    sample_emails = []

    for mailbox in sorted(enron_dir.iterdir()):
        if not mailbox.is_dir():
            continue
        mailbox_count += 1
        for root, _, files in os.walk(mailbox):
            for f in files:
                email_count += 1
                if len(sample_emails) < 5:
                    try:
                        content = (Path(root) / f).read_text(errors="ignore")[:500]
                        sample_emails.append(content[:200])
                    except Exception:
                        pass

    return {
        "available": True,
        "mailboxes": mailbox_count,
        "total_emails": email_count,
        "labeled": False,
        "estimated_pii_samples": min(email_count, 2000),
        "covers": ["pii.identity", "pii.contact", "confidential.internal"],
        "notes": "Raw emails. Need NER/LLM labeling to extract PII findings. ~60-70% contain names+emails, ~5-10% contain addresses/phone numbers.",
    }


def analyze_seclists() -> dict:
    """Inventory SecLists by attack category."""
    sl_dir = RAW_DIR / "SecLists"
    if not sl_dir.exists():
        return {"available": False}

    categories = {}
    key_dirs = {
        "Fuzzing/SQLi": "malicious.injection",
        "Fuzzing/XSS": "malicious.injection",
        "Fuzzing/Databases": "malicious.injection",
        "Fuzzing": "malicious.injection",
        "Passwords": "credentials.password",
        "Passwords/Common-Credentials": "credentials.password",
        "Passwords/Default-Credentials": "credentials.password",
        "Passwords/Leaked-Databases": "credentials.password",
        "Web-Shells": "malicious.shell",
        "Payloads": "malicious.obfuscated",
        "Discovery": "safe.config",
    }

    total_files = 0
    total_lines = 0

    for rel_path, label in key_dirs.items():
        full_path = sl_dir / rel_path
        if not full_path.exists():
            continue

        file_count = 0
        line_count = 0
        for root, _, files in os.walk(full_path):
            for f in files:
                fp = Path(root) / f
                if fp.suffix in (".txt", ".lst", ".csv", ".md"):
                    file_count += 1
                    try:
                        line_count += sum(1 for _ in open(fp, errors="ignore"))
                    except Exception:
                        pass

        if label not in categories:
            categories[label] = {"files": 0, "lines": 0}
        categories[label]["files"] += file_count
        categories[label]["lines"] += line_count
        total_files += file_count
        total_lines += line_count

    return {
        "available": True,
        "total_files": total_files,
        "total_payload_lines": total_lines,
        "labeled": "implicit",
        "categories": categories,
        "covers": list(categories.keys()),
        "notes": "Payloads organized by directory = implicit labels. Each line is one payload. Need to wrap in realistic file contexts for training.",
    }


def analyze_mitre() -> dict:
    """Parse MITRE ATT&CK STIX data."""
    mitre_dir = RAW_DIR / "mitre-cti"
    if not mitre_dir.exists():
        return {"available": False}

    technique_count = 0
    tactic_count = 0
    malware_count = 0

    # Count attack patterns
    attack_path = mitre_dir / "enterprise-attack" / "attack-pattern"
    if attack_path.exists():
        technique_count = len(list(attack_path.glob("*.json")))

    # Count malware
    malware_path = mitre_dir / "enterprise-attack" / "malware"
    if malware_path.exists():
        malware_count = len(list(malware_path.glob("*.json")))

    return {
        "available": True,
        "techniques": technique_count,
        "malware_entries": malware_count,
        "labeled": True,
        "label_format": "STIX 2.1 (technique IDs, tactics, descriptions)",
        "covers": ["malicious.malware", "malicious.exploit"],
        "notes": "Well-structured threat intelligence. Descriptions can be used as training context for malware/threat classification. Not file-level samples — need transformation.",
    }


def analyze_exploitdb() -> dict:
    """Inventory Exploit-DB exploits."""
    edb_dir = RAW_DIR / "exploitdb"
    if not edb_dir.exists():
        return {"available": False}

    # Count exploits by type from CSV
    csv_path = edb_dir / "files_exploits.csv"
    type_counts = defaultdict(int)
    platform_counts = defaultdict(int)
    total = 0

    if csv_path.exists():
        try:
            with open(csv_path, errors="ignore") as f:
                reader = csv.DictReader(f)
                for row in reader:
                    total += 1
                    etype = row.get("type", "unknown")
                    platform = row.get("platform", "unknown")
                    type_counts[etype] += 1
                    platform_counts[platform] += 1
        except Exception:
            pass

    # Count actual exploit files
    exploits_dir = edb_dir / "exploits"
    file_count = 0
    if exploits_dir.exists():
        for root, _, files in os.walk(exploits_dir):
            file_count += len(files)

    return {
        "available": True,
        "total_entries": total,
        "exploit_files": file_count,
        "by_type": dict(sorted(type_counts.items(), key=lambda x: -x[1])[:10]),
        "top_platforms": dict(sorted(platform_counts.items(), key=lambda x: -x[1])[:10]),
        "labeled": True,
        "label_format": "CSV with type, platform, CVE ID",
        "covers": ["malicious.exploit", "malicious.shell"],
        "notes": "Real exploit code with CVE mappings. Good for malicious.exploit training. Each file is a standalone PoC.",
    }


def analyze_nvd() -> dict:
    """Parse NVD CVE feeds."""
    nvd_dir = RAW_DIR / "nvd"
    if not nvd_dir.exists():
        return {"available": False}

    total_cves = 0
    severity_counts = defaultdict(int)
    cwe_counts = defaultdict(int)

    for json_file in sorted(nvd_dir.glob("*.json")):
        try:
            with open(json_file) as f:
                data = json.load(f)
            for vuln in data.get("vulnerabilities", []):
                total_cves += 1
                cve = vuln.get("cve", {})

                # CVSS severity
                metrics = cve.get("metrics", {})
                for version in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
                    if version in metrics:
                        severity = metrics[version][0].get("cvssData", {}).get("baseSeverity", "UNKNOWN")
                        severity_counts[severity] += 1
                        break

                # CWE
                weaknesses = cve.get("weaknesses", [])
                for w in weaknesses:
                    for desc in w.get("description", []):
                        cwe_id = desc.get("value", "")
                        if cwe_id.startswith("CWE-"):
                            cwe_counts[cwe_id] += 1
        except Exception:
            pass

    return {
        "available": True,
        "total_cves": total_cves,
        "by_severity": dict(severity_counts),
        "top_cwes": dict(sorted(cwe_counts.items(), key=lambda x: -x[1])[:15]),
        "labeled": True,
        "label_format": "CVSS scores, CWE IDs, descriptions",
        "covers": ["malicious.exploit", "malicious.injection"],
        "notes": "Vulnerability metadata with severity scores. Useful for enriching exploit samples with CVE context. Not file-level — need to pair with Exploit-DB.",
    }


def analyze_mtsamples() -> dict:
    """Parse MTSamples medical transcriptions."""
    csv_path = RAW_DIR / "mtsamples.csv"
    if not csv_path.exists():
        return {"available": False}

    total = 0
    specialty_counts = defaultdict(int)
    avg_length = 0

    try:
        with open(csv_path, errors="ignore") as f:
            reader = csv.DictReader(f)
            for row in reader:
                total += 1
                spec = row.get("medical_specialty", "").strip()
                if spec:
                    specialty_counts[spec] += 1
                text = row.get("transcription", "")
                avg_length += len(text)
    except Exception:
        pass

    if total > 0:
        avg_length //= total

    return {
        "available": True,
        "total_samples": total,
        "avg_length_chars": avg_length,
        "specialties": dict(sorted(specialty_counts.items(), key=lambda x: -x[1])[:20]),
        "labeled": "partial",
        "label_format": "medical_specialty, sample_name, description",
        "covers": ["medical.diagnosis", "medical.prescription"],
        "notes": "Real medical transcriptions with specialty labels. Contains diagnoses, medications, procedures. Need to inject synthetic PII (patient names, DOB, SSN) for full training samples.",
    }


def analyze_owasp() -> dict:
    """Check OWASP WSTG content."""
    owasp_dir = RAW_DIR / "owasp-wstg"
    if not owasp_dir.exists():
        return {"available": False}

    test_categories = []
    doc_dir = owasp_dir / "document" / "4-Web_Application_Security_Testing"
    if doc_dir.exists():
        for d in sorted(doc_dir.iterdir()):
            if d.is_dir():
                test_count = len(list(d.glob("*.md")))
                test_categories.append({"category": d.name, "tests": test_count})

    return {
        "available": True,
        "test_categories": test_categories,
        "total_tests": sum(c["tests"] for c in test_categories),
        "labeled": False,
        "covers": ["malicious.injection"],
        "notes": "Testing methodology guides, not payload data. Useful as reference for generating realistic attack scenarios, but not directly usable as training samples.",
    }


# ── Manual datasets (not downloaded) ─────────────────────────────────────

MANUAL_DATASETS = {
    "edgar": {
        "available": False,
        "reason": "Requires SEC EDGAR bulk download",
        "url": "https://www.sec.gov/edgar/",
        "license": "Public domain (US Gov)",
        "covers": ["financial.transaction", "confidential.legal"],
        "estimated_samples": 500,
    },
    "courtlistener": {
        "available": False,
        "reason": "Requires API access setup",
        "url": "https://www.courtlistener.com/api/",
        "license": "Public domain (court records)",
        "covers": ["confidential.legal"],
        "estimated_samples": 300,
    },
    "cia_foia": {
        "available": False,
        "reason": "Manual search/download from reading room",
        "url": "https://www.cia.gov/readingroom/",
        "license": "Public domain (US Gov)",
        "covers": ["confidential.classified", "confidential.intelligence"],
        "estimated_samples": 300,
    },
    "crs_reports": {
        "available": False,
        "reason": "Bulk download from crsreports.congress.gov",
        "url": "https://crsreports.congress.gov/",
        "license": "Public domain (US Gov)",
        "covers": ["confidential.weapons_systems", "confidential.military"],
        "estimated_samples": 400,
    },
    "dtic": {
        "available": False,
        "reason": "Search and download public technical reports",
        "url": "https://discover.dtic.mil/",
        "license": "Public domain (US Gov)",
        "covers": ["confidential.military", "confidential.weapons_systems"],
        "estimated_samples": 300,
    },
    "army_doctrine": {
        "available": False,
        "reason": "Download public Army doctrinal publications (ADP/FM/ATP)",
        "url": "https://armypubs.army.mil/",
        "license": "Public domain (US Gov)",
        "covers": ["confidential.military", "confidential.military_comms", "confidential.geospatial"],
        "estimated_samples": 200,
    },
    "gao": {
        "available": False,
        "reason": "Download defense/intelligence audit reports",
        "url": "https://www.gao.gov/",
        "license": "Public domain (US Gov)",
        "covers": ["confidential.weapons_systems", "confidential.nuclear"],
        "estimated_samples": 200,
    },
    "midv500": {
        "available": False,
        "reason": "Academic dataset, request from authors",
        "url": "https://arxiv.org/abs/1807.05786",
        "license": "CC / Public domain (Wikimedia sources)",
        "covers": ["pii.government_id"],
        "estimated_samples": 300,
    },
}

# ── Excluded datasets (license issues) ───────────────────────────────────

EXCLUDED_DATASETS = {
    "mimic3": {
        "reason": "PhysioNet DUA explicitly prohibits sharing with LLM services. Local fine-tuning is ambiguous under the agreement.",
        "url": "https://physionet.org/content/mimiciii/",
        "replacement": "MTSamples + synthetic medical data",
    },
    "exploitdb": {
        "reason": "GPL v2 on repository. Individual exploits have no clear license. Whether model training creates a 'derivative work' under GPL is legally debated.",
        "url": "https://gitlab.com/exploit-database/exploitdb",
        "replacement": "NVD metadata + synthetic exploit samples. Exploit-DB used only as reference for realistic generation.",
    },
}


# ── Coverage analysis ─────────────────────────────────────────────────────

def compute_coverage(datasets: dict) -> dict:
    """Map dataset availability to taxonomy coverage."""
    coverage = {}

    for subcategory, spec in TAXONOMY.items():
        target = spec["target"]
        sources = spec["sources"]

        available_count = 0
        source_details = []

        for src in sources:
            if src == "synthetic":
                continue  # synthetic always available

            ds = datasets.get(src, {})
            if ds.get("available"):
                is_covered = subcategory in ds.get("covers", [])
                if is_covered:
                    available_count += 1
                    source_details.append({"source": src, "status": "available"})
                else:
                    source_details.append({"source": src, "status": "available_but_no_coverage"})
            else:
                source_details.append({"source": src, "status": "not_downloaded"})

        # Estimate how many samples come from real data vs synthetic
        real_sources = [s for s in source_details if s["status"] == "available"]
        needs_synthetic = "synthetic" in sources

        if real_sources:
            real_estimate = min(target, target * len(real_sources) // len(sources))
            synthetic_needed = max(0, target - real_estimate)
        else:
            real_estimate = 0
            synthetic_needed = target

        coverage[subcategory] = {
            "target": target,
            "real_estimate": real_estimate,
            "synthetic_needed": synthetic_needed,
            "pct_synthetic": round(synthetic_needed / target * 100) if target > 0 else 0,
            "sources": source_details,
            "gap_level": "none" if synthetic_needed == 0 else "partial" if real_estimate > 0 else "full",
        }

    return coverage


def print_report(datasets: dict, coverage: dict):
    """Print human-readable coverage report."""
    print()
    print("=" * 72)
    print("  TORCHSIGHT DATASET COVERAGE ANALYSIS")
    print("=" * 72)

    # ── Dataset inventory ──
    print("\n  DOWNLOADED DATASETS")
    print("  " + "─" * 68)

    for name, ds in sorted(datasets.items()):
        status = "READY" if ds.get("available") else "MISSING"
        icon = "  [OK]  " if ds.get("available") else "  [--]  "
        label_status = ds.get("labeled", False)
        if label_status is True:
            label_str = "labeled"
        elif label_status == "partial" or label_status == "implicit":
            label_str = f"{label_status} labels"
        else:
            label_str = "unlabeled"

        print(f"{icon}{name:<20} {status:<10} {label_str}")

        if ds.get("notes"):
            # Wrap notes
            words = ds["notes"].split()
            line = "          "
            for w in words:
                if len(line) + len(w) > 70:
                    print(line)
                    line = "          "
                line += w + " "
            if line.strip():
                print(line)

    # ── Manual datasets ──
    print("\n  MANUAL DATASETS (not yet downloaded)")
    print("  " + "─" * 68)
    for name, ds in MANUAL_DATASETS.items():
        print(f"  [--]  {name:<20} {ds['reason']}")
        print(f"          License: {ds.get('license', 'unknown')}")
        print(f"          URL: {ds['url']}")
        print(f"          Covers: {', '.join(ds['covers'])}")

    # ── Excluded datasets ──
    print("\n  EXCLUDED DATASETS (license issues)")
    print("  " + "─" * 68)
    for name, ds in EXCLUDED_DATASETS.items():
        print(f"  [XX]  {name:<20} {ds['reason']}")
        print(f"          Replacement: {ds['replacement']}")

    # ── Coverage matrix ──
    print("\n  COVERAGE BY SUBCATEGORY")
    print("  " + "─" * 68)
    print(f"  {'Subcategory':<30} {'Target':>6} {'Real':>6} {'Synth':>6} {'%Synth':>7}  Gap")
    print("  " + "─" * 68)

    total_target = 0
    total_real = 0
    total_synth = 0
    full_gaps = []

    categories_seen = set()
    for sub in sorted(coverage.keys()):
        cat = sub.split(".")[0]
        if cat not in categories_seen:
            categories_seen.add(cat)
            if len(categories_seen) > 1:
                print()

        c = coverage[sub]
        total_target += c["target"]
        total_real += c["real_estimate"]
        total_synth += c["synthetic_needed"]

        gap_icon = {
            "none": "  OK",
            "partial": "  ~",
            "full": "  !!",
        }[c["gap_level"]]

        print(f"  {sub:<30} {c['target']:>6} {c['real_estimate']:>6} {c['synthetic_needed']:>6} {c['pct_synthetic']:>6}% {gap_icon}")

        if c["gap_level"] == "full":
            full_gaps.append(sub)

    print("  " + "─" * 68)
    pct = round(total_synth / total_target * 100) if total_target > 0 else 0
    print(f"  {'TOTAL':<30} {total_target:>6} {total_real:>6} {total_synth:>6} {pct:>6}%")

    # ── Gap analysis ──
    print(f"\n  GAP ANALYSIS")
    print("  " + "─" * 68)
    print(f"  Target dataset size:     {total_target:,} samples")
    print(f"  From real data:          {total_real:,} samples ({round(total_real/total_target*100)}%)")
    print(f"  Needs synthesis:         {total_synth:,} samples ({pct}%)")
    print(f"  Fully synthetic cats:    {len(full_gaps)}")

    if full_gaps:
        print(f"\n  FULLY SYNTHETIC (no real data source):")
        for gap in full_gaps:
            target = coverage[gap]["target"]
            print(f"    - {gap} ({target} samples needed)")

    # ── Synthesis recommendations ──
    print(f"\n  SYNTHESIS STRATEGY")
    print("  " + "─" * 68)

    strategies = {
        "pii": "Generate realistic personal profiles (Faker library). Embed in email templates, forms, CSV records. Vary formats (US/EU/Asian names, address styles).",
        "credentials": "Generate realistic config files (.env, yaml, json, .properties) with fake but valid-format API keys, passwords, connection strings. Include both exposed and properly redacted versions.",
        "financial": "Generate invoices (HTML/PDF), bank statements, W-2/1099 forms, credit card receipts. Use realistic but fake numbers passing Luhn check.",
        "medical": "Inject synthetic PII into MTSamples transcriptions. Generate discharge summaries, lab reports, insurance cards. Follow HL7/FHIR field patterns.",
        "confidential": "Generate memos with classification markings (TOP SECRET//SCI, SECRET//NOFORN, CONFIDENTIAL, INTERNAL ONLY). Create NDA templates. Military: generate OPORDs, FRAGOs, SITREPs with proper DTG format, MGRS coordinates, and unit designations. Weapons systems: create technical spec sheets for fictional systems with realistic parameters. Intelligence: generate HUMINT/SIGINT/IMINT report formats with source reliability ratings (A-F) and info credibility (1-6). Geospatial: create targeting packages with coordinate sets and imagery metadata. Nuclear: generate RD/FRD/CNWDI handling cover sheets and fictional facility reports.",
        "malicious": "Embed SecLists payloads into realistic file contexts (HTML forms, config files, log entries). Create multi-stage attack scenarios. Generate prompt injection payloads (direct, indirect, jailbreaks). Create supply chain attack samples (malicious package.json, lockfile poisoning, typosquatted packages). Generate deserialization payloads (pickle, YAML, Java). Create SSRF vectors targeting cloud metadata endpoints. Generate ReDoS patterns, XXE payloads, SSTI templates, and prototype pollution vectors. Create steganography samples with hidden data in images.",
        "safe": "Generate clean README files, source code (Python/JS/Rust), config files (nginx, docker-compose), and describe stock photos.",
    }

    for cat, strategy in strategies.items():
        print(f"\n  {cat}:")
        words = strategy.split()
        line = "    "
        for w in words:
            if len(line) + len(w) > 68:
                print(line)
                line = "    "
            line += w + " "
        if line.strip():
            print(line)

    # ── Priority actions ──
    print(f"\n  PRIORITY ACTIONS")
    print("  " + "─" * 68)
    print("  1. Process Enron emails → extract PII with NER, label pii.identity/contact")
    print("  2. Process MTSamples → inject synthetic PII, label medical.*")
    print("  3. Process SecLists → wrap payloads in file contexts, label malicious.*")
    print("  4. Process Exploit-DB → extract PoCs with CVE metadata, label malicious.exploit")
    print("  5. Generate synthetic: credentials, financial, government IDs, military, education")
    print("  6. Generate safe/clean negative examples (~1000 samples)")
    print("  7. Apply for MIMIC-III access (PhysioNet) for medical.lab_result coverage")
    print("  8. Download SEC EDGAR filings for financial.transaction / confidential.legal")
    print()


def main():
    print("\n  Analyzing downloaded datasets...\n")

    # Run all analyzers (only datasets with confirmed training-compatible licenses)
    datasets = {
        "enron": analyze_enron(),
        "seclists": analyze_seclists(),
        "mitre": analyze_mitre(),
        "nvd": analyze_nvd(),
        "mtsamples": analyze_mtsamples(),
        "owasp": analyze_owasp(),
    }
    # Note: exploitdb excluded (GPL v2 — training legality unclear)
    # Note: mimic3 excluded (PhysioNet DUA prohibits LLM use)

    # Add manual datasets
    datasets.update(MANUAL_DATASETS)

    # Compute coverage
    coverage = compute_coverage(datasets)

    # Print report
    print_report(datasets, coverage)

    # Optionally save JSON
    if "--output" in sys.argv:
        idx = sys.argv.index("--output")
        if idx + 1 < len(sys.argv):
            output = {
                "datasets": datasets,
                "coverage": coverage,
                "taxonomy": TAXONOMY,
                "target_total": TARGET_TOTAL,
            }
            with open(sys.argv[idx + 1], "w") as f:
                json.dump(output, f, indent=2, default=str)
            print(f"  Full report saved to: {sys.argv[idx + 1]}\n")


if __name__ == "__main__":
    main()
