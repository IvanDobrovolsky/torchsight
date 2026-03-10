#!/usr/bin/env python3
"""
MITRE ATT&CK Processor for TorchSight Training

Extracts attack technique and malware descriptions from STIX bundles,
maps to taxonomy, and outputs labeled JSONL.

Targets: malicious.malware, malicious.exploit
"""

import json
import random
import sys
from pathlib import Path

RAW_DIR = Path(__file__).parent.parent.parent / "data" / "raw" / "mitre-cti"
OUT_DIR = Path(__file__).parent.parent.parent / "data" / "processed"

ENTERPRISE = RAW_DIR / "enterprise-attack"

# Map MITRE tactics to our severity
TACTIC_SEVERITY = {
    "initial-access": "critical",
    "execution": "critical",
    "persistence": "critical",
    "privilege-escalation": "critical",
    "defense-evasion": "medium",
    "credential-access": "critical",
    "discovery": "low",
    "lateral-movement": "critical",
    "collection": "medium",
    "command-and-control": "critical",
    "exfiltration": "critical",
    "impact": "critical",
    "resource-development": "info",
    "reconnaissance": "info",
}


def parse_stix_object(path: Path) -> dict | None:
    """Parse a single STIX JSON bundle."""
    try:
        with open(path) as f:
            data = json.load(f)
    except Exception:
        return None

    objects = data.get("objects", [])
    for obj in objects:
        obj_type = obj.get("type", "")
        if obj_type in ("attack-pattern", "malware", "tool"):
            name = obj.get("name", "")
            description = obj.get("description", "")
            if not description:
                continue

            # Get technique ID
            ext_refs = obj.get("external_references", [])
            technique_id = ""
            for ref in ext_refs:
                if ref.get("source_name") == "mitre-attack":
                    technique_id = ref.get("external_id", "")
                    break

            # Get tactics
            kill_chain = obj.get("kill_chain_phases", [])
            tactics = [kc.get("phase_name", "") for kc in kill_chain]

            # Get platforms
            platforms = obj.get("x_mitre_platforms", [])

            return {
                "type": obj_type,
                "name": name,
                "technique_id": technique_id,
                "description": description,
                "tactics": tactics,
                "platforms": platforms,
            }

    return None


def process(max_per_type: int = 500, seed: int = 42):
    """Process MITRE ATT&CK data into labeled JSONL."""
    random.seed(seed)
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    out_path = OUT_DIR / "mitre.jsonl"

    if not ENTERPRISE.exists():
        print(f"ERROR: MITRE data not found at {ENTERPRISE}")
        sys.exit(1)

    all_samples = []
    counts = {"malicious.malware": 0, "malicious.exploit": 0}

    # Process attack techniques
    techniques_dir = ENTERPRISE / "attack-pattern"
    if techniques_dir.exists():
        for json_file in sorted(techniques_dir.glob("*.json")):
            obj = parse_stix_object(json_file)
            if not obj:
                continue

            # Determine severity from tactics
            severity = "medium"
            for tactic in obj["tactics"]:
                s = TACTIC_SEVERITY.get(tactic, "medium")
                if s == "critical":
                    severity = "critical"
                    break

            # Build training text — simulate a "document" containing attack description
            text = f"# {obj['name']}\n\n"
            if obj["technique_id"]:
                text += f"Technique: {obj['technique_id']}\n"
            if obj["tactics"]:
                text += f"Tactics: {', '.join(obj['tactics'])}\n"
            if obj["platforms"]:
                text += f"Platforms: {', '.join(obj['platforms'])}\n"
            text += f"\n{obj['description'][:3000]}"

            sample = {
                "text": text,
                "findings": [{
                    "category": "malicious",
                    "subcategory": "malicious.exploit",
                    "severity": severity,
                    "compliance": [],
                    "fields": {
                        "technique_id": obj["technique_id"],
                        "technique_name": obj["name"],
                        "tactics": obj["tactics"],
                    },
                }],
            }
            all_samples.append(sample)
            counts["malicious.exploit"] += 1

    # Process malware and tools
    for subdir in ["malware", "tool"]:
        malware_dir = ENTERPRISE / subdir
        if not malware_dir.exists():
            continue

        for json_file in sorted(malware_dir.glob("*.json")):
            obj = parse_stix_object(json_file)
            if not obj:
                continue

            text = f"# {obj['name']}\n\n"
            text += f"Type: {obj['type']}\n"
            if obj["platforms"]:
                text += f"Platforms: {', '.join(obj['platforms'])}\n"
            text += f"\n{obj['description'][:3000]}"

            sample = {
                "text": text,
                "findings": [{
                    "category": "malicious",
                    "subcategory": "malicious.malware",
                    "severity": "critical",
                    "compliance": [],
                    "fields": {
                        "malware_family": obj["name"],
                        "malware_type": obj["type"],
                    },
                }],
            }
            all_samples.append(sample)
            counts["malicious.malware"] += 1

    # Limit per type if needed
    random.shuffle(all_samples)

    with open(out_path, "w") as fout:
        for i, sample in enumerate(all_samples):
            record = {
                "id": f"mitre_{i:05d}",
                "source": "mitre_attack",
                "source_license": "Apache-2.0",
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
