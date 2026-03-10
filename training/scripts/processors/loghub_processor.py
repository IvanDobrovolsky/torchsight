#!/usr/bin/env python3
"""
Loghub System Log Processor for TorchSight Training

Processes system log files from various sources (Linux, Apache,
OpenSSH, Hadoop, etc.). Most logs are safe; some contain
security-relevant content.

Targets: safe.config, safe.documentation, credentials (context)
"""

import json
import random
import re
import sys
from collections import defaultdict
from pathlib import Path

RAW_DIR = Path(__file__).parent.parent.parent / "data" / "raw" / "loghub"
OUT_DIR = Path(__file__).parent.parent.parent / "data" / "processed"

# Log sources and their default classification
LOG_SOURCES = {
    "Android": "safe.config",
    "Apache": "safe.config",
    "BGL": "safe.config",
    "Hadoop": "safe.config",
    "HDFS": "safe.config",
    "HealthApp": "safe.config",
    "HPC": "safe.config",
    "Linux": "safe.config",
    "Mac": "safe.config",
    "OpenSSH": "safe.config",
    "OpenStack": "safe.config",
    "Proxifier": "safe.config",
    "Spark": "safe.config",
    "Thunderbird": "safe.config",
    "Windows": "safe.config",
    "Zookeeper": "safe.config",
}

# Security-relevant patterns in logs
AUTH_FAILURE_PATTERNS = [
    re.compile(r'authentication failure', re.IGNORECASE),
    re.compile(r'failed password', re.IGNORECASE),
    re.compile(r'invalid user', re.IGNORECASE),
    re.compile(r'failed login', re.IGNORECASE),
    re.compile(r'access denied', re.IGNORECASE),
    re.compile(r'permission denied', re.IGNORECASE),
    re.compile(r'unauthorized', re.IGNORECASE),
]

IP_PATTERN = re.compile(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b')

# Number of consecutive log lines to group as one sample
CHUNK_SIZE = 25


def classify_log_chunk(lines: list[str], source: str) -> dict:
    """Classify a chunk of log lines."""
    text = "\n".join(lines)
    text_lower = text.lower()

    # Check for authentication/security events
    auth_failures = sum(1 for pat in AUTH_FAILURE_PATTERNS if pat.search(text))
    ips = set(IP_PATTERN.findall(text))

    if auth_failures >= 2 or (auth_failures >= 1 and source in ("OpenSSH", "Linux")):
        return {
            "text": text[:4000],
            "findings": [{
                "category": "pii",
                "subcategory": "pii.metadata",
                "severity": "medium",
                "explanation": (
                    f"System logs from {source} containing authentication failure events. "
                    f"Found {auth_failures} security-relevant log entries"
                    f"{f' from {len(ips)} unique IP addresses' if ips else ''}. "
                    f"These logs may reveal information about authentication attempts "
                    f"and network access patterns."
                ),
            }],
        }

    # Default: safe system logs
    return {
        "text": text[:4000],
        "findings": [{
            "category": "safe",
            "subcategory": "safe.config",
            "severity": "info",
            "explanation": (
                f"Standard {source} system log output. "
                f"Contains operational log messages with no sensitive "
                f"credentials, PII, or security-critical information."
            ),
        }],
    }


def process(max_samples: int = 2000, seed: int = 42):
    """Process Loghub system logs and output labeled JSONL."""
    random.seed(seed)
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    out_path = OUT_DIR / "loghub.jsonl"

    if not RAW_DIR.exists():
        print(f"ERROR: Loghub data not found at {RAW_DIR}")
        sys.exit(1)

    print("Scanning Loghub log directories...")

    # Collect samples by subcategory
    safe_samples = []
    security_samples = []

    for source_name, default_subcat in LOG_SOURCES.items():
        source_dir = RAW_DIR / source_name
        if not source_dir.exists():
            continue

        # Find the main log file
        log_files = list(source_dir.glob("*_2k.log"))
        if not log_files:
            continue

        for log_file in log_files:
            try:
                lines = log_file.read_text(errors="ignore").splitlines()
            except Exception:
                continue

            if not lines:
                continue

            print(f"  {source_name}: {len(lines)} log lines")

            # Chunk lines into samples
            for i in range(0, len(lines), CHUNK_SIZE):
                chunk = lines[i:i + CHUNK_SIZE]
                if len(chunk) < 5:
                    continue

                sample = classify_log_chunk(chunk, source_name)
                subcat = sample["findings"][0]["subcategory"]

                if subcat == "safe.config":
                    safe_samples.append(sample)
                else:
                    security_samples.append(sample)

    print(f"\nTotal chunks:")
    print(f"  Safe: {len(safe_samples):,}")
    print(f"  Security-relevant: {len(security_samples):,}")

    # Target mostly safe samples
    max_safe = min(int(max_samples * 0.85), len(safe_samples))
    max_security = min(max_samples - max_safe, len(security_samples))

    random.shuffle(safe_samples)
    random.shuffle(security_samples)

    selected = safe_samples[:max_safe] + security_samples[:max_security]
    random.shuffle(selected)

    # Write output
    subcat_counts = defaultdict(int)
    with open(out_path, "w") as fout:
        for i, item in enumerate(selected):
            for f in item["findings"]:
                subcat_counts[f["subcategory"]] += 1
            record = {
                "id": f"loghub_{i:05d}",
                "source": "loghub",
                "source_license": "research_free",
                "text": item["text"],
                "findings": item["findings"],
            }
            fout.write(json.dumps(record) + "\n")

    print(f"\nWrote {len(selected):,} samples to {out_path}")
    print("\nCategory distribution:")
    for sub, count in sorted(subcat_counts.items()):
        print(f"  {sub}: {count}")


if __name__ == "__main__":
    max_n = int(sys.argv[1]) if len(sys.argv) > 1 else 2000
    process(max_samples=max_n)
