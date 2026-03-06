#!/usr/bin/env python3
"""
TorchSight Master Processing Pipeline

Runs all dataset processors and generates a combined training dataset.

Usage:
    python process_all.py              # Process all datasets
    python process_all.py --only enron # Process single dataset
    python process_all.py --stats      # Show stats for existing processed data
"""

import json
import sys
from pathlib import Path

DATA_DIR = Path(__file__).parent.parent.parent / "data"
PROCESSED_DIR = DATA_DIR / "processed"
SYNTHETIC_DIR = DATA_DIR / "synthetic"
COMBINED_PATH = PROCESSED_DIR / "combined_train.jsonl"

PROCESSORS = {
    "enron": "enron_processor",
    "seclists": "seclists_processor",
    "mitre": "mitre_processor",
    "nvd": "nvd_processor",
    "mtsamples": "mtsamples_processor",
    "crs_reports": "crs_processor",
    "prompt_injection": "prompt_injection_processor",
    "ghsa": "ghsa_processor",
    "ossf": "ossf_processor",
}


def run_processor(name: str):
    """Import and run a processor module."""
    print(f"\n{'=' * 60}")
    print(f"  Processing: {name}")
    print(f"{'=' * 60}")

    module_name = PROCESSORS[name]
    module = __import__(module_name)
    # Support both process() and main() entry points
    if hasattr(module, "process"):
        module.process()
    elif hasattr(module, "main"):
        module.main()
    else:
        print(f"  WARNING: {module_name} has no process() or main() function")


def combine_datasets():
    """Combine all processed JSONL files into one training file."""
    PROCESSED_DIR.mkdir(parents=True, exist_ok=True)

    total = 0
    source_counts = {}

    # Gather JSONL files from both processed and synthetic dirs
    all_files = []
    for jsonl_file in sorted(PROCESSED_DIR.glob("*.jsonl")):
        if jsonl_file.name != "combined_train.jsonl":
            all_files.append(jsonl_file)
    if SYNTHETIC_DIR.exists():
        for jsonl_file in sorted(SYNTHETIC_DIR.glob("*.jsonl")):
            all_files.append(jsonl_file)

    with open(COMBINED_PATH, "w") as fout:
        for jsonl_file in all_files:
            source = jsonl_file.stem
            count = 0
            with open(jsonl_file) as fin:
                for line in fin:
                    line = line.strip()
                    if line:
                        fout.write(line + "\n")
                        count += 1
                        total += 1

            source_counts[source] = count

    print(f"\n{'=' * 60}")
    print(f"  Combined Training Dataset")
    print(f"{'=' * 60}")
    print(f"\nTotal samples: {total:,}")
    print(f"\nBy source:")
    for source, count in sorted(source_counts.items()):
        print(f"  {source}: {count:,}")
    print(f"\nOutput: {COMBINED_PATH}")


def show_stats():
    """Show statistics for existing processed data."""
    if not PROCESSED_DIR.exists():
        print("No processed data found. Run processors first.")
        return

    total = 0
    all_files = [f for f in sorted(PROCESSED_DIR.glob("*.jsonl")) if f.name != "combined_train.jsonl"]
    if SYNTHETIC_DIR.exists():
        all_files += sorted(SYNTHETIC_DIR.glob("*.jsonl"))
    for jsonl_file in all_files:

        count = 0
        subcats = {}
        with open(jsonl_file) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                count += 1
                try:
                    record = json.loads(line)
                    for finding in record.get("findings", []):
                        sub = finding.get("subcategory", "unknown")
                        subcats[sub] = subcats.get(sub, 0) + 1
                except Exception:
                    pass

        total += count
        print(f"\n{jsonl_file.stem}: {count:,} samples")
        for sub, c in sorted(subcats.items()):
            print(f"  {sub}: {c}")

    print(f"\n{'=' * 40}")
    print(f"Total processed: {total:,} samples")


def main():
    if "--stats" in sys.argv:
        show_stats()
        return

    if "--only" in sys.argv:
        idx = sys.argv.index("--only")
        if idx + 1 < len(sys.argv):
            name = sys.argv[idx + 1]
            if name not in PROCESSORS:
                print(f"Unknown processor: {name}")
                print(f"Available: {', '.join(PROCESSORS.keys())}")
                sys.exit(1)
            run_processor(name)
            return

    # Run all processors
    for name in PROCESSORS:
        try:
            run_processor(name)
        except Exception as e:
            print(f"ERROR processing {name}: {e}")

    # Combine
    combine_datasets()


if __name__ == "__main__":
    main()
