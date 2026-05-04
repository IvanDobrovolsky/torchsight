#!/usr/bin/env python3
"""
Build an external validation benchmark from sources NOT in Beam's training set,
or from held-out portions of sources that were used.

Sources:
1. MTSamples (medical transcriptions) — EXPLICITLY EXCLUDED from training
2. Held-out NVD CVEs — training used 50K, there are 200K+
3. Held-out AI4Privacy — training used 5K from a much larger dataset
4. Held-out Enron — training used 2K from 500K+ emails
5. NIST safe documentation — held-out from the 3K used

Target: ~500 samples with ground-truth labels from the original source.
"""

import csv
import hashlib
import json
import os
import random
import sys

random.seed(42)

BEAM_DATA = "/Users/id/Desktop/torchsight/beam/data"
PROCESSED = os.path.join(BEAM_DATA, "processed")
RAW = os.path.join(BEAM_DATA, "raw")
OUT_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "data", "eval-500-external")
os.makedirs(OUT_DIR, exist_ok=True)

# ============================================================
# Step 1: Load training data text hashes to ensure no overlap
# ============================================================
def load_training_hashes():
    """Hash all training texts to detect any overlap."""
    hashes = set()
    balanced = os.path.join(PROCESSED, "combined_train_balanced.jsonl")
    print(f"Loading training hashes from {balanced}...")
    with open(balanced) as f:
        for line in f:
            d = json.loads(line)
            text = d.get("text", "")
            h = hashlib.sha256(text[:500].encode()).hexdigest()[:16]
            hashes.add(h)
    print(f"  Loaded {len(hashes)} training text hashes")
    return hashes

def text_hash(text):
    return hashlib.sha256(text[:500].encode()).hexdigest()[:16]


# ============================================================
# Source 1: MTSamples — medical transcriptions (EXCLUDED from training)
# ============================================================
def build_mtsamples(training_hashes):
    """MTSamples was explicitly excluded from training due to provenance concerns.
    These are real medical transcription samples with PHI patterns."""
    csv_path = os.path.join(RAW, "mtsamples.csv")
    if not os.path.exists(csv_path):
        print("  SKIP: mtsamples.csv not found")
        return []

    samples = []
    with open(csv_path, encoding='utf-8', errors='replace') as f:
        reader = csv.reader(f)
        header = next(reader)
        for row in reader:
            if len(row) < 5:
                continue
            transcription = row[4] if len(row) > 4 else ""
            specialty = row[2] if len(row) > 2 else ""
            if len(transcription) < 200:
                continue
            h = text_hash(transcription)
            if h in training_hashes:
                continue
            samples.append({
                "text": transcription[:6000],
                "category": "medical",
                "subcategory": "medical.diagnosis",
                "source": "mtsamples",
                "source_detail": specialty,
            })

    random.shuffle(samples)
    selected = samples[:100]
    print(f"  MTSamples: {len(selected)} samples (from {len(samples)} available)")
    return selected


# ============================================================
# Source 2: Held-out NVD CVEs
# ============================================================
def build_nvd_holdout(training_hashes):
    """NVD has 50K in training. Load the full processed file and find ones NOT in training."""
    nvd_path = os.path.join(PROCESSED, "nvd.jsonl")
    if not os.path.exists(nvd_path):
        print("  SKIP: nvd.jsonl not found")
        return []

    all_nvd = []
    with open(nvd_path) as f:
        for line in f:
            d = json.loads(line)
            text = d.get("text", "")
            h = text_hash(text)
            if h not in training_hashes and len(text) > 100:
                all_nvd.append({
                    "text": text[:6000],
                    "category": "malicious",
                    "subcategory": d.get("findings", [{}])[0].get("subcategory", "malicious.exploit") if d.get("findings") else "malicious.exploit",
                    "source": "nvd_holdout",
                })

    random.shuffle(all_nvd)
    selected = all_nvd[:100]
    print(f"  NVD held-out: {len(selected)} samples (from {len(all_nvd)} available)")
    return selected


# ============================================================
# Source 3: Held-out AI4Privacy
# ============================================================
def build_ai4privacy_holdout(training_hashes):
    """AI4Privacy has far more than 5K. Find samples not in training."""
    path = os.path.join(PROCESSED, "ai4privacy.jsonl")
    if not os.path.exists(path):
        print("  SKIP: ai4privacy.jsonl not found")
        return []

    all_samples = []
    with open(path) as f:
        for line in f:
            d = json.loads(line)
            text = d.get("text", "")
            h = text_hash(text)
            if h not in training_hashes and len(text) > 100:
                all_samples.append({
                    "text": text[:6000],
                    "category": "pii",
                    "subcategory": d.get("findings", [{}])[0].get("subcategory", "pii.identity") if d.get("findings") else "pii.identity",
                    "source": "ai4privacy_holdout",
                })

    random.shuffle(all_samples)
    selected = all_samples[:80]
    print(f"  AI4Privacy held-out: {len(selected)} samples (from {len(all_samples)} available)")
    return selected


# ============================================================
# Source 4: Held-out Enron emails
# ============================================================
def build_enron_holdout(training_hashes):
    """Enron raw archive has 500K+ emails, training used 2K."""
    path = os.path.join(PROCESSED, "enron.jsonl")
    if not os.path.exists(path):
        print("  SKIP: enron.jsonl not found")
        return []

    all_samples = []
    with open(path) as f:
        for line in f:
            d = json.loads(line)
            text = d.get("text", "")
            h = text_hash(text)
            if h not in training_hashes and len(text) > 100:
                findings = d.get("findings", [{}])
                cat = findings[0].get("category", "pii") if findings else "pii"
                subcat = findings[0].get("subcategory", "pii.contact") if findings else "pii.contact"
                all_samples.append({
                    "text": text[:6000],
                    "category": cat,
                    "subcategory": subcat,
                    "source": "enron_holdout",
                })

    random.shuffle(all_samples)
    selected = all_samples[:80]
    print(f"  Enron held-out: {len(selected)} samples (from {len(all_samples)} available)")
    return selected


# ============================================================
# Source 5: Held-out phishing emails
# ============================================================
def build_phishing_holdout(training_hashes):
    """Phishing dataset — find held-out samples."""
    path = os.path.join(PROCESSED, "phishing.jsonl")
    if not os.path.exists(path):
        print("  SKIP: phishing.jsonl not found")
        return []

    all_samples = []
    with open(path) as f:
        for line in f:
            d = json.loads(line)
            text = d.get("text", "")
            h = text_hash(text)
            if h not in training_hashes and len(text) > 100:
                all_samples.append({
                    "text": text[:6000],
                    "category": "malicious",
                    "subcategory": "malicious.phishing",
                    "source": "phishing_holdout",
                })

    random.shuffle(all_samples)
    selected = all_samples[:60]
    print(f"  Phishing held-out: {len(selected)} samples (from {len(all_samples)} available)")
    return selected


# ============================================================
# Source 6: Held-out NIST safe documentation
# ============================================================
def build_nist_holdout(training_hashes):
    """NIST training docs — safe content not in training."""
    path = os.path.join(PROCESSED, "nist.jsonl")
    if not os.path.exists(path):
        print("  SKIP: nist.jsonl not found")
        return []

    all_samples = []
    with open(path) as f:
        for line in f:
            d = json.loads(line)
            text = d.get("text", "")
            h = text_hash(text)
            if h not in training_hashes and len(text) > 100:
                all_samples.append({
                    "text": text[:6000],
                    "category": "safe",
                    "subcategory": "safe.documentation",
                    "source": "nist_holdout",
                })

    random.shuffle(all_samples)
    selected = all_samples[:80]
    print(f"  NIST held-out: {len(selected)} samples (from {len(all_samples)} available)")
    return selected


# ============================================================
# Build benchmark
# ============================================================
def main():
    print("Building external validation benchmark...")
    print("=" * 60)

    training_hashes = load_training_hashes()

    all_samples = []
    all_samples.extend(build_mtsamples(training_hashes))
    all_samples.extend(build_nvd_holdout(training_hashes))
    all_samples.extend(build_ai4privacy_holdout(training_hashes))
    all_samples.extend(build_enron_holdout(training_hashes))
    all_samples.extend(build_phishing_holdout(training_hashes))
    all_samples.extend(build_nist_holdout(training_hashes))

    random.shuffle(all_samples)

    # Assign IDs
    for i, s in enumerate(all_samples, 1):
        s["id"] = i

    # Write ground truth
    gt_path = os.path.join(OUT_DIR, "ground-truth.json")
    with open(gt_path, "w") as f:
        json.dump(all_samples, f, indent=2)

    # Write individual files
    for s in all_samples:
        cat_dir = os.path.join(OUT_DIR, s["category"])
        os.makedirs(cat_dir, exist_ok=True)
        fname = f"ext-{s['id']:04d}.txt"
        s["file"] = f"{s['category']}/{fname}"
        with open(os.path.join(cat_dir, fname), "w") as f:
            f.write(s["text"])

    # Re-save with file paths
    with open(gt_path, "w") as f:
        json.dump(all_samples, f, indent=2)

    # Summary
    print("\n" + "=" * 60)
    print(f"Total samples: {len(all_samples)}")
    cats = {}
    sources = {}
    for s in all_samples:
        cats[s["category"]] = cats.get(s["category"], 0) + 1
        sources[s["source"]] = sources.get(s["source"], 0) + 1

    print("\nBy category:")
    for c in sorted(cats):
        print(f"  {c:<15s} {cats[c]:>4d}")

    print("\nBy source:")
    for s in sorted(sources):
        print(f"  {s:<25s} {sources[s]:>4d}")

    print(f"\nGround truth: {gt_path}")
    print(f"Files in: {OUT_DIR}/")


if __name__ == "__main__":
    main()
