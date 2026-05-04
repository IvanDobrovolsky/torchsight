#!/usr/bin/env python3
"""Create stratified 100-sample subsets from primary and external benchmarks
for blind manual annotation.

Outputs:
  manual-review/primary_100.csv     — annotator worksheet (no ground truth visible)
  manual-review/external_100.csv    — annotator worksheet (no ground truth visible)
  manual-review/primary_100_KEY.csv — author-only file with ground truth
  manual-review/external_100_KEY.csv
  manual-review/README.md           — annotator instructions

Run: python scripts/sample_for_manual_review.py
"""
import csv
import json
import random
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PRIMARY_DIR = ROOT / "data" / "eval-1000-synthetic"
EXTERNAL_DIR = ROOT / "data" / "eval-500-external"
OUT = ROOT / "manual-review"
OUT.mkdir(exist_ok=True)

SEED = 2026
PREVIEW_CHARS = 1500

CATEGORIES = ["credentials", "pii", "financial", "medical",
              "confidential", "malicious", "safe"]

PRIMARY_QUOTA = {
    "credentials": 15, "pii": 15, "malicious": 15, "safe": 25,
    "financial": 10, "medical": 10, "confidential": 10,
}

EXTERNAL_QUOTA = {
    "nvd_holdout": 20, "mtsamples": 20, "nist_holdout": 16,
    "ai4privacy_holdout": 16, "enron_holdout": 16, "phishing_holdout": 12,
}


def read_text(file_path: Path) -> str:
    try:
        return file_path.read_text(errors="replace")[:PREVIEW_CHARS]
    except Exception as e:
        return f"[READ ERROR: {e}]"


def stratified_sample(entries, quota_key, quota):
    rng = random.Random(SEED)
    sampled = []
    by_key = {}
    for e in entries:
        by_key.setdefault(e[quota_key], []).append(e)
    for key, n in quota.items():
        pool = by_key.get(key, [])
        if len(pool) < n:
            raise ValueError(f"Not enough samples for {key}: need {n}, have {len(pool)}")
        sampled.extend(rng.sample(pool, n))
    rng.shuffle(sampled)  # randomize order so reviewer doesn't see categories grouped
    return sampled


def write_worksheet(rows, out_path: Path, base_dir: Path, source_field=None):
    with out_path.open("w", newline="") as f:
        w = csv.writer(f)
        header = [
            "review_id", "file",
            "annotator_category", "annotator_subcategory", "annotator_notes",
            "content_preview",
        ]
        w.writerow(header)
        for i, row in enumerate(rows, 1):
            file_path = base_dir / row["file"]
            preview = read_text(file_path).replace("\n", " \\n ")
            w.writerow([
                f"R{i:03d}", row["file"],
                "", "", "",  # annotator fills these
                preview,
            ])


def write_key(rows, out_path: Path, source_field=None):
    with out_path.open("w", newline="") as f:
        w = csv.writer(f)
        cols = ["review_id", "file", "true_category", "true_subcategory"]
        if source_field:
            cols.append("source")
        cols.append("note")
        w.writerow(cols)
        for i, row in enumerate(rows, 1):
            line = [f"R{i:03d}", row["file"], row["category"], row.get("subcategory", "")]
            if source_field:
                line.append(row.get(source_field, ""))
            line.append(row.get("note", ""))
            w.writerow(line)


def main():
    primary_gt = json.loads((PRIMARY_DIR / "ground-truth.json").read_text())
    primary_text_only = [e for e in primary_gt if e.get("bucket") != "images"]
    primary_sample = stratified_sample(primary_text_only, "category", PRIMARY_QUOTA)
    write_worksheet(primary_sample, OUT / "primary_100.csv", PRIMARY_DIR)
    write_key(primary_sample, OUT / "primary_100_KEY.csv")

    external_gt = json.loads((EXTERNAL_DIR / "ground-truth.json").read_text())
    external_sample = stratified_sample(external_gt, "source", EXTERNAL_QUOTA)
    write_worksheet(external_sample, OUT / "external_100.csv", EXTERNAL_DIR)
    write_key(external_sample, OUT / "external_100_KEY.csv", source_field="source")

    readme = f"""# TorchSight Manual Annotation — Reviewer Instructions

You are reviewing **100 documents** to verify category labels for a security
classification benchmark. Two reviewers will label the same set independently.
**Do not consult the ground truth file or the other reviewer.**

## Files

- `primary_100.csv` — 100 docs from the primary 1,000-sample benchmark
  (programmatically generated; verifying generator → label fidelity)
- `external_100.csv` — 100 docs from the 500-sample external benchmark
  (drawn from real public datasets: NVD, NIST, MTSamples, AI4Privacy, Enron, Phishing)

## Categories (pick exactly one per document)

1. **credentials** — passwords, API keys, tokens, private keys, connection strings
2. **pii** — names+SSN, biometrics, contact info, government IDs, behavioral data
3. **financial** — credit cards, bank accounts, transactions, tax forms (W-2 etc.)
4. **medical** — diagnoses, prescriptions, lab results, insurance records
5. **confidential** — TOP SECRET / OPORD / classified / military / intelligence
6. **malicious** — exploits, shells, phishing, malware, prompt injection, supply chain
7. **safe** — tutorials, public docs, open-source code, harmless config, business email

If a document fits multiple, pick the **most severe non-safe** label.
If you genuinely cannot tell, mark `unsure` in `annotator_category`.

## How to fill the CSV

For each row, fill three columns:

- `annotator_category` — one of the 7 labels above (or `unsure`)
- `annotator_subcategory` — optional fine-grained label, e.g. `credentials.api_key`
- `annotator_notes` — optional 1-line note (esp. if you marked `unsure`
  or disagree strongly with what the file appears to be)

The `content_preview` column shows the first {PREVIEW_CHARS} characters of the file.
For full content, open `eval-1000/<file>` or `eval-external/<file>` in the repo.

## Estimated time

~3–5 hours total for 200 samples (90 sec/doc on average).

## Random seed

Stratified sample drawn with seed = {SEED}. Re-running the script reproduces the same selection.
"""
    (OUT / "README.md").write_text(readme)

    print(f"Wrote: {OUT}/primary_100.csv ({len(primary_sample)} rows)")
    print(f"Wrote: {OUT}/external_100.csv ({len(external_sample)} rows)")
    print(f"Wrote: {OUT}/primary_100_KEY.csv (author only — keep blind from reviewers)")
    print(f"Wrote: {OUT}/external_100_KEY.csv (author only)")
    print(f"Wrote: {OUT}/README.md")


if __name__ == "__main__":
    main()
