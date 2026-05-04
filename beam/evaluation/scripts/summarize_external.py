#!/usr/bin/env python3
"""Post-rerun analysis: load all four new external result JSONs and produce
a summary suitable for pasting into FINDINGS.md, build_docx.py, and
generate_figures.py.

Run after eval_external.py completes for every model. Prints:
  - Overall accuracy + 95% Wilson CI per model
  - Per-source breakdown matching FINDINGS.md table format
  - Per-category breakdown
  - Proposed updates for fig10, fig11, paper §6.10 text
"""
from __future__ import annotations

import json
import math
from pathlib import Path

RESULTS = Path(__file__).resolve().parent.parent / "results"

MODELS = [
    ("Beam q4_K_M", "eval_external_torchsight-beam-q4_K_M.json"),
    ("Beam q8_0",   "eval_external_torchsight-beam-q8_0.json"),
    ("Beam f16",    "eval_external_torchsight-beam-f16.json"),
    ("Qwen 27B base", "eval_external_qwen3.5-27b.json"),
]

SOURCES = ["nvd_holdout", "nist_holdout", "mtsamples", "ai4privacy_holdout",
           "phishing_holdout", "enron_holdout"]

SOURCE_LABEL = {
    "nvd_holdout": "NVD held-out",
    "nist_holdout": "NIST held-out",
    "mtsamples": "MTSamples",
    "ai4privacy_holdout": "AI4Privacy held-out",
    "phishing_holdout": "Phishing held-out",
    "enron_holdout": "Enron held-out",
}


def wilson_ci(correct: int, total: int, z: float = 1.96) -> tuple[float, float]:
    """Wilson score interval for a binomial proportion."""
    if total == 0:
        return (0.0, 0.0)
    p = correct / total
    denom = 1 + z * z / total
    center = (p + z * z / (2 * total)) / denom
    margin = z * math.sqrt((p * (1 - p) + z * z / (4 * total)) / total) / denom
    return ((center - margin) * 100, (center + margin) * 100)


def summarize_one(path: Path) -> dict | None:
    if not path.exists():
        return None
    with open(path) as f:
        d = json.load(f)
    results = d["results"]
    n = len(results)
    correct = sum(1 for r in results if r.get("cat_correct"))
    sub_correct = sum(1 for r in results if r.get("subcat_correct"))
    errors = sum(1 for r in results if r.get("error"))

    by_source: dict = {s: {"total": 0, "correct": 0} for s in SOURCES}
    by_category: dict = {}
    for r in results:
        if r.get("error"):
            continue
        s = r.get("source", "?")
        if s not in by_source:
            by_source[s] = {"total": 0, "correct": 0}
        by_source[s]["total"] += 1
        if r.get("cat_correct"):
            by_source[s]["correct"] += 1
        c = r.get("expected_cat", "?")
        if c not in by_category:
            by_category[c] = {"total": 0, "correct": 0}
        by_category[c]["total"] += 1
        if r.get("cat_correct"):
            by_category[c]["correct"] += 1

    times = [r.get("elapsed", 0) for r in results if "elapsed" in r and not r.get("error")]
    return {
        "model": d.get("model", "?"),
        "n": n,
        "correct": correct,
        "accuracy": correct / n if n else 0,
        "sub_accuracy": sub_correct / n if n else 0,
        "errors": errors,
        "ci95": wilson_ci(correct, n),
        "by_source": by_source,
        "by_category": by_category,
        "avg_time_s": sum(times) / len(times) if times else 0,
    }


def main() -> None:
    summaries = {}
    print("=" * 100)
    print("EXTERNAL BENCHMARK SUMMARY — full 500 samples, methodology mirrors eval_beam.py")
    print("=" * 100)
    for label, fname in MODELS:
        s = summarize_one(RESULTS / fname)
        if s is None:
            print(f"\n{label:18s} — not yet available ({fname})")
            continue
        summaries[label] = s
        lo, hi = s["ci95"]
        print(
            f"\n{label:18s} {s['model']}\n"
            f"  Overall: {s['correct']}/{s['n']} = {s['accuracy'] * 100:.1f}%  CI95 [{lo:.1f}, {hi:.1f}]\n"
            f"  Subcat:  {s['sub_accuracy'] * 100:.1f}%   Errors: {s['errors']}   Avg: {s['avg_time_s']:.1f}s/sample"
        )
        print(f"  By source:")
        for src in SOURCES:
            b = s["by_source"].get(src, {"total": 0, "correct": 0})
            if b["total"]:
                print(
                    f"    {SOURCE_LABEL[src]:<22s} {b['correct']:>3d}/{b['total']:<3d} = {b['correct'] / b['total'] * 100:5.1f}%"
                )

    if not summaries:
        return

    # FINDINGS.md table
    print("\n" + "=" * 100)
    print("FINDINGS.md table (External-500 vs Primary):")
    print("=" * 100)
    primary_known = {"Beam q4_K_M": 95.1, "Beam q8_0": 92.7, "Beam f16": 93.0, "Qwen 27B base": 43.3}
    print("\n| Model | External-500 | Primary Eval-1000 | Delta |")
    print("|---|---|---|---|")
    for label in primary_known:
        if label in summaries:
            s = summaries[label]
            ext = s["accuracy"] * 100
            pri = primary_known[label]
            delta = ext - pri
            print(f"| {label} | **{ext:.1f}%** | {pri}% | {delta:+.1f} pp |")

    # Per-source breakdown for headline q4_K_M (matches FINDINGS.md format)
    if "Beam q4_K_M" in summaries:
        print("\nBeam q4_K_M External — Per-Source Breakdown")
        print("\n| Source | Accuracy | Samples |")
        print("|---|---|---|")
        for src in SOURCES:
            b = summaries["Beam q4_K_M"]["by_source"].get(src)
            if b and b["total"]:
                print(f"| {SOURCE_LABEL[src]} | **{b['correct'] / b['total'] * 100:.1f}%** | {b['correct']}/{b['total']} |")

    # generate_figures.py replacement values
    print("\n" + "=" * 100)
    print("generate_figures.py replacements:")
    print("=" * 100)
    if "Beam q4_K_M" in summaries:
        s = summaries["Beam q4_K_M"]
        print(f"\nfig10() per-source bars:")
        per_source_pct = []
        for src in ["nvd_holdout", "nist_holdout", "mtsamples", "ai4privacy_holdout", "phishing_holdout", "enron_holdout"]:
            b = s["by_source"].get(src, {"total": 0, "correct": 0})
            pct = b["correct"] / b["total"] * 100 if b["total"] else 0
            per_source_pct.append(pct)
        print(f"  acc = {[round(p, 1) for p in per_source_pct]}")
        print(f"  ax.axhline(y={s['accuracy'] * 100:.1f}, ...)")
        print(f"  ax.text(..., 'Overall: {s['accuracy'] * 100:.1f}%', ...)")

    # fig11: primary vs external
    print("\nfig11() external bars:")
    ext_q4 = summaries.get("Beam q4_K_M", {}).get("accuracy", 0) * 100
    print(f"  Beam q4_K_M external: {ext_q4:.1f} (was 90.6)")
    print("  Other external numbers unchanged: Claude 86.4, Gemini 82.0, GPT-5 65.8, regex 29.6")


if __name__ == "__main__":
    main()
