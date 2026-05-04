#!/usr/bin/env python3
"""Evaluate Beam (or any Ollama model) on the eval-500-external 500-sample benchmark.

Methodology mirrors eval_beam.py exactly: same query_beam, same parser
(parse_beam_response with resolve_category fix-up), same scorer (alt_category
honored), same prompt format, same Modelfile-default sampling parameters.
This script is a thin wrapper around eval_beam.py — DO NOT duplicate logic.

The external ground truth (eval-500-external/ground-truth.json) carries
`alt_category` for 320/500 samples (NVD held-out, NIST held-out, Enron
held-out, phishing held-out). Both labels are accepted as correct.

Usage:
    python eval_external.py                          # default: torchsight/beam:q4_K_M
    BEAM_MODEL=torchsight/beam:q8_0 python eval_external.py
    BEAM_MODEL=torchsight/beam:f16 python eval_external.py
    BEAM_MODEL=qwen3.5:27b python eval_external.py   # base-model comparison
    OLLAMA_URL=http://1.2.3.4:11434 python eval_external.py
"""

import json
import os
import sys
import time
from collections import defaultdict
from pathlib import Path

# Import everything from eval_beam.py — guarantees identical methodology
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from eval_beam import (  # noqa: E402
    OLLAMA_URL,
    check_ollama,
    query_beam,
    parse_beam_response,
    get_primary_category,
    get_primary_subcategory,
    category_match,
    subcategory_match,
)

MODEL = os.environ.get("BEAM_MODEL", "torchsight/beam:q4_K_M")
EVAL_DIR = Path(__file__).resolve().parent.parent / "data" / "eval-500-external"
GROUND_TRUTH = EVAL_DIR / "ground-truth.json"
RESULTS_DIR = Path(__file__).resolve().parent.parent / "results"
RESULTS_DIR.mkdir(parents=True, exist_ok=True)


def main() -> None:
    print(f"Model:    {MODEL}")
    print(f"Ollama:   {OLLAMA_URL}")
    print(f"Eval:     {EVAL_DIR}")
    check_ollama(MODEL)

    with open(GROUND_TRUTH) as f:
        samples = json.load(f)

    model_tag = MODEL.replace("/", "-").replace(":", "-")
    output_path = RESULTS_DIR / f"eval_external_{model_tag}.json"

    # Resume support — keep results that already succeeded
    results = []
    done_ids = set()
    if output_path.exists():
        try:
            with open(output_path) as f:
                results = json.load(f).get("results", [])
            done_ids = {r["id"] for r in results if not r.get("error")}
            print(f"Resuming: {len(done_ids)} samples already done")
        except (json.JSONDecodeError, KeyError):
            print("Existing output unreadable, starting fresh")
            results = []
            done_ids = set()

    print(f"\nEvaluating {len(samples) - len(done_ids)} of {len(samples)} samples\n")
    print("=" * 100)

    source_stats: dict = defaultdict(lambda: {"total": 0, "correct": 0})
    category_stats: dict = defaultdict(lambda: {"total": 0, "correct": 0})

    for sample in samples:
        if sample["id"] in done_ids:
            continue

        file_path = EVAL_DIR / sample["file"]
        if not file_path.exists():
            print(f"  SKIP [{sample['id']:4d}] {sample['file']} — not found")
            continue

        with open(file_path, "r", errors="replace") as f:
            content = f.read()[:6000]  # match eval_beam.py truncation

        print(
            f"  [{sample['id']:4d}] {sample['source']:<22s} {sample['file']:<35s}",
            end="",
            flush=True,
        )
        start = time.time()

        try:
            response = query_beam(content, MODEL)
            elapsed = time.time() - start
            findings = parse_beam_response(response)
            pred_cat = get_primary_category(findings)
            pred_subcat = get_primary_subcategory(findings)

            expected_cat = sample["category"]
            expected_subcat = sample["subcategory"]
            alt_cat = sample.get("alt_category", "")
            alt_subcat = sample.get("alt_subcategory", "")

            cat_ok = (
                category_match(pred_cat, expected_cat)
                or (bool(alt_cat) and category_match(pred_cat, alt_cat))
            )
            subcat_ok = (
                subcategory_match(pred_subcat, expected_subcat)
                or (bool(alt_subcat) and subcategory_match(pred_subcat, alt_subcat))
            )

            status = "OK" if cat_ok else "MISS"
            sub_status = "ok" if subcat_ok else "miss"
            print(
                f" {elapsed:5.1f}s  cat={pred_cat:<14s} [{status:4s}]"
                f"  sub={pred_subcat:<28s} [{sub_status}]"
            )

            results.append(
                {
                    "id": sample["id"],
                    "file": sample["file"],
                    "source": sample["source"],
                    "expected_cat": expected_cat,
                    "expected_subcat": expected_subcat,
                    "predicted_cat": pred_cat,
                    "predicted_subcat": pred_subcat,
                    "cat_correct": cat_ok,
                    "subcat_correct": subcat_ok,
                    "elapsed": elapsed,
                    "num_findings": len(findings),
                    "raw_findings": findings,
                }
            )

        except Exception as e:
            elapsed = time.time() - start
            print(f" {elapsed:5.1f}s  ERROR: {e}")
            results.append(
                {
                    "id": sample["id"],
                    "file": sample["file"],
                    "source": sample["source"],
                    "expected_cat": sample["category"],
                    "expected_subcat": sample.get("subcategory", ""),
                    "predicted_cat": "error",
                    "predicted_subcat": "error",
                    "cat_correct": False,
                    "subcat_correct": False,
                    "error": str(e),
                    "elapsed": elapsed,
                }
            )

        # Checkpoint every sample (cheap; protects against interruptions)
        total = len(results)
        cat_correct = sum(1 for r in results if r.get("cat_correct"))
        subcat_correct = sum(1 for r in results if r.get("subcat_correct"))
        with open(output_path, "w") as f:
            json.dump(
                {
                    "model": MODEL,
                    "benchmark": "external-500",
                    "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                    "total_samples": total,
                    "category_accuracy": cat_correct / total if total else 0,
                    "subcategory_accuracy": subcat_correct / total if total else 0,
                    "results": results,
                },
                f,
                indent=2,
                default=str,
            )

    # Final per-source / per-category breakdown
    for r in results:
        if r.get("error"):
            continue
        source_stats[r["source"]]["total"] += 1
        if r.get("cat_correct"):
            source_stats[r["source"]]["correct"] += 1
        category_stats[r["expected_cat"]]["total"] += 1
        if r.get("cat_correct"):
            category_stats[r["expected_cat"]]["correct"] += 1

    total = len(results)
    cat_correct = sum(1 for r in results if r.get("cat_correct"))
    subcat_correct = sum(1 for r in results if r.get("subcat_correct"))
    errors = sum(1 for r in results if r.get("error"))
    times = [r["elapsed"] for r in results if "elapsed" in r and not r.get("error")]

    print("\n" + "=" * 100)
    print(f"{'EXTERNAL BENCHMARK RESULTS — ' + MODEL:^100}")
    print("=" * 100)
    print(f"  Samples evaluated:  {total}")
    print(f"  Errors:             {errors}")
    print(f"  Category accuracy:  {cat_correct}/{total} = {cat_correct / total * 100:.1f}%")
    print(f"  Subcategory acc.:   {subcat_correct}/{total} = {subcat_correct / total * 100:.1f}%")
    if times:
        print(f"  Avg time/sample:    {sum(times) / len(times):.1f}s")
        print(f"  Total wall-clock:   {sum(times):.0f}s ({sum(times) / 60:.1f}m)")

    print(f"\n{'ACCURACY BY SOURCE':^100}")
    print("-" * 100)
    for src in sorted(source_stats):
        s = source_stats[src]
        acc = s["correct"] / s["total"] * 100
        print(f"  {src:<25s} {s['correct']:>4d}/{s['total']:<4d} = {acc:5.1f}%")

    print(f"\n{'ACCURACY BY CATEGORY':^100}")
    print("-" * 100)
    for cat in sorted(category_stats):
        s = category_stats[cat]
        acc = s["correct"] / s["total"] * 100
        print(f"  {cat:<15s} {s['correct']:>4d}/{s['total']:<4d} = {acc:5.1f}%")

    print(f"\nResults saved to: {output_path}")


if __name__ == "__main__":
    main()
