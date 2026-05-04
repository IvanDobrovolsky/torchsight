#!/usr/bin/env python3
"""Evaluate TorchSight CLI against eval-1000-synthetic ground truth.

Runs the actual torchsight binary on each sample file, parses the JSON output,
and compares predicted categories against ground truth.

Usage:
    python eval_torchsight.py                          # default: torchsight/beam model
    TEXT_MODEL=qwen3.5:27b python eval_torchsight.py   # base model comparison
    OLLAMA_URL=http://localhost:11434 python eval_torchsight.py

Env vars:
    TEXT_MODEL    — Ollama model name (default: torchsight/beam)
    VISION_MODEL  — Vision model (default: llama3.2-vision)
    OLLAMA_URL    — Ollama server URL (default: http://localhost:11434)
    TORCHSIGHT    — Path to torchsight binary (default: ./torchsight)
    EVAL_DIR      — Path to eval-1000-synthetic directory (default: ./eval-1000-synthetic)
    START_ID      — Resume from this sample ID (default: 1)
"""
import json
import os
import subprocess
import sys
import time
from pathlib import Path

EVAL_DIR = os.environ.get("EVAL_DIR", os.path.join(os.path.dirname(__file__), "..", "data", "eval-1000-synthetic"))
TORCHSIGHT = os.environ.get("TORCHSIGHT", "./torchsight")
TEXT_MODEL = os.environ.get("TEXT_MODEL", "torchsight/beam")
VISION_MODEL = os.environ.get("VISION_MODEL", "llama3.2-vision")
OLLAMA_URL = os.environ.get("OLLAMA_URL", "http://localhost:11434")
START_ID = int(os.environ.get("START_ID", "1"))


def category_match(predicted: str, expected: str) -> bool:
    return predicted.lower().strip() == expected.lower().strip()


def subcategory_match(predicted: str, expected: str) -> bool:
    p = predicted.lower().strip()
    e = expected.lower().strip()
    if p == e:
        return True
    if "." in e:
        return p == e.split(".")[-1]
    return False


def scan_file(filepath: str) -> dict:
    """Run torchsight on a single file, return parsed JSON result."""
    cmd = [
        TORCHSIGHT,
        filepath,
        "--format", "json",
        "--text-model", TEXT_MODEL,
        "--vision-model", VISION_MODEL,
        "--ollama-url", OLLAMA_URL,
    ]
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=600
        )
        # torchsight prints JSON to stdout
        output = result.stdout.strip()
        if not output:
            return {"error": f"No output. stderr: {result.stderr[:200]}"}
        return json.loads(output)
    except subprocess.TimeoutExpired:
        return {"error": "timeout (600s)"}
    except json.JSONDecodeError as e:
        return {"error": f"JSON parse error: {e}"}
    except Exception as e:
        return {"error": str(e)}


def extract_category(scan_result: dict) -> tuple:
    """Extract the primary category and subcategory from torchsight scan output."""
    files = scan_result.get("files", [])
    if not files:
        return "unknown", "unknown"

    findings = files[0].get("findings", [])
    if not findings:
        return "safe", "safe"

    # If all findings are safe, return safe
    non_safe = [f for f in findings if f.get("category", "").lower() != "safe"]
    if not non_safe:
        # Get the safe finding's subcategory if available
        safe_f = findings[0]
        subcat = safe_f.get("subcategory", safe_f.get("category", "safe"))
        return "safe", subcat

    # Return the highest-severity non-safe finding
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    non_safe.sort(key=lambda f: severity_order.get(f.get("severity", "info").lower(), 5))
    top = non_safe[0]
    return top.get("category", "unknown").lower(), top.get("subcategory", top.get("category", "unknown")).lower()


def main():
    # Load ground truth
    gt_path = os.path.join(EVAL_DIR, "ground-truth.json")
    with open(gt_path) as f:
        gt = json.load(f)

    samples = gt if isinstance(gt, list) else gt.get("samples", gt.get("entries", []))
    samples = [s for s in samples if s["id"] >= START_ID]
    samples.sort(key=lambda s: s["id"])

    model_tag = TEXT_MODEL.replace("/", "_").replace(":", "_")
    out_file = f"eval1000_results_{model_tag}.json"

    print(f"Model: {TEXT_MODEL}")
    print(f"Binary: {TORCHSIGHT}")
    print(f"Eval dir: {EVAL_DIR}")
    print(f"Samples: {len(samples)} (starting from ID {START_ID})")
    print(f"Output: {out_file}")
    print(f"\n{'='*90}")

    results = []
    # Load existing results if resuming
    if START_ID > 1 and os.path.exists(out_file):
        with open(out_file) as f:
            existing = json.load(f)
        results = existing.get("results", [])
        print(f"  Loaded {len(results)} existing results, resuming from ID {START_ID}")

    cat_correct = sum(1 for r in results if r.get("cat_correct"))
    subcat_correct = sum(1 for r in results if r.get("subcat_correct"))
    errors = sum(1 for r in results if r.get("error"))
    total = len(results)

    for sample in samples:
        sid = sample["id"]
        filepath = os.path.join(EVAL_DIR, sample["file"])

        if not os.path.exists(filepath):
            print(f"  SKIP [{sid:4d}] {sample['file']} — not found")
            continue

        print(f"  [{sid:4d}] {sample['file']:<55s}", end="", flush=True)
        t0 = time.time()

        scan_result = scan_file(filepath)
        elapsed = time.time() - t0

        if "error" in scan_result and "files" not in scan_result:
            print(f" {elapsed:5.1f}s  ERROR: {scan_result['error'][:80]}")
            results.append({
                "id": sid,
                "file": sample["file"],
                "bucket": sample.get("bucket", sample.get("category", "")),
                "expected_cat": sample["category"],
                "expected_subcat": sample["subcategory"],
                "predicted_cat": "error",
                "predicted_subcat": "error",
                "cat_correct": False,
                "subcat_correct": False,
                "error": scan_result["error"],
                "elapsed": elapsed,
            })
            errors += 1
            total += 1
            continue

        pred_cat, pred_subcat = extract_category(scan_result)
        expected_cat = sample["category"]
        expected_subcat = sample["subcategory"]
        alt_cat = sample.get("alt_category", "")
        alt_subcat = sample.get("alt_subcategory", "")

        cat_ok = category_match(pred_cat, expected_cat) or (bool(alt_cat) and category_match(pred_cat, alt_cat))
        subcat_ok = subcategory_match(pred_subcat, expected_subcat) or (bool(alt_subcat) and subcategory_match(pred_subcat, alt_subcat))

        if cat_ok:
            cat_correct += 1
        if subcat_ok:
            subcat_correct += 1
        total += 1

        status = "OK" if cat_ok else "MISS"
        sub_status = "ok" if subcat_ok else "miss"
        print(f" {elapsed:5.1f}s  cat={pred_cat:<14s} [{status:4s}]  sub={pred_subcat:<30s} [{sub_status}]")

        # Extract all findings for the result
        findings = []
        for file_entry in scan_result.get("files", []):
            findings.extend(file_entry.get("findings", []))

        results.append({
            "id": sid,
            "file": sample["file"],
            "bucket": sample.get("bucket", sample.get("category", "")),
            "expected_cat": expected_cat,
            "expected_subcat": expected_subcat,
            "predicted_cat": pred_cat,
            "predicted_subcat": pred_subcat,
            "cat_correct": cat_ok,
            "subcat_correct": subcat_ok,
            "severity": sample.get("severity", ""),
            "elapsed": elapsed,
            "num_findings": len(findings),
            "raw_findings": findings,
        })

        # Save periodically
        if total % 50 == 0:
            _save_results(out_file, results, total, cat_correct, subcat_correct, errors)

    # Final save
    _save_results(out_file, results, total, cat_correct, subcat_correct, errors)

    print(f"\n{'='*90}")
    print(f"\n{'OVERALL RESULTS':^90}")
    print(f"{'='*90}")
    print(f"  Model:                {TEXT_MODEL}")
    print(f"  Samples evaluated:    {total}")
    print(f"  Errors:               {errors}")
    print(f"  Category accuracy:    {cat_correct}/{total} = {cat_correct/total*100:.1f}%")
    print(f"  Subcategory accuracy: {subcat_correct}/{total} = {subcat_correct/total*100:.1f}%")
    print(f"  Output:               {out_file}")


def _save_results(out_file, results, total, cat_correct, subcat_correct, errors):
    data = {
        "model": TEXT_MODEL,
        "total_samples": total,
        "category_accuracy": cat_correct / total if total > 0 else 0,
        "subcategory_accuracy": subcat_correct / total if total > 0 else 0,
        "errors": errors,
        "results": results,
    }
    with open(out_file, "w") as f:
        json.dump(data, f, indent=2, default=str)


if __name__ == "__main__":
    main()
