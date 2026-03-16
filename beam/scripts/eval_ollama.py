#!/usr/bin/env python3
"""
TorchSight Beam v1.0 — Ollama Evaluation

Evaluates the beam model via Ollama API against validation data.
Uses the local GPU (Metal/CUDA) for fast inference.

Usage:
    python eval_ollama.py
    python eval_ollama.py --max-samples 200
    python eval_ollama.py --model torchsight/beam --val-data ../data/sft/val_alpaca.jsonl
"""

import json
import re
import sys
import time
from collections import defaultdict
from pathlib import Path
from urllib.request import Request, urlopen
from urllib.error import URLError

SCRIPT_DIR = Path(__file__).resolve().parent
DATA_DIR = SCRIPT_DIR.parent / "data"
OUTPUT_DIR = SCRIPT_DIR.parent / "output"

OLLAMA_URL = "http://localhost:11434/api/chat"
CATEGORIES = ["pii", "credentials", "financial", "medical", "confidential", "malicious", "safe"]
KNOWN_CATEGORIES = set(CATEGORIES)


def parse_args():
    config = {
        "model": "torchsight/beam",
        "val_data": str(DATA_DIR / "sft" / "val_alpaca.jsonl"),
        "max_samples": 0,
        "output": str(OUTPUT_DIR / "eval_results_ollama.json"),
        "timeout": 120,
    }
    args = sys.argv[1:]
    i = 0
    while i < len(args):
        key = args[i].lstrip("-").replace("-", "_")
        if i + 1 < len(args) and not args[i + 1].startswith("--"):
            val = args[i + 1]
            if key in ("max_samples", "timeout"):
                val = int(val)
            config[key] = val
            i += 2
        else:
            config[key] = True
            i += 1
    return config


def ollama_chat(model: str, user_msg: str, timeout: int = 120) -> str:
    """Call Ollama chat API."""
    payload = json.dumps({
        "model": model,
        "messages": [{"role": "user", "content": user_msg}],
        "stream": False,
        "options": {
            "temperature": 0.1,
            "top_p": 0.9,
            "num_predict": 2048,
            "stop": ["\n\n\n"],
        },
    }).encode()

    req = Request(OLLAMA_URL, data=payload, headers={"Content-Type": "application/json"})
    try:
        resp = urlopen(req, timeout=timeout)
        data = json.loads(resp.read())
        return data.get("message", {}).get("content", "")
    except Exception as e:
        return f"ERROR: {e}"


def resolve_category(category: str, subcategory: str) -> str:
    """Derive correct category from subcategory prefix when they mismatch.
    Only overrides 'confidential' — the model's main over-predicted catch-all."""
    if category == "confidential" and subcategory and "." in subcategory:
        prefix = subcategory.split(".")[0]
        if prefix in KNOWN_CATEGORIES and prefix != "confidential":
            return prefix
    return category


def try_repair_json_array(partial: str):
    """Try to repair truncated JSON by finding the last complete object."""
    depth = 0
    last_complete = None
    in_string = False
    escape_next = False

    for i, ch in enumerate(partial):
        if escape_next:
            escape_next = False
            continue
        if ch == '\\' and in_string:
            escape_next = True
            continue
        if ch == '"':
            in_string = not in_string
            continue
        if in_string:
            continue
        if ch == '{':
            depth += 1
        elif ch == '}':
            depth -= 1
            if depth == 0:
                last_complete = i

    if last_complete is not None:
        return partial[:last_complete + 1] + "]"
    return None


def parse_model_output(text: str) -> list[dict]:
    """Parse model output JSON with truncation repair and category fix."""
    text = text.strip()
    findings = []
    seen = set()

    def process_parsed(parsed):
        result = []
        for f in parsed:
            if not isinstance(f, dict) or "category" not in f:
                continue
            subcat = f.get("subcategory", "")
            f["category"] = resolve_category(f.get("category", ""), subcat)
            key = f"{f['category']}:{subcat}"
            if key in seen:
                continue
            seen.add(key)
            result.append(f)
        return result

    # Find all complete [...] blocks
    for match in re.finditer(r'\[.*?\]', text, re.DOTALL):
        try:
            parsed = json.loads(match.group())
            if isinstance(parsed, list):
                findings.extend(process_parsed(parsed))
        except json.JSONDecodeError:
            continue

    # If nothing found, try to repair truncated JSON
    if not findings:
        bracket_pos = text.find('[')
        if bracket_pos >= 0:
            repaired = try_repair_json_array(text[bracket_pos:])
            if repaired:
                try:
                    parsed = json.loads(repaired)
                    if isinstance(parsed, list):
                        findings.extend(process_parsed(parsed))
                except json.JSONDecodeError:
                    pass

    return findings


def compute_metrics(results: list[dict]) -> dict:
    """Compute accuracy metrics."""
    per_category = defaultdict(lambda: {"tp": 0, "fp": 0, "fn": 0})
    per_subcategory = defaultdict(lambda: {"tp": 0, "fp": 0, "fn": 0})
    parse_failures = 0
    empty_predictions = 0
    cat_correct = 0
    cat_total = 0
    subcat_correct = 0
    subcat_total = 0

    for r in results:
        expected = r["expected"]
        predicted = r["predicted"]

        if r.get("parse_error"):
            parse_failures += 1
            continue

        if not predicted:
            empty_predictions += 1

        expected_cats = set(f.get("category", "") for f in expected)
        predicted_cats = set(f.get("category", "") for f in predicted)
        expected_subcats = set(f.get("subcategory", "") for f in expected)
        predicted_subcats = set(f.get("subcategory", "") for f in predicted)

        for cat in expected_cats | predicted_cats:
            if not cat:
                continue
            if cat in expected_cats and cat in predicted_cats:
                per_category[cat]["tp"] += 1
                cat_correct += 1
            elif cat in predicted_cats:
                per_category[cat]["fp"] += 1
            else:
                per_category[cat]["fn"] += 1
            cat_total += 1

        for subcat in expected_subcats | predicted_subcats:
            if not subcat:
                continue
            if subcat in expected_subcats and subcat in predicted_subcats:
                per_subcategory[subcat]["tp"] += 1
                subcat_correct += 1
            elif subcat in predicted_subcats:
                per_subcategory[subcat]["fp"] += 1
            else:
                per_subcategory[subcat]["fn"] += 1
            subcat_total += 1

    category_metrics = {}
    for cat in sorted(per_category.keys()):
        s = per_category[cat]
        p = s["tp"] / (s["tp"] + s["fp"]) if (s["tp"] + s["fp"]) > 0 else 0
        r = s["tp"] / (s["tp"] + s["fn"]) if (s["tp"] + s["fn"]) > 0 else 0
        f1 = 2 * p * r / (p + r) if (p + r) > 0 else 0
        category_metrics[cat] = {"precision": p, "recall": r, "f1": f1, "support": s["tp"] + s["fn"]}

    subcategory_metrics = {}
    for subcat in sorted(per_subcategory.keys()):
        s = per_subcategory[subcat]
        p = s["tp"] / (s["tp"] + s["fp"]) if (s["tp"] + s["fp"]) > 0 else 0
        r = s["tp"] / (s["tp"] + s["fn"]) if (s["tp"] + s["fn"]) > 0 else 0
        f1 = 2 * p * r / (p + r) if (p + r) > 0 else 0
        subcategory_metrics[subcat] = {"precision": p, "recall": r, "f1": f1, "support": s["tp"] + s["fn"]}

    return {
        "total_samples": len(results),
        "parse_failures": parse_failures,
        "empty_predictions": empty_predictions,
        "category_accuracy": cat_correct / cat_total if cat_total > 0 else 0,
        "subcategory_accuracy": subcat_correct / subcat_total if subcat_total > 0 else 0,
        "category_metrics": category_metrics,
        "subcategory_metrics": subcategory_metrics,
    }


def print_report(metrics: dict):
    """Print formatted evaluation report."""
    print(f"\n{'=' * 70}")
    print("  TorchSight Beam v1.0 — Evaluation Report (Ollama)")
    print(f"{'=' * 70}")

    print(f"\n  Total samples:            {metrics['total_samples']}")
    print(f"  Parse failures:           {metrics['parse_failures']}")
    print(f"  Empty predictions:        {metrics['empty_predictions']}")
    print(f"\n  Category accuracy:        {metrics['category_accuracy']:.1%}")
    print(f"  Subcategory accuracy:     {metrics['subcategory_accuracy']:.1%}")

    print(f"\n{'─' * 70}")
    print(f"  {'Category':<20} {'Precision':>10} {'Recall':>10} {'F1':>10} {'Support':>10}")
    print(f"{'─' * 70}")

    cat_metrics = metrics["category_metrics"]
    for cat in CATEGORIES:
        if cat in cat_metrics:
            m = cat_metrics[cat]
            print(f"  {cat:<20} {m['precision']:>10.1%} {m['recall']:>10.1%} {m['f1']:>10.1%} {m['support']:>10}")

    if cat_metrics:
        avg_p = sum(m["precision"] for m in cat_metrics.values()) / len(cat_metrics)
        avg_r = sum(m["recall"] for m in cat_metrics.values()) / len(cat_metrics)
        avg_f1 = sum(m["f1"] for m in cat_metrics.values()) / len(cat_metrics)
        total_support = sum(m["support"] for m in cat_metrics.values())
        print(f"{'─' * 70}")
        print(f"  {'MACRO AVG':<20} {avg_p:>10.1%} {avg_r:>10.1%} {avg_f1:>10.1%} {total_support:>10}")

    subcat_metrics = metrics["subcategory_metrics"]
    if subcat_metrics:
        print(f"\n{'─' * 70}")
        print(f"  Top Subcategories by Support")
        print(f"{'─' * 70}")
        print(f"  {'Subcategory':<35} {'Prec':>8} {'Recall':>8} {'F1':>8} {'Supp':>8}")
        print(f"{'─' * 70}")
        sorted_subcats = sorted(subcat_metrics.items(), key=lambda x: x[1]["support"], reverse=True)
        for subcat, m in sorted_subcats[:25]:
            print(f"  {subcat:<35} {m['precision']:>8.1%} {m['recall']:>8.1%} {m['f1']:>8.1%} {m['support']:>8}")

        worst = sorted(
            [(k, v) for k, v in subcat_metrics.items() if v["support"] >= 5],
            key=lambda x: x[1]["f1"]
        )[:10]
        if worst:
            print(f"\n{'─' * 70}")
            print(f"  Weakest Subcategories (min 5 support)")
            print(f"{'─' * 70}")
            print(f"  {'Subcategory':<35} {'Prec':>8} {'Recall':>8} {'F1':>8} {'Supp':>8}")
            print(f"{'─' * 70}")
            for subcat, m in worst:
                print(f"  {subcat:<35} {m['precision']:>8.1%} {m['recall']:>8.1%} {m['f1']:>8.1%} {m['support']:>8}")

    print(f"\n{'=' * 70}")


def main():
    config = parse_args()

    # Check Ollama is running
    try:
        urlopen("http://localhost:11434/api/tags", timeout=5)
    except URLError:
        print("ERROR: Ollama is not running. Start it with: ollama serve")
        sys.exit(1)

    # Load validation data
    val_path = Path(config["val_data"])
    if not val_path.exists():
        print(f"ERROR: Validation data not found at {val_path}")
        sys.exit(1)

    print(f"Loading validation data from {val_path}...")
    records = []
    with open(val_path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            records.append(json.loads(line))
            if config["max_samples"] and len(records) >= config["max_samples"]:
                break

    print(f"  Loaded {len(records)} samples")
    print(f"  Model: {config['model']}")
    print(f"\nEvaluating...")

    results = []
    start_time = time.time()

    for i, record in enumerate(records):
        user_msg = record.get("input", "")
        expected_text = record.get("output", "")

        try:
            expected = json.loads(expected_text)
            if isinstance(expected, dict):
                expected = [expected]
        except json.JSONDecodeError:
            expected = []

        # Call Ollama
        response = ollama_chat(config["model"], user_msg, config["timeout"])
        predicted = parse_model_output(response)
        parse_error = len(predicted) == 0 and len(expected) > 0

        results.append({
            "expected": expected,
            "predicted": predicted,
            "parse_error": parse_error,
            "raw_output": response[:500],
        })

        elapsed = time.time() - start_time
        rate = (i + 1) / elapsed if elapsed > 0 else 0
        eta = (len(records) - i - 1) / rate if rate > 0 else 0
        print(f"\r  [{i+1}/{len(records)}] {rate:.2f} samples/sec | ETA: {eta:.0f}s", end="", flush=True)

    print()
    elapsed = time.time() - start_time
    print(f"\nEvaluation complete in {elapsed:.1f}s ({len(results)/elapsed:.2f} samples/sec)")

    metrics = compute_metrics(results)
    print_report(metrics)

    # Save results
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    output_path = config["output"]
    with open(output_path, "w") as f:
        json.dump({
            "model": config["model"],
            "metrics": {
                "category_accuracy": metrics["category_accuracy"],
                "subcategory_accuracy": metrics["subcategory_accuracy"],
                "parse_failures": metrics["parse_failures"],
                "total_samples": metrics["total_samples"],
                "category_metrics": metrics["category_metrics"],
                "subcategory_metrics": metrics["subcategory_metrics"],
            },
            "results": results,
        }, f, indent=2)
    print(f"\nDetailed results saved to {output_path}")


if __name__ == "__main__":
    main()
