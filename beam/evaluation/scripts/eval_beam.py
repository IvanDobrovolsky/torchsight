#!/usr/bin/env python3
"""Evaluate torchsight/beam model against TorchSight-Eval-1000 dataset."""

import base64
import json
import os
import re
import sys
import time
import requests

OLLAMA_URL = os.environ.get("OLLAMA_URL", "http://localhost:11434")
MODEL = os.environ.get("BEAM_MODEL", "torchsight/beam:q4_K_M")
VISION_MODEL = os.environ.get("VISION_MODEL", "qwen3-vl:8b")
EVAL_DIR = os.path.join(os.path.dirname(__file__), "..", "data", "eval-1000-synthetic")
GROUND_TRUTH = os.path.join(EVAL_DIR, "ground-truth.json")

ALL_MODELS = [
    "torchsight/beam:q4_K_M",
    "torchsight/beam:q8_0",
    "torchsight/beam:f16",
    "torchsight/beam:v0-llama-8b",
]

IMAGE_EXTENSIONS = {".png", ".jpg", ".jpeg", ".gif", ".bmp", ".tiff", ".tif", ".webp"}

SYSTEM_PROMPT = """You are TorchSight, a cybersecurity document classifier. Analyze the provided text and identify ALL security-relevant findings.

For each finding, output a JSON object with:
- category: one of [pii, credentials, financial, medical, confidential, malicious, safe]
- subcategory: specific type (e.g., pii.identity, malicious.injection, credentials.api_key)
- severity: one of [critical, high, medium, low, info]
- explanation: detailed explanation including specific values found (redact sensitive parts, e.g., SSN: 412-XX-7890, API key: sk_live_51HG...). Explain what was found, why it matters, and the risk.

If a document contains multiple types of sensitive data, return a finding for EACH one.
If the text is clean/safe, output a single finding with category "safe".

Respond ONLY with a JSON array of findings."""

INSTRUCTION = "Analyze the following text for security threats, sensitive data, and policy violations."


def check_ollama(model_name: str):
    """Verify Ollama is running and the target model is available."""
    try:
        r = requests.get(f"{OLLAMA_URL}/api/tags", timeout=5)
        models = [m["name"] for m in r.json().get("models", [])]
        if not any(model_name in m or m in model_name for m in models):
            print(f"ERROR: {model_name} not found. Available: {models}")
            sys.exit(1)
        print(f"Model: {model_name}")
        return True
    except Exception as e:
        print(f"ERROR: Cannot connect to Ollama: {e}")
        sys.exit(1)


def query_beam(text: str, model_name: str) -> str:
    is_beam = "torchsight/beam" in model_name
    if is_beam:
        prompt = f"### Instruction:\n{INSTRUCTION}\n\n### Input:\n{text}\n\n### Response:\n"
        payload = {
            "model": model_name,
            "prompt": prompt,
            "system": SYSTEM_PROMPT,
            "stream": False,
            "options": {
                "num_predict": 2048,
                "temperature": 0,
                "top_p": 1.0,
                "stop": ["\n\n\n"],
            },
        }
        r = requests.post(f"{OLLAMA_URL}/api/generate", json=payload, timeout=600)
        r.raise_for_status()
        return r.json()["response"]
    payload = {
        "model": model_name,
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": f"{INSTRUCTION}\n\n{text}"},
        ],
        "think": False,
        "stream": False,
        "options": {
            "num_predict": 2048,
            "temperature": 0,
            "top_p": 1.0,
        },
    }
    r = requests.post(f"{OLLAMA_URL}/api/chat", json=payload, timeout=600)
    r.raise_for_status()
    return r.json()["message"]["content"]


def describe_image(image_path: str) -> str:
    """Use the vision model to describe an image, returning the text description."""
    with open(image_path, "rb") as f:
        image_b64 = base64.b64encode(f.read()).decode("utf-8")

    prompt = (
        "Describe everything visible in this image in detail. "
        "Include all text, numbers, labels, UI elements, and any sensitive information you can see. "
        "Be thorough and exact with any text content."
    )
    payload = {
        "model": VISION_MODEL,
        "prompt": prompt,
        "images": [image_b64],
        "stream": False,
        "options": {
            "num_predict": 2048,
        },
    }
    r = requests.post(f"{OLLAMA_URL}/api/generate", json=payload, timeout=600)
    r.raise_for_status()
    return r.json()["response"]


KNOWN_CATEGORIES = {"pii", "credentials", "financial", "medical", "confidential", "malicious", "safe"}


def resolve_category(category: str, subcategory: str) -> str:
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


def parse_beam_response(response: str) -> list[dict]:
    """Parse beam output — extract JSON arrays, deduplicate, fix category mismatches.
    Handles truncated JSON from token limit."""
    findings = []
    seen = set()

    def process_parsed(parsed):
        for f in parsed:
            if not isinstance(f, dict) or "category" not in f:
                continue
            subcat = f.get("subcategory", "")
            cat = resolve_category(f.get("category", ""), subcat)
            f["category"] = cat
            key = f"{cat}:{subcat}"
            if key in seen:
                continue
            seen.add(key)
            findings.append(f)

    # Find all complete [...] blocks
    for match in re.finditer(r'\[.*?\]', response, re.DOTALL):
        try:
            parsed = json.loads(match.group())
            if isinstance(parsed, list):
                process_parsed(parsed)
        except json.JSONDecodeError:
            continue

    # If nothing found, try to repair truncated JSON
    if not findings:
        bracket_pos = response.find('[')
        if bracket_pos >= 0:
            repaired = try_repair_json_array(response[bracket_pos:])
            if repaired:
                try:
                    parsed = json.loads(repaired)
                    if isinstance(parsed, list):
                        process_parsed(parsed)
                except json.JSONDecodeError:
                    pass

    return findings


def get_primary_category(findings: list[dict]) -> str:
    """Determine the primary category from beam findings (matching Rust logic).

    If any non-safe finding exists, the primary category is the most severe non-safe one.
    Otherwise it's 'safe'.
    """
    non_safe = [f for f in findings if f.get("category", "") != "safe"]
    if not non_safe:
        return "safe"

    severity_rank = {"critical": 0, "high": 1, "medium": 2, "warning": 2, "low": 3, "info": 4}
    non_safe.sort(key=lambda f: severity_rank.get(f.get("severity", "info"), 4))
    return non_safe[0].get("category", "unknown")


def get_primary_subcategory(findings: list[dict]) -> str:
    """Get subcategory of the most severe non-safe finding."""
    non_safe = [f for f in findings if f.get("category", "") != "safe"]
    if not non_safe:
        return "safe"
    severity_rank = {"critical": 0, "high": 1, "medium": 2, "warning": 2, "low": 3, "info": 4}
    non_safe.sort(key=lambda f: severity_rank.get(f.get("severity", "info"), 4))
    return non_safe[0].get("subcategory", "")


def category_match(predicted: str, expected: str) -> bool:
    """Check if predicted category matches expected (top-level)."""
    return predicted.lower().strip() == expected.lower().strip()


def subcategory_match(predicted: str, expected: str) -> bool:
    """Check subcategory match."""
    return predicted.lower().strip() == expected.lower().strip()


def run_eval(model_name: str) -> dict:
    """Run evaluation for a single model and return the results dict."""
    check_ollama(model_name)

    # Load ground truth — skip images (beam is text-only, commercial models handle images)
    with open(GROUND_TRUTH) as f:
        all_samples = json.load(f)

    start_id = int(os.environ.get("START_ID", "1"))
    samples = [s for s in all_samples
               if s["id"] >= start_id
               and not s["file"].startswith("images/")]
    print(f"\nEvaluating {len(samples)} text samples (starting from ID {start_id}, skipping images)\n")
    print("=" * 90)

    results = []
    bucket_stats = {}
    category_stats = {}

    for i, sample in enumerate(samples):
        sample_path = os.path.join(EVAL_DIR, sample["file"])
        if not os.path.exists(sample_path):
            print(f"  SKIP [{sample['id']:3d}] {sample['file']} — file not found")
            continue

        _, ext = os.path.splitext(sample["file"])
        is_image = ext.lower() in IMAGE_EXTENSIONS

        print(f"  [{sample['id']:3d}] {sample['file']:<55s}", end="", flush=True)
        start = time.time()

        try:
            if is_image:
                # For images: get vision description, then pass to beam as text
                vision_desc = describe_image(sample_path)
                content = f"[Image description from vision model]\n{vision_desc}"
            else:
                with open(sample_path, "r", errors="replace") as f:
                    content = f.read()
                # Truncate to 6000 chars like Rust code
                content = content[:6000]

            response = query_beam(content, model_name)
            elapsed = time.time() - start
            findings = parse_beam_response(response)
            pred_cat = get_primary_category(findings)
            pred_subcat = get_primary_subcategory(findings)
            expected_cat = sample["category"]
            expected_subcat = sample["subcategory"]

            alt_cat = sample.get("alt_category", "")
            alt_subcat = sample.get("alt_subcategory", "")
            cat_ok = category_match(pred_cat, expected_cat) or (bool(alt_cat) and category_match(pred_cat, alt_cat))
            subcat_ok = subcategory_match(pred_subcat, expected_subcat) or (bool(alt_subcat) and subcategory_match(pred_subcat, alt_subcat))

            status = "OK" if cat_ok else "MISS"
            sub_status = "ok" if subcat_ok else "miss"
            img_tag = " [IMG]" if is_image else ""

            print(f" {elapsed:5.1f}s  cat={pred_cat:<14s} [{status:4s}]  sub={pred_subcat:<30s} [{sub_status}]{img_tag}")

            result = {
                "id": sample["id"],
                "file": sample["file"],
                "bucket": sample["bucket"],
                "expected_cat": expected_cat,
                "expected_subcat": expected_subcat,
                "predicted_cat": pred_cat,
                "predicted_subcat": pred_subcat,
                "cat_correct": cat_ok,
                "subcat_correct": subcat_ok,
                "severity": sample["severity"],
                "elapsed": elapsed,
                "num_findings": len(findings),
                "raw_findings": findings,
                "is_image": is_image,
            }
            results.append(result)

            # Bucket stats
            b = sample["bucket"]
            if b not in bucket_stats:
                bucket_stats[b] = {"total": 0, "cat_correct": 0, "subcat_correct": 0}
            bucket_stats[b]["total"] += 1
            bucket_stats[b]["cat_correct"] += int(cat_ok)
            bucket_stats[b]["subcat_correct"] += int(subcat_ok)

            # Category stats
            ec = expected_cat
            if ec not in category_stats:
                category_stats[ec] = {"total": 0, "cat_correct": 0, "tp": 0, "fp": 0, "fn": 0}
            category_stats[ec]["total"] += 1
            category_stats[ec]["cat_correct"] += int(cat_ok)

        except Exception as e:
            elapsed = time.time() - start
            print(f" {elapsed:5.1f}s  ERROR: {e}")
            results.append({
                "id": sample["id"],
                "file": sample["file"],
                "bucket": sample["bucket"],
                "expected_cat": sample["category"],
                "predicted_cat": "error",
                "cat_correct": False,
                "subcat_correct": False,
                "error": str(e),
                "is_image": is_image,
            })

    # Compute confusion-style stats for precision/recall
    for r in results:
        if "error" in r:
            continue
        pred = r["predicted_cat"]
        exp = r["expected_cat"]
        # FP: predicted this category but it was something else
        if pred not in category_stats:
            category_stats[pred] = {"total": 0, "cat_correct": 0, "tp": 0, "fp": 0, "fn": 0}
        if exp not in category_stats:
            category_stats[exp] = {"total": 0, "cat_correct": 0, "tp": 0, "fp": 0, "fn": 0}
        if pred != exp:
            category_stats[pred]["fp"] += 1
            category_stats[exp]["fn"] += 1
        else:
            category_stats[exp]["tp"] += 1

    # Print results
    total = len(results)
    cat_correct = sum(1 for r in results if r.get("cat_correct"))
    subcat_correct = sum(1 for r in results if r.get("subcat_correct"))
    errors = sum(1 for r in results if "error" in r)
    times = [r["elapsed"] for r in results if "elapsed" in r]

    print("\n" + "=" * 90)
    print(f"\n{'OVERALL RESULTS':^90}")
    print("=" * 90)
    print(f"  Model:                {model_name}")
    print(f"  Samples evaluated:    {total}")
    print(f"  Errors:               {errors}")
    print(f"  Category accuracy:    {cat_correct}/{total} = {cat_correct/total*100:.1f}%")
    print(f"  Subcategory accuracy: {subcat_correct}/{total} = {subcat_correct/total*100:.1f}%")
    if times:
        print(f"  Avg time/sample:      {sum(times)/len(times):.1f}s")
        print(f"  Total time:           {sum(times):.0f}s ({sum(times)/60:.1f}m)")

    verdict = "EXCELLENT" if cat_correct/total >= 0.9 else "SUFFICIENT" if cat_correct/total >= 0.8 else "NEEDS RETRAINING"
    print(f"\n  VERDICT: {verdict}")

    print(f"\n{'ACCURACY BY BUCKET':^90}")
    print("-" * 90)
    print(f"  {'Bucket':<25s} {'Cat Acc':>10s} {'Subcat Acc':>12s} {'Samples':>10s}")
    print("-" * 90)
    for b in sorted(bucket_stats.keys()):
        s = bucket_stats[b]
        ca = s["cat_correct"] / s["total"] * 100
        sa = s["subcat_correct"] / s["total"] * 100
        print(f"  {b:<25s} {ca:>9.1f}% {sa:>11.1f}% {s['total']:>10d}")

    print(f"\n{'ACCURACY BY CATEGORY':^90}")
    print("-" * 90)
    print(f"  {'Category':<15s} {'Accuracy':>10s} {'Precision':>11s} {'Recall':>10s} {'F1':>8s} {'TP':>5s} {'FP':>5s} {'FN':>5s} {'N':>5s}")
    print("-" * 90)
    for c in sorted(category_stats.keys()):
        s = category_stats[c]
        acc = s["cat_correct"] / s["total"] * 100 if s["total"] > 0 else 0
        tp = s.get("tp", 0)
        fp = s.get("fp", 0)
        fn = s.get("fn", 0)
        precision = tp / (tp + fp) * 100 if (tp + fp) > 0 else 0
        recall = tp / (tp + fn) * 100 if (tp + fn) > 0 else 0
        f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0
        print(f"  {c:<15s} {acc:>9.1f}% {precision:>10.1f}% {recall:>9.1f}% {f1:>7.1f}% {tp:>5d} {fp:>5d} {fn:>5d} {s['total']:>5d}")

    # Misclassifications detail
    misses = [r for r in results if not r.get("cat_correct") and "error" not in r]
    if misses:
        print(f"\n{'MISCLASSIFICATIONS':^90}")
        print("-" * 90)
        for m in misses:
            print(f"  [{m['id']:3d}] {m['file']}")
            print(f"        Expected: {m['expected_cat']:<15s} ({m['expected_subcat']})")
            print(f"        Got:      {m['predicted_cat']:<15s} ({m.get('predicted_subcat', '?')})")
            print()

    # Save detailed results — canonical name matches existing eval1000_*.json layout
    if "torchsight/beam" in model_name:
        tag = "beam_" + model_name.split(":")[-1]
    else:
        tag = model_name.replace("/", "_").replace(":", "_").replace(".", "")
    results_dir = os.path.join(os.path.dirname(__file__), "..", "results")
    os.makedirs(results_dir, exist_ok=True)
    output_path = os.path.join(results_dir, f"eval1000_{tag}.json")
    result_dict = {
        "model": model_name,
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "total_samples": total,
        "category_accuracy": cat_correct / total if total > 0 else 0,
        "subcategory_accuracy": subcat_correct / total if total > 0 else 0,
        "bucket_stats": bucket_stats,
        "category_stats": {k: {kk: vv for kk, vv in v.items()} for k, v in category_stats.items()},
        "results": results,
    }
    with open(output_path, "w") as f:
        json.dump(result_dict, f, indent=2, default=str)
    print(f"\nDetailed results saved to: {output_path}")

    return result_dict


def main():
    if MODEL == "all":
        print("Running evaluation for ALL models sequentially...\n")
        all_results = {}
        for model_name in ALL_MODELS:
            print(f"\n{'#' * 90}")
            print(f"# MODEL: {model_name}")
            print(f"{'#' * 90}")
            result_dict = run_eval(model_name)
            all_results[model_name] = result_dict
        # Save combined summary
        summary_path = os.path.join(os.path.dirname(__file__), "eval1000_results_all.json")
        with open(summary_path, "w") as f:
            json.dump(all_results, f, indent=2, default=str)
        print(f"\nCombined results saved to: {summary_path}")
    else:
        run_eval(MODEL)


if __name__ == "__main__":
    main()
