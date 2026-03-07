#!/usr/bin/env python3
"""
TorchSight Model Evaluation

Evaluates a fine-tuned model (or LoRA adapter) against held-out validation
data and reports accuracy metrics per category and subcategory.

Requirements:
    pip install torch transformers peft datasets scikit-learn tabulate

Usage:
    # Evaluate LoRA adapter
    python eval_model.py --adapter ./output/torchsight-llama-lora

    # Evaluate merged model
    python eval_model.py --model ./output/torchsight-llama-lora-merged

    # Evaluate with custom validation data
    python eval_model.py --adapter ./output/torchsight-llama-lora --val-data ./data/sft/val_chatml.jsonl

    # Limit samples for quick check
    python eval_model.py --adapter ./output/torchsight-llama-lora --max-samples 200
"""

import json
import os
import re
import sys
import time
from collections import defaultdict
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
DATA_DIR = SCRIPT_DIR.parent / "data"
OUTPUT_DIR = SCRIPT_DIR.parent / "output"

CATEGORIES = ["pii", "credentials", "financial", "medical", "confidential", "malicious", "safe"]


def parse_args():
    config = {
        "adapter": None,
        "model": None,
        "val_data": str(DATA_DIR / "sft" / "val_chatml.jsonl"),
        "max_samples": 0,  # 0 = all
        "batch_size": 1,
        "max_new_tokens": 1024,
        "quantize": None,
        "output": None,  # Save detailed results to file
    }
    args = sys.argv[1:]
    i = 0
    while i < len(args):
        key = args[i].lstrip("-").replace("-", "_")
        if i + 1 < len(args) and not args[i + 1].startswith("--"):
            val = args[i + 1]
            if key in ("max_samples", "batch_size", "max_new_tokens"):
                val = int(val)
            config[key] = val
            i += 2
        else:
            config[key] = True
            i += 1
    return config


def load_val_data(path: str, max_samples: int) -> list[dict]:
    """Load validation data in ChatML format."""
    records = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            record = json.loads(line)
            records.append(record)
            if max_samples and len(records) >= max_samples:
                break
    return records


def extract_expected(record: dict) -> tuple[str, list[dict]]:
    """Extract input text and expected findings from a ChatML record."""
    messages = record["messages"]
    user_msg = next(m["content"] for m in messages if m["role"] == "user")
    assistant_msg = next(m["content"] for m in messages if m["role"] == "assistant")

    try:
        expected = json.loads(assistant_msg)
    except json.JSONDecodeError:
        expected = []

    return user_msg, expected


def parse_model_output(text: str) -> list[dict]:
    """Parse model output JSON, handling common LLM formatting quirks."""
    text = text.strip()

    # Try direct parse
    try:
        result = json.loads(text)
        if isinstance(result, list):
            return result
        if isinstance(result, dict):
            return [result]
    except json.JSONDecodeError:
        pass

    # Try extracting JSON array from markdown code block
    match = re.search(r'```(?:json)?\s*(\[.*?\])\s*```', text, re.DOTALL)
    if match:
        try:
            return json.loads(match.group(1))
        except json.JSONDecodeError:
            pass

    # Try finding first [ ... ] in the text
    match = re.search(r'\[.*\]', text, re.DOTALL)
    if match:
        try:
            return json.loads(match.group(0))
        except json.JSONDecodeError:
            pass

    return []


def compute_metrics(results: list[dict]) -> dict:
    """Compute accuracy metrics from evaluation results."""
    # Top-level category accuracy
    cat_correct = 0
    cat_total = 0
    subcat_correct = 0
    subcat_total = 0

    # Per-category stats
    per_category = defaultdict(lambda: {"tp": 0, "fp": 0, "fn": 0})
    per_subcategory = defaultdict(lambda: {"tp": 0, "fp": 0, "fn": 0})

    # Parse failures
    parse_failures = 0
    empty_predictions = 0

    for r in results:
        expected = r["expected"]
        predicted = r["predicted"]

        if r.get("parse_error"):
            parse_failures += 1
            continue

        if not predicted:
            empty_predictions += 1

        # Get sets of categories and subcategories
        expected_cats = set(f["category"] for f in expected if "category" in f)
        predicted_cats = set(f["category"] for f in predicted if "category" in f)
        expected_subcats = set(f["subcategory"] for f in expected if "subcategory" in f)
        predicted_subcats = set(f["subcategory"] for f in predicted if "subcategory" in f)

        # Category-level
        for cat in expected_cats | predicted_cats:
            if cat in expected_cats and cat in predicted_cats:
                per_category[cat]["tp"] += 1
                cat_correct += 1
            elif cat in predicted_cats:
                per_category[cat]["fp"] += 1
            else:
                per_category[cat]["fn"] += 1
            cat_total += 1

        # Subcategory-level
        for subcat in expected_subcats | predicted_subcats:
            cat = subcat.split(".")[0] if "." in subcat else subcat
            if subcat in expected_subcats and subcat in predicted_subcats:
                per_subcategory[subcat]["tp"] += 1
                subcat_correct += 1
            elif subcat in predicted_subcats:
                per_subcategory[subcat]["fp"] += 1
            else:
                per_subcategory[subcat]["fn"] += 1
            subcat_total += 1

    # Compute precision/recall/f1 per category
    category_metrics = {}
    for cat in sorted(per_category.keys()):
        stats = per_category[cat]
        precision = stats["tp"] / (stats["tp"] + stats["fp"]) if (stats["tp"] + stats["fp"]) > 0 else 0
        recall = stats["tp"] / (stats["tp"] + stats["fn"]) if (stats["tp"] + stats["fn"]) > 0 else 0
        f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0
        category_metrics[cat] = {
            "precision": precision,
            "recall": recall,
            "f1": f1,
            "support": stats["tp"] + stats["fn"],
        }

    subcategory_metrics = {}
    for subcat in sorted(per_subcategory.keys()):
        stats = per_subcategory[subcat]
        precision = stats["tp"] / (stats["tp"] + stats["fp"]) if (stats["tp"] + stats["fp"]) > 0 else 0
        recall = stats["tp"] / (stats["tp"] + stats["fn"]) if (stats["tp"] + stats["fn"]) > 0 else 0
        f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0
        subcategory_metrics[subcat] = {
            "precision": precision,
            "recall": recall,
            "f1": f1,
            "support": stats["tp"] + stats["fn"],
        }

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
    """Print a formatted evaluation report."""
    print(f"\n{'=' * 70}")
    print("  TorchSight Sentinel — Evaluation Report")
    print(f"{'=' * 70}")

    print(f"\n  Total samples evaluated:  {metrics['total_samples']}")
    print(f"  Parse failures:           {metrics['parse_failures']}")
    print(f"  Empty predictions:        {metrics['empty_predictions']}")
    print(f"\n  Category accuracy:        {metrics['category_accuracy']:.1%}")
    print(f"  Subcategory accuracy:     {metrics['subcategory_accuracy']:.1%}")

    # Category breakdown
    print(f"\n{'─' * 70}")
    print(f"  {'Category':<20} {'Precision':>10} {'Recall':>10} {'F1':>10} {'Support':>10}")
    print(f"{'─' * 70}")

    cat_metrics = metrics["category_metrics"]
    for cat in CATEGORIES:
        if cat in cat_metrics:
            m = cat_metrics[cat]
            print(f"  {cat:<20} {m['precision']:>10.1%} {m['recall']:>10.1%} {m['f1']:>10.1%} {m['support']:>10}")

    # Macro averages
    if cat_metrics:
        avg_p = sum(m["precision"] for m in cat_metrics.values()) / len(cat_metrics)
        avg_r = sum(m["recall"] for m in cat_metrics.values()) / len(cat_metrics)
        avg_f1 = sum(m["f1"] for m in cat_metrics.values()) / len(cat_metrics)
        total_support = sum(m["support"] for m in cat_metrics.values())
        print(f"{'─' * 70}")
        print(f"  {'MACRO AVG':<20} {avg_p:>10.1%} {avg_r:>10.1%} {avg_f1:>10.1%} {total_support:>10}")

    # Subcategory breakdown (top 20 by support)
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

    # Worst performing subcategories
    if subcat_metrics:
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

    if not config["adapter"] and not config["model"]:
        print("Usage:")
        print("  python eval_model.py --adapter ./output/torchsight-llama-lora")
        print("  python eval_model.py --model ./output/torchsight-llama-lora-merged")
        sys.exit(1)

    val_path = Path(config["val_data"])
    if not val_path.exists():
        print(f"ERROR: Validation data not found at {val_path}")
        print("Run sft_converter.py first to generate validation data.")
        sys.exit(1)

    # Load validation data
    print(f"Loading validation data from {val_path}...")
    val_records = load_val_data(str(val_path), config["max_samples"])
    print(f"  Loaded {len(val_records)} samples")

    # Import heavy deps
    print("\nLoading libraries...")
    try:
        import torch
        from transformers import AutoModelForCausalLM, AutoTokenizer, BitsAndBytesConfig
        from peft import PeftModel
    except ImportError as e:
        print(f"Missing dependency: {e}")
        print("pip install torch transformers peft")
        sys.exit(1)

    # Load model
    if config["adapter"]:
        adapter_path = Path(config["adapter"])
        # Read training config for base model name
        training_config_path = adapter_path / "training_config.json"
        if training_config_path.exists():
            with open(training_config_path) as f:
                training_config = json.load(f)
            base_model = training_config.get("base_model", "meta-llama/Llama-3.1-8B-Instruct")
        else:
            base_model = "meta-llama/Llama-3.1-8B-Instruct"

        print(f"Loading base model: {base_model}")
        model_kwargs = {
            "trust_remote_code": True,
            "torch_dtype": torch.bfloat16,
            "device_map": "auto",
        }
        if config["quantize"] == "4bit":
            model_kwargs["quantization_config"] = BitsAndBytesConfig(
                load_in_4bit=True,
                bnb_4bit_quant_type="nf4",
                bnb_4bit_compute_dtype=torch.bfloat16,
            )

        model = AutoModelForCausalLM.from_pretrained(base_model, **model_kwargs)
        tokenizer = AutoTokenizer.from_pretrained(base_model, trust_remote_code=True)

        print(f"Loading LoRA adapter: {adapter_path}")
        model = PeftModel.from_pretrained(model, str(adapter_path))
        model.eval()
    else:
        model_path = config["model"]
        print(f"Loading merged model: {model_path}")
        model = AutoModelForCausalLM.from_pretrained(
            model_path,
            trust_remote_code=True,
            torch_dtype=torch.bfloat16,
            device_map="auto",
        )
        tokenizer = AutoTokenizer.from_pretrained(model_path, trust_remote_code=True)
        model.eval()

    if tokenizer.pad_token is None:
        tokenizer.pad_token = tokenizer.eos_token

    # Run evaluation
    print(f"\nEvaluating {len(val_records)} samples...")
    results = []
    start_time = time.time()

    for i, record in enumerate(val_records):
        user_msg, expected = extract_expected(record)

        # Build prompt (system + user only, no assistant)
        messages = [m for m in record["messages"] if m["role"] != "assistant"]
        prompt = tokenizer.apply_chat_template(messages, tokenize=False, add_generation_prompt=True)

        inputs = tokenizer(prompt, return_tensors="pt", truncation=True, max_length=4096)
        inputs = {k: v.to(model.device) for k, v in inputs.items()}

        with torch.no_grad():
            outputs = model.generate(
                **inputs,
                max_new_tokens=config["max_new_tokens"],
                temperature=0.1,
                top_p=0.9,
                do_sample=True,
                pad_token_id=tokenizer.pad_token_id,
            )

        # Decode only the generated part
        generated = outputs[0][inputs["input_ids"].shape[1]:]
        response = tokenizer.decode(generated, skip_special_tokens=True)

        # Parse
        predicted = parse_model_output(response)
        parse_error = len(predicted) == 0 and len(expected) > 0

        results.append({
            "expected": expected,
            "predicted": predicted,
            "parse_error": parse_error,
            "raw_output": response[:500],
        })

        # Progress
        elapsed = time.time() - start_time
        rate = (i + 1) / elapsed if elapsed > 0 else 0
        eta = (len(val_records) - i - 1) / rate if rate > 0 else 0
        print(f"\r  [{i+1}/{len(val_records)}] {rate:.1f} samples/sec | ETA: {eta:.0f}s", end="", flush=True)

    print()
    elapsed = time.time() - start_time
    print(f"\nEvaluation complete in {elapsed:.1f}s ({len(results)/elapsed:.1f} samples/sec)")

    # Compute and display metrics
    metrics = compute_metrics(results)
    print_report(metrics)

    # Save detailed results if requested
    output_path = config.get("output")
    if not output_path:
        output_path = str(OUTPUT_DIR / "eval_results.json")

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w") as f:
        json.dump({
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
