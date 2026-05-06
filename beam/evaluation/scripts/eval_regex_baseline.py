#!/usr/bin/env python3
"""
Regex-only baseline evaluation on TorchSight-Eval-1000 and eval-500-external.

Runs TorchSight's 48 regex patterns (NO LLM) against the benchmarks to show
what rule-based detection achieves. This represents the best-case scenario for
tools like TruffleHog, detect-secrets, and Semgrep on document classification.

Usage:
  python eval_regex_baseline.py              # runs both benchmarks
  python eval_regex_baseline.py eval-1000-synthetic    # primary benchmark only
  python eval_regex_baseline.py eval-500-external # external validation only
"""

import json
import os
import re
import sys
import time

SCRIPT_DIR = os.path.dirname(__file__)
EVAL1000_DIR = os.path.join(SCRIPT_DIR, "..", "data", "eval-1000-synthetic")
EVAL1000_GT = os.path.join(EVAL1000_DIR, "ground-truth.json")
EVAL_EXT_GT = os.path.join(SCRIPT_DIR, "..", "data", "eval-500-external", "ground-truth.json")
RESULTS_DIR = os.path.join(SCRIPT_DIR, "..", "results")

# ============================================================
# All 48 regex patterns from TorchSight core/src/analyzers/text.rs
# Ported directly from Rust to Python
# ============================================================

PATTERNS = [
    # A. SSTI (8 patterns)
    (r"\{\{[^}]*__class__", "malicious", "malicious.injection"),
    (r"\{\{[^}]*__mro__", "malicious", "malicious.injection"),
    (r"\{\{[^}]*__subclasses__", "malicious", "malicious.injection"),
    (r"\{\{[^}]*config\s*\.", "malicious", "malicious.injection"),
    (r"\{\{[^}]*request\s*\.", "malicious", "malicious.injection"),
    (r"\$\{[^}]*Runtime\s*\.", "malicious", "malicious.injection"),
    (r"\$\{[^}]*getRuntime", "malicious", "malicious.injection"),
    (r"#set\s*\(\s*\$[^)]*class\s*\.", "malicious", "malicious.injection"),

    # B. XXE (3 patterns)
    (r"(?s)<!DOCTYPE[^>]*\[.*<!ENTITY", "malicious", "malicious.injection"),
    (r'<!ENTITY[^>]*SYSTEM\s*["\']', "malicious", "malicious.injection"),
    (r'<!ENTITY[^>]*PUBLIC\s*["\']', "malicious", "malicious.injection"),

    # C. Deserialization (7 patterns — yaml.load handled separately below)
    (r"pickle\.loads\s*\(", "malicious", "malicious.exploit"),
    (r"ObjectInputStream", "malicious", "malicious.exploit"),
    (r"unserialize\s*\(", "malicious", "malicious.exploit"),
    (r"Marshal\.load\s*\(", "malicious", "malicious.exploit"),
    (r"BinaryFormatter\.Deserialize", "malicious", "malicious.exploit"),

    # D. Shell / RCE (5 patterns)
    (r"\beval\s*\(\s*atob\b", "malicious", "malicious.shell"),
    (r"\bexec\s*\(\s*compile\b", "malicious", "malicious.shell"),
    (r"\b__import__\s*\(\s*['\"]os['\"]\s*\)", "malicious", "malicious.shell"),
    (r"\b(nc|ncat|netcat)\s+.*-e\s+/bin/(sh|bash)", "malicious", "malicious.shell"),
    (r"/dev/tcp/", "malicious", "malicious.shell"),

    # E. SSRF (3 patterns)
    (r"169\.254\.169\.254", "malicious", "malicious.ssrf"),
    (r"metadata\.google\.internal", "malicious", "malicious.ssrf"),
    (r"100\.100\.100\.200", "malicious", "malicious.ssrf"),

    # F. Supply chain (3 patterns)
    (r'"(preinstall|postinstall|preuninstall)":\s*"[^"]*curl\s', "malicious", "malicious.exploit"),
    (r'"(preinstall|postinstall)":\s*"[^"]*wget\s', "malicious", "malicious.exploit"),
    (r"(?s)cmdclass.*install.*os\.system", "malicious", "malicious.exploit"),

    # G. Prompt injection (3 patterns)
    (r"(?i)ignore\s+(all\s+)?previous\s+instructions", "malicious", "malicious.prompt_injection"),
    (r"(?i)you\s+are\s+now\s+(DAN|an?\s+unrestricted)", "malicious", "malicious.prompt_injection"),
    (r"(?i)system:\s*override", "malicious", "malicious.prompt_injection"),

    # H. PII (3 patterns)
    (r"\b\d{3}-\d{2}-\d{4}\b", "pii", "pii.identity"),
    (r"(?i)(\*{3}-\*{2}-\d{4}|XXX-XX-\d{4}|xxx-xx-\d{4}|\*{5,}\d{4})", "pii", "pii.identity"),
    (r"(?i)\b(DOB|date\s+of\s+birth|birth\s*date)\s*[:=]\s*\d{1,2}[/\-]\d{1,2}[/\-]\d{2,4}", "pii", "pii.identity"),

    # I. Financial (5 patterns)
    (r"\b4\d{3}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b", "financial", "financial.credit_card"),
    (r"\b5[1-5]\d{2}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b", "financial", "financial.credit_card"),
    (r"\b3[47]\d{2}[\s-]?\d{6}[\s-]?\d{5}\b", "financial", "financial.credit_card"),
    (r"\*{4,}\d{4}", "financial", "financial.bank_account"),
    (r"\b[A-Z]{2}\d{2}[A-Z0-9]{4}\d{7}([A-Z0-9]?\d{0,16})\b", "financial", "financial.bank_account"),

    # J. Credentials (6 patterns)
    (r"\bAKIA[A-Z0-9]{16}\b", "credentials", "credentials.api_key"),
    (r"\b(sk|pk)_(live|test)_[a-zA-Z0-9]{20,}", "credentials", "credentials.api_key"),
    (r"\b(ghp|gho|ghu|ghs|ghr)_[a-zA-Z0-9]{36,}\b", "credentials", "credentials.token"),
    (r"-----BEGIN\s+(RSA|EC|DSA|OPENSSH|PGP)\s+PRIVATE\s+KEY-----", "credentials", "credentials.private_key"),
    (r'(?i)(password|passwd|pwd|secret|token)\s*[:=]\s*["\']?[^\s"\']{8,}', "credentials", "credentials.password"),
    (r"(?i)(mongodb|postgres|mysql|redis|amqp)://[^\s]+@[^\s]+", "credentials", "credentials.connection_string"),

    # K. Financial identifiers (4 patterns)
    (r"\b\d{2}-\d{7}\b", "pii", "pii.identity"),  # EIN
    (r"(?i)(routing|aba|transit)\s*#?\s*:?\s*\d{9}\b", "financial", "financial.bank_account"),
    (r"(?i)(loan|account|acct|policy)\s*(number|num|no|#)\s*:?\s*\d{6,15}", "financial", "financial.bank_account"),
    (r"(?i)check\s*(number|num|no|#)\s*:?\s*\d{4,10}", "financial", "financial.transaction"),
]

# Special: yaml.load without SafeLoader (mirrors Rust logic)
RE_YAML_UNSAFE = re.compile(r"yaml\.load\s*\([^)]*\)")
RE_YAML_SAFE = re.compile(r"Loader\s*=\s*SafeLoader")

# Compile all patterns
COMPILED = [(re.compile(p), cat, subcat) for p, cat, subcat in PATTERNS]


def classify_with_regex(text):
    """Run all 48 regex patterns against text. Return highest-priority category found."""
    found_categories = set()
    found_subcategories = set()

    for pattern, cat, subcat in COMPILED:
        if pattern.search(text):
            found_categories.add(cat)
            found_subcategories.add(subcat)

    # Special yaml.load handling: only flag if SafeLoader not nearby
    for m in RE_YAML_UNSAFE.finditer(text):
        vicinity = text[m.start():min(m.start() + m.end() - m.start() + 100, len(text))]
        if not RE_YAML_SAFE.search(vicinity):
            found_categories.add("malicious")
            found_subcategories.add("malicious.exploit")

    if not found_categories:
        return "safe", ""

    # Priority: malicious > credentials > pii > financial > medical > confidential > safe
    priority = ["malicious", "credentials", "pii", "financial", "medical", "confidential"]
    for p in priority:
        if p in found_categories:
            subcats = [s for _, c, s in PATTERNS if c == p and s in found_subcategories]
            return p, subcats[0] if subcats else ""

    return "safe", ""


def run_eval1000():
    """Run regex baseline on TorchSight-Eval-1000."""
    with open(EVAL1000_GT) as f:
        samples = json.load(f)

    text_samples = [s for s in samples if not s["file"].startswith("images/")]

    print(f"\n{'='*80}")
    print(f"EVAL-1000: Regex-only baseline on {len(text_samples)} text samples (48 patterns)")
    print(f"{'='*80}")

    results = []
    start_all = time.time()

    for sample in text_samples:
        sample_path = os.path.join(EVAL1000_DIR, sample["file"])
        if not os.path.exists(sample_path):
            continue

        with open(sample_path, "r", errors="replace") as f:
            content = f.read()[:6000]

        pred_cat, pred_subcat = classify_with_regex(content)
        expected_cat = sample["category"]
        alt_cat = sample.get("alt_category", "")
        cat_ok = pred_cat == expected_cat or (alt_cat and pred_cat == alt_cat)

        results.append({
            "id": sample["id"],
            "file": sample["file"],
            "expected_cat": expected_cat,
            "predicted_cat": pred_cat,
            "predicted_subcat": pred_subcat,
            "cat_correct": cat_ok,
        })

    elapsed = time.time() - start_all
    print_results(results, elapsed)

    os.makedirs(RESULTS_DIR, exist_ok=True)
    output_path = os.path.join(RESULTS_DIR, "eval1000_regex_only.json")
    with open(output_path, "w") as f:
        json.dump({
            "method": "regex_only",
            "patterns": len(PATTERNS) + 1,  # +1 for yaml special case
            "total_samples": len(results),
            "category_accuracy": sum(1 for r in results if r["cat_correct"]) / len(results),
            "time_seconds": elapsed,
            "results": results,
        }, f, indent=2)
    print(f"\nResults saved to: {output_path}")


def run_eval_external():
    """Run regex baseline on eval-500-external (500 held-out samples)."""
    with open(EVAL_EXT_GT) as f:
        samples = json.load(f)

    print(f"\n{'='*80}")
    print(f"EVAL-EXTERNAL: Regex-only baseline on {len(samples)} held-out samples (48 patterns)")
    print(f"{'='*80}")

    eval_ext_dir = os.path.join(SCRIPT_DIR, "..", "data", "eval-500-external")
    results = []
    start_all = time.time()

    for sample in samples:
        # External dataset has text inline OR in files
        if "text" in sample and sample["text"]:
            content = sample["text"][:6000]
        else:
            sample_path = os.path.join(eval_ext_dir, sample["file"])
            if not os.path.exists(sample_path):
                continue
            with open(sample_path, "r", errors="replace") as f:
                content = f.read()[:6000]

        pred_cat, pred_subcat = classify_with_regex(content)
        expected_cat = sample["category"]
        alt_cat = sample.get("alt_category", "")
        cat_ok = pred_cat == expected_cat or (alt_cat and pred_cat == alt_cat)

        results.append({
            "id": sample["id"],
            "file": sample["file"],
            "source": sample.get("source", ""),
            "expected_cat": expected_cat,
            "predicted_cat": pred_cat,
            "predicted_subcat": pred_subcat,
            "cat_correct": cat_ok,
        })

    elapsed = time.time() - start_all
    print_results(results, elapsed)

    # Per-source breakdown
    source_stats = {}
    for r in results:
        src = r.get("source", "unknown")
        if src not in source_stats:
            source_stats[src] = {"total": 0, "correct": 0}
        source_stats[src]["total"] += 1
        if r["cat_correct"]:
            source_stats[src]["correct"] += 1

    print(f"\n{'ACCURACY BY SOURCE':^80}")
    print("-" * 80)
    for src in sorted(source_stats):
        s = source_stats[src]
        acc = s["correct"] / s["total"] * 100
        print(f"  {src:<25s} {s['correct']:>4d}/{s['total']:<4d} = {acc:.1f}%")

    os.makedirs(RESULTS_DIR, exist_ok=True)
    output_path = os.path.join(RESULTS_DIR, "eval_external_regex_only.json")
    with open(output_path, "w") as f:
        json.dump({
            "method": "regex_only",
            "patterns": len(PATTERNS) + 1,
            "total_samples": len(results),
            "category_accuracy": sum(1 for r in results if r["cat_correct"]) / len(results),
            "time_seconds": elapsed,
            "results": results,
        }, f, indent=2)
    print(f"\nResults saved to: {output_path}")


def print_results(results, elapsed):
    """Print accuracy summary."""
    total = len(results)
    correct = sum(1 for r in results if r["cat_correct"])

    print(f"\nRegex-only (48 patterns): {correct}/{total} = {correct/total*100:.1f}%")
    print(f"Time: {elapsed:.2f}s ({elapsed/total*1000:.2f}ms per sample)")

    # Per-category
    cat_stats = {}
    for r in results:
        ec = r["expected_cat"]
        if ec not in cat_stats:
            cat_stats[ec] = {"total": 0, "correct": 0}
        cat_stats[ec]["total"] += 1
        if r["cat_correct"]:
            cat_stats[ec]["correct"] += 1

    print(f"\n{'ACCURACY BY CATEGORY':^80}")
    print("-" * 80)
    for cat in sorted(cat_stats):
        s = cat_stats[cat]
        acc = s["correct"] / s["total"] * 100
        print(f"  {cat:<15s} {s['correct']:>4d}/{s['total']:<4d} = {acc:.1f}%")

    detected = sum(1 for r in results if r["predicted_cat"] != "safe")
    missed = sum(1 for r in results if r["predicted_cat"] == "safe" and r["expected_cat"] != "safe")
    false_pos = sum(1 for r in results if r["predicted_cat"] != "safe" and r["expected_cat"] == "safe")

    print(f"\n  Documents flagged:      {detected}/{total}")
    print(f"  Missed (false neg):     {missed}")
    print(f"  False positives:        {false_pos}")


def main():
    target = sys.argv[1] if len(sys.argv) > 1 else "both"

    if target in ("eval-1000-synthetic", "both"):
        run_eval1000()
    if target in ("eval-500-external", "both"):
        run_eval_external()


if __name__ == "__main__":
    main()
