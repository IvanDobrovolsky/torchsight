#!/usr/bin/env python3
"""Shared methodology for the Eval-500 external benchmark.

Every `eval_external_*.py` script differs only in how it talks to its provider
API. The system prompt, response parser, severity ranking, alt-aware scorer,
and result-snapshot format all live here so that the three commercial-model
runs (Claude, GPT-5, Gemini) and any future addition use the *same* parsing
and scoring logic. This is what lets the paper claim a methodology-symmetric
comparison.

Usage from a provider-specific driver:

    from external_eval_lib import SYSTEM_PROMPT, INSTRUCTION, run_benchmark

    def query(text: str) -> str:
        ...  # provider-specific HTTP call, return the raw text response

    if __name__ == "__main__":
        run_benchmark(
            query_fn=query,
            model_label="claude-sonnet-4-20250514",
            output_filename="eval_external_claude-sonnet-4-20250514.json",
        )
"""

import json
import os
import re
import sys
import time
from typing import Callable, Optional


SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
EVAL_DIR = os.path.join(SCRIPT_DIR, "..", "data", "eval-500-external")
GROUND_TRUTH = os.path.join(EVAL_DIR, "ground-truth.json")
RESULTS_DIR = os.path.join(SCRIPT_DIR, "..", "results")

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

SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def parse_response(response: Optional[str]) -> list[dict]:
    """Extract findings from a model response, tolerating malformed output.

    First tries every well-formed `[...]` block found by a non-greedy regex.
    If none parse, falls back to a brace-balancing repair over the truncated
    JSON suffix (handles cases where the response was cut off mid-object).
    Deduplicates findings by (category, subcategory).
    """
    findings: list[dict] = []
    seen: set[str] = set()

    def absorb(parsed: list) -> None:
        for finding in parsed:
            if not isinstance(finding, dict) or "category" not in finding:
                continue
            category = finding.get("category", "").lower().strip()
            key = f"{category}:{finding.get('subcategory', '')}"
            if key in seen:
                continue
            seen.add(key)
            finding["category"] = category
            findings.append(finding)

    for match in re.finditer(r"\[.*?\]", response or "", re.DOTALL):
        try:
            parsed = json.loads(match.group())
        except json.JSONDecodeError:
            continue
        if isinstance(parsed, list):
            absorb(parsed)

    if findings or not response:
        return findings

    bracket_pos = response.find("[")
    if bracket_pos < 0:
        return findings

    depth = 0
    last_complete_obj = None
    in_string = False
    escape_next = False
    for i, ch in enumerate(response[bracket_pos:]):
        if escape_next:
            escape_next = False
            continue
        if ch == "\\" and in_string:
            escape_next = True
            continue
        if ch == '"':
            in_string = not in_string
            continue
        if in_string:
            continue
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                last_complete_obj = i

    if last_complete_obj is None:
        return findings

    repaired = response[bracket_pos : bracket_pos + last_complete_obj + 1] + "]"
    try:
        parsed = json.loads(repaired)
    except json.JSONDecodeError:
        return findings
    if isinstance(parsed, list):
        absorb(parsed)
    return findings


def get_primary_category(findings: list[dict]) -> str:
    """Pick the most severe non-safe category, or 'safe' if none found."""
    non_safe = [f for f in findings if f.get("category", "") != "safe"]
    if not non_safe:
        return "safe"
    non_safe.sort(key=lambda f: SEVERITY_RANK.get(f.get("severity", "info"), 4))
    return non_safe[0].get("category", "unknown")


def score(predicted: str, expected: str, alt: str) -> bool:
    """alt-aware scoring: either the expected or the alternate label counts."""
    return predicted == expected or (bool(alt) and predicted == alt)


def _write_snapshot(output_path: str, model_label: str, results: list[dict]) -> None:
    total = len(results)
    correct = sum(1 for r in results if r.get("cat_correct"))
    snapshot = {
        "model": model_label,
        "benchmark": "external-500",
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "total_samples": total,
        "category_accuracy": correct / total if total else 0,
        "results": results,
    }
    with open(output_path, "w") as fp:
        json.dump(snapshot, fp, indent=2)


def _print_per_source(results: list[dict]) -> None:
    per_source: dict[str, dict] = {}
    for r in results:
        bucket = per_source.setdefault(r.get("source", "?"), {"total": 0, "correct": 0})
        bucket["total"] += 1
        if r.get("cat_correct"):
            bucket["correct"] += 1
    for source in sorted(per_source):
        bucket = per_source[source]
        accuracy = bucket["correct"] / bucket["total"] * 100
        print(f"  {source:<25s} {bucket['correct']:>3d}/{bucket['total']:<3d} = {accuracy:.1f}%")


def run_benchmark(
    query_fn: Callable[[str], str],
    model_label: str,
    output_filename: str,
    required_env_var: Optional[str] = None,
) -> None:
    """Run the external-500 benchmark with the given provider query function.

    `query_fn` accepts the document text and returns the model's raw text
    response. It is responsible for its own retries and rate-limit handling;
    failures bubble up here and are recorded as `error` rows in the output.

    Resume: if `output_filename` already exists in `RESULTS_DIR`, samples
    whose ids appear there without an `error` field are skipped.
    """
    if required_env_var and not os.environ.get(required_env_var):
        print(f"ERROR: {required_env_var} not set", file=sys.stderr)
        sys.exit(1)

    with open(GROUND_TRUTH) as fp:
        samples = json.load(fp)
    os.makedirs(RESULTS_DIR, exist_ok=True)
    output_path = os.path.join(RESULTS_DIR, output_filename)

    results: list[dict] = []
    done_ids: set = set()
    if os.path.exists(output_path):
        with open(output_path) as fp:
            existing = json.load(fp)
        results = existing.get("results", [])
        done_ids = {r["id"] for r in results if not r.get("error")}
        print(f"Resuming: {len(done_ids)} samples already scored")

    print(f"{model_label} on {len(samples)} external samples\n{'=' * 80}")
    for sample in samples:
        if sample["id"] in done_ids:
            continue
        file_path = os.path.join(EVAL_DIR, sample["file"])
        if not os.path.exists(file_path):
            continue
        with open(file_path, "r", errors="replace") as fp:
            content = fp.read()[:6000]

        print(f"  [{sample['id']:4d}] {sample['source']:<25s}", end="", flush=True)
        start = time.time()

        expected = sample["category"]
        alt = sample.get("alt_category", "")

        try:
            response = query_fn(content)
            elapsed = time.time() - start
            findings = parse_response(response)
            predicted = get_primary_category(findings)
            ok = score(predicted, expected, alt)
            print(f" {elapsed:5.1f}s  cat={predicted:<14s} [{'OK' if ok else 'MISS':4s}]")
            results.append({
                "id": sample["id"],
                "file": sample["file"],
                "source": sample["source"],
                "expected_cat": expected,
                "predicted_cat": predicted,
                "cat_correct": ok,
                "elapsed": elapsed,
            })
        except Exception as exc:
            elapsed = time.time() - start
            print(f" {elapsed:5.1f}s  ERROR: {exc}")
            results.append({
                "id": sample["id"],
                "file": sample["file"],
                "source": sample["source"],
                "expected_cat": expected,
                "predicted_cat": "error",
                "cat_correct": False,
                "error": str(exc),
            })

        _write_snapshot(output_path, model_label, results)

    total = len(results)
    correct = sum(1 for r in results if r.get("cat_correct"))
    print(f"\n{'=' * 80}\n{model_label} external: {correct}/{total} = {correct / total * 100:.1f}%")
    _print_per_source(results)
    print(f"\nSaved: {output_path}")
