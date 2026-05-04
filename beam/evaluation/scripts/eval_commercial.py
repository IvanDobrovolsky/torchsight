#!/usr/bin/env python3
"""Evaluate commercial LLMs (GPT-4o, Claude, Gemini) against TorchSight-Eval-1000.

Uses the EXACT same system prompt, instruction, and scoring logic as eval_beam.py
to ensure a fair comparison.

Requirements:
    pip install requests

Usage:
    # Run specific provider
    PROVIDER=openai OPENAI_API_KEY=sk-... python eval_commercial.py
    PROVIDER=anthropic ANTHROPIC_API_KEY=sk-ant-... python eval_commercial.py
    PROVIDER=google GOOGLE_API_KEY=... python eval_commercial.py

    # Override model
    PROVIDER=openai MODEL=gpt-4.1 python eval_commercial.py

    # Resume from specific sample
    PROVIDER=openai START_ID=500 python eval_commercial.py

Environment variables:
    PROVIDER            — openai | anthropic | google (required)
    MODEL               — override default model
    START_ID            — resume from this sample ID
    OPENAI_API_KEY      — for GPT-4o / GPT-4.1
    ANTHROPIC_API_KEY   — for Claude
    GOOGLE_API_KEY      — for Gemini
"""

import base64
import json
import os
import re
import sys
import time
import requests

EVAL_DIR = os.environ.get("EVAL_DIR", os.path.join(os.path.dirname(__file__), "..", "data", "eval-1000-synthetic"))
GROUND_TRUTH = os.path.join(EVAL_DIR, "ground-truth.json")
RESULTS_DIR = os.path.join(os.path.dirname(__file__), "..", "results")

# ============================================================
# IDENTICAL prompt used across ALL models (Beam, GPT, Claude, Gemini)
# Source of truth: training/scripts/sft_converter.py SYSTEM_PROMPT
# ============================================================
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

KNOWN_CATEGORIES = {"pii", "credentials", "financial", "medical", "confidential", "malicious", "safe"}

PROVIDER = os.environ.get("PROVIDER", "").lower()

DEFAULT_MODELS = {
    "openai": "gpt-4o",
    "anthropic": "claude-sonnet-4-20250514",
    "google": "gemini-2.5-pro-preview-06-05",
    "google_vertex": "gemini-2.5-pro",
}

# Lazy-initialized Vertex AI client
_vertex_client = None

IMAGE_INSTRUCTION = "Analyze this image for security threats, sensitive data, credentials, PII, and policy violations. Look at ALL text visible in the image."
IMAGE_EXTENSIONS = {".png", ".jpg", ".jpeg", ".gif", ".webp", ".bmp"}


def get_api_key():
    if PROVIDER == "google_vertex":
        return "vertex"  # Uses ADC, no explicit key needed
    keys = {"openai": "OPENAI_API_KEY", "anthropic": "ANTHROPIC_API_KEY", "google": "GOOGLE_API_KEY"}
    env_name = keys.get(PROVIDER)
    if not env_name:
        print(f"ERROR: Unknown provider '{PROVIDER}'. Use: openai, anthropic, google, google_vertex")
        sys.exit(1)
    key = os.environ.get(env_name)
    if not key:
        print(f"ERROR: {env_name} not set")
        sys.exit(1)
    return key


# ============================================================
# Provider clients — raw HTTP, no SDKs
# ============================================================

def _request_with_retry(method, url, **kwargs):
    """HTTP request with exponential backoff on rate limits and server errors."""
    for attempt in range(8):
        try:
            r = requests.request(method, url, timeout=300, **kwargs)
            if r.status_code == 429:
                # Parse Retry-After header if present
                retry_after = r.headers.get("Retry-After")
                if retry_after:
                    wait = int(retry_after) + 1
                else:
                    wait = min(2 ** attempt * 10, 120)
                print(f" [rate-limited, wait {wait}s]", end="", flush=True)
                time.sleep(wait)
                continue
            r.raise_for_status()
            return r.json()
        except requests.exceptions.HTTPError:
            if attempt < 7 and r.status_code >= 500:
                time.sleep(2 ** attempt * 2)
                continue
            raise
    raise Exception("Max retries exceeded")


def build_content_parts(text=None, image_path=None):
    """Build multimodal content in provider-specific format."""
    is_image = image_path is not None
    if is_image:
        ext = os.path.splitext(image_path)[1].lower()
        mime = {".jpg": "image/jpeg", ".jpeg": "image/jpeg", ".png": "image/png",
                ".gif": "image/gif", ".webp": "image/webp"}.get(ext, "image/png")
        with open(image_path, "rb") as f:
            b64 = base64.b64encode(f.read()).decode()

    if PROVIDER == "google_vertex":
        from google.genai import types
        parts = []
        if is_image:
            parts.append(types.Part.from_bytes(data=open(image_path, "rb").read(), mime_type=mime))
            parts.append(types.Part.from_text(text=IMAGE_INSTRUCTION))
        else:
            parts.append(types.Part.from_text(text=f"{INSTRUCTION}\n\n{text}"))
        return parts
    elif PROVIDER == "openai":
        parts = []
        if is_image:
            parts.append({"type": "image_url", "image_url": {"url": f"data:{mime};base64,{b64}"}})
            parts.append({"type": "text", "text": IMAGE_INSTRUCTION})
        else:
            parts.append({"type": "text", "text": f"{INSTRUCTION}\n\n{text}"})
        return parts
    elif PROVIDER == "anthropic":
        parts = []
        if is_image:
            parts.append({"type": "image", "source": {"type": "base64", "media_type": mime, "data": b64}})
            parts.append({"type": "text", "text": IMAGE_INSTRUCTION})
        else:
            parts.append({"type": "text", "text": f"{INSTRUCTION}\n\n{text}"})
        return parts
    elif PROVIDER == "google":
        parts = []
        if is_image:
            parts.append({"inlineData": {"mimeType": mime, "data": b64}})
            parts.append({"text": IMAGE_INSTRUCTION})
        else:
            parts.append({"text": f"{INSTRUCTION}\n\n{text}"})
        return parts


def query_openai(api_key, model, content_parts):
    payload = {
        "model": model,
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": content_parts},
        ],
        "max_completion_tokens": 16384 if "gpt-5" in model else 4096,
        **({"temperature": 0} if "gpt-5" not in model else {}),
    }
    headers = {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}
    data = _request_with_retry("POST", "https://api.openai.com/v1/chat/completions",
                               json=payload, headers=headers)
    return data["choices"][0]["message"]["content"]


def query_anthropic(api_key, model, content_parts):
    payload = {
        "model": model, "max_tokens": 4096, "temperature": 0,
        "system": SYSTEM_PROMPT,
        "messages": [{"role": "user", "content": content_parts}],
    }
    headers = {"x-api-key": api_key, "anthropic-version": "2023-06-01", "Content-Type": "application/json"}
    data = _request_with_retry("POST", "https://api.anthropic.com/v1/messages",
                               json=payload, headers=headers)
    return data["content"][0]["text"]


def query_google_vertex(api_key, model, content_parts):
    global _vertex_client
    if _vertex_client is None:
        from google import genai
        project = os.environ.get("GCP_PROJECT", "dehum-research-ml")
        location = os.environ.get("GCP_LOCATION", "us-central1")
        _vertex_client = genai.Client(vertexai=True, project=project, location=location)
    from google.genai import types
    config = types.GenerateContentConfig(
        system_instruction=SYSTEM_PROMPT,
        temperature=0,
        max_output_tokens=4096,
    )
    resp = _vertex_client.models.generate_content(
        model=model, contents=content_parts, config=config
    )
    return resp.text


def query_google(api_key, model, content_parts):
    payload = {
        "systemInstruction": {"parts": [{"text": SYSTEM_PROMPT}]},
        "contents": [{"parts": content_parts}],
        "generationConfig": {"temperature": 0, "maxOutputTokens": 4096},
    }
    url = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent?key={api_key}"
    data = _request_with_retry("POST", url, json=payload)
    return data["candidates"][0]["content"]["parts"][0]["text"]


def query(api_key, model, content_parts):
    if PROVIDER == "openai":
        return query_openai(api_key, model, content_parts)
    elif PROVIDER == "anthropic":
        return query_anthropic(api_key, model, content_parts)
    elif PROVIDER == "google":
        return query_google(api_key, model, content_parts)
    elif PROVIDER == "google_vertex":
        return query_google_vertex(api_key, model, content_parts)
    raise ValueError(f"Unknown provider: {PROVIDER}")


# ============================================================
# Parsing & scoring — IDENTICAL to eval_beam.py
# ============================================================

def resolve_category(category: str, subcategory: str) -> str:
    if category == "confidential" and subcategory and "." in subcategory:
        prefix = subcategory.split(".")[0]
        if prefix in KNOWN_CATEGORIES and prefix != "confidential":
            return prefix
    return category


def try_repair_json_array(partial: str):
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


def parse_response(response: str) -> list[dict]:
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

    for match in re.finditer(r'\[.*?\]', response, re.DOTALL):
        try:
            parsed = json.loads(match.group())
            if isinstance(parsed, list):
                process_parsed(parsed)
        except json.JSONDecodeError:
            continue

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
    non_safe = [f for f in findings if f.get("category", "") != "safe"]
    if not non_safe:
        return "safe"
    severity_rank = {"critical": 0, "high": 1, "medium": 2, "warning": 2, "low": 3, "info": 4}
    non_safe.sort(key=lambda f: severity_rank.get(f.get("severity", "info"), 4))
    return non_safe[0].get("category", "unknown")


def get_primary_subcategory(findings: list[dict]) -> str:
    non_safe = [f for f in findings if f.get("category", "") != "safe"]
    if not non_safe:
        return "safe"
    severity_rank = {"critical": 0, "high": 1, "medium": 2, "warning": 2, "low": 3, "info": 4}
    non_safe.sort(key=lambda f: severity_rank.get(f.get("severity", "info"), 4))
    return non_safe[0].get("subcategory", "")


# ============================================================
# Main evaluation
# ============================================================

def _save_checkpoint(output_path, provider, model, results,
                     bucket_stats=None, category_stats=None,
                     txt_results=None, img_results=None):
    total = len(results)
    if total == 0:
        return
    cat_correct = sum(1 for r in results if r.get("cat_correct"))
    subcat_correct = sum(1 for r in results if r.get("subcat_correct"))
    data = {
        "provider": provider,
        "model": model,
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "total_samples": total,
        "category_accuracy": cat_correct / total,
        "subcategory_accuracy": subcat_correct / total,
        "results": results,
    }
    if bucket_stats:
        data["bucket_stats"] = bucket_stats
    if category_stats:
        data["category_stats"] = {k: dict(v) for k, v in category_stats.items()}
    if txt_results is not None:
        txt_correct = sum(1 for r in txt_results if r.get("cat_correct"))
        data["text_accuracy"] = txt_correct / len(txt_results) if txt_results else 0
    if img_results is not None:
        img_correct = sum(1 for r in img_results if r.get("cat_correct"))
        data["image_accuracy"] = img_correct / len(img_results) if img_results else 0
    with open(output_path, "w") as f:
        json.dump(data, f, indent=2, default=str)


def main():
    if not PROVIDER:
        print("ERROR: Set PROVIDER env var (openai, anthropic, google)")
        sys.exit(1)

    api_key = get_api_key()
    model = os.environ.get("MODEL", DEFAULT_MODELS.get(PROVIDER, ""))
    start_id = int(os.environ.get("START_ID", "1"))
    max_samples = int(os.environ.get("MAX_SAMPLES", "0"))  # 0 = unlimited

    print(f"Provider: {PROVIDER}")
    print(f"Model:    {model}")

    with open(GROUND_TRUTH) as f:
        all_samples = json.load(f)

    samples = [s for s in all_samples if s["id"] >= start_id]
    # Checkpoint support — resume from partial results
    os.makedirs(RESULTS_DIR, exist_ok=True)
    model_tag = model.replace("/", "-").replace(":", "-")
    output_path = os.path.join(RESULTS_DIR, f"eval1000_{PROVIDER}_{model_tag}.json")

    results = []
    done_ids = set()
    if start_id <= 1 and os.path.exists(output_path):
        with open(output_path) as f:
            existing = json.load(f)
        results = existing.get("results", [])
        done_ids = {r["id"] for r in results}
        print(f"  Resuming: {len(results)} samples already done, skipping those")

    print(f"\nEvaluating {len(samples)} samples (starting from ID {start_id})\n")
    print("=" * 95)

    bucket_stats = {}
    category_stats = {}

    evaluated_count = 0
    for i, sample in enumerate(samples):
        if sample["id"] in done_ids:
            continue
        if max_samples > 0 and evaluated_count >= max_samples:
            print(f"\n  Reached MAX_SAMPLES={max_samples}, stopping.")
            break
        evaluated_count += 1
        sample_path = os.path.join(EVAL_DIR, sample["file"])
        if not os.path.exists(sample_path):
            print(f"  SKIP [{sample['id']:4d}] {sample['file']} — file not found")
            continue

        is_image = os.path.splitext(sample["file"])[1].lower() in IMAGE_EXTENSIONS

        if is_image:
            content_parts = build_content_parts(image_path=sample_path)
        else:
            with open(sample_path, "r", errors="replace") as f:
                content = f.read()[:6000]
            content_parts = build_content_parts(text=content)

        tag = "IMG" if is_image else "TXT"
        print(f"  [{sample['id']:4d}] {tag} {sample['file']:<55s}", end="", flush=True)
        start = time.time()

        try:
            response = query(api_key, model, content_parts)
            elapsed = time.time() - start
            findings = parse_response(response)
            pred_cat = get_primary_category(findings)
            pred_subcat = get_primary_subcategory(findings)
            expected_cat = sample["category"]
            expected_subcat = sample["subcategory"]

            alt_cat = sample.get("alt_category", "")
            alt_subcat = sample.get("alt_subcategory", "")
            cat_ok = (pred_cat.lower().strip() == expected_cat.lower().strip() or
                      (bool(alt_cat) and pred_cat.lower().strip() == alt_cat.lower().strip()))
            subcat_ok = (pred_subcat.lower().strip() == expected_subcat.lower().strip() or
                         (bool(alt_subcat) and pred_subcat.lower().strip() == alt_subcat.lower().strip()))

            status = "OK" if cat_ok else "MISS"
            sub_status = "ok" if subcat_ok else "miss"

            print(f" {elapsed:5.1f}s  cat={pred_cat:<14s} [{status:4s}]  sub={pred_subcat:<30s} [{sub_status}]")

            result = {
                "id": sample["id"],
                "file": sample["file"],
                "bucket": sample.get("bucket", ""),
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
                "is_image": is_image,
            }
            results.append(result)

            b = sample.get("bucket", "unknown")
            if b not in bucket_stats:
                bucket_stats[b] = {"total": 0, "cat_correct": 0, "subcat_correct": 0}
            bucket_stats[b]["total"] += 1
            bucket_stats[b]["cat_correct"] += int(cat_ok)
            bucket_stats[b]["subcat_correct"] += int(subcat_ok)

            ec = expected_cat
            if ec not in category_stats:
                category_stats[ec] = {"total": 0, "cat_correct": 0, "tp": 0, "fp": 0, "fn": 0}
            category_stats[ec]["total"] += 1
            category_stats[ec]["cat_correct"] += int(cat_ok)

        except Exception as e:
            elapsed = time.time() - start
            print(f" {elapsed:5.1f}s  ERROR: {e}")
            results.append({
                "id": sample["id"], "file": sample["file"],
                "bucket": sample.get("bucket", ""),
                "expected_cat": sample["category"], "predicted_cat": "error",
                "cat_correct": False, "subcat_correct": False,
                "error": str(e), "is_image": is_image,
            })

        # Checkpoint after every sample — API calls are expensive
        _save_checkpoint(output_path, PROVIDER, model, results)

    # Confusion stats
    for r in results:
        if "error" in r:
            continue
        pred, exp = r["predicted_cat"], r["expected_cat"]
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

    img_results = [r for r in results if r.get("is_image")]
    txt_results = [r for r in results if not r.get("is_image")]
    img_correct = sum(1 for r in img_results if r.get("cat_correct"))
    txt_correct = sum(1 for r in txt_results if r.get("cat_correct"))

    print("\n" + "=" * 95)
    print(f"\n{'OVERALL RESULTS — ' + PROVIDER.upper() + ' / ' + model:^95}")
    print("=" * 95)
    print(f"  Samples evaluated:    {total}")
    print(f"  Errors:               {errors}")
    print(f"  Category accuracy:    {cat_correct}/{total} = {cat_correct/total*100:.1f}%")
    print(f"  Subcategory accuracy: {subcat_correct}/{total} = {subcat_correct/total*100:.1f}%")
    if txt_results:
        print(f"  Text accuracy:        {txt_correct}/{len(txt_results)} = {txt_correct/len(txt_results)*100:.1f}%")
    if img_results:
        print(f"  Image accuracy:       {img_correct}/{len(img_results)} = {img_correct/len(img_results)*100:.1f}%")
    if times:
        print(f"  Avg time/sample:      {sum(times)/len(times):.1f}s")
        print(f"  Total time:           {sum(times):.0f}s ({sum(times)/60:.1f}m)")

    print(f"\n{'ACCURACY BY BUCKET':^95}")
    print("-" * 95)
    print(f"  {'Bucket':<25s} {'Cat Acc':>10s} {'Subcat Acc':>12s} {'Samples':>10s}")
    print("-" * 95)
    for b in sorted(bucket_stats.keys()):
        s = bucket_stats[b]
        ca = s["cat_correct"] / s["total"] * 100
        sa = s["subcat_correct"] / s["total"] * 100
        print(f"  {b:<25s} {ca:>9.1f}% {sa:>11.1f}% {s['total']:>10d}")

    print(f"\n{'ACCURACY BY CATEGORY':^95}")
    print("-" * 95)
    print(f"  {'Category':<15s} {'Accuracy':>10s} {'Precision':>11s} {'Recall':>10s} {'F1':>8s} {'TP':>5s} {'FP':>5s} {'FN':>5s} {'N':>5s}")
    print("-" * 95)
    for c in sorted(category_stats.keys()):
        s = category_stats[c]
        acc = s["cat_correct"] / s["total"] * 100 if s["total"] > 0 else 0
        tp, fp, fn = s.get("tp", 0), s.get("fp", 0), s.get("fn", 0)
        precision = tp / (tp + fp) * 100 if (tp + fp) > 0 else 0
        recall = tp / (tp + fn) * 100 if (tp + fn) > 0 else 0
        f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0
        print(f"  {c:<15s} {acc:>9.1f}% {precision:>10.1f}% {recall:>9.1f}% {f1:>7.1f}% {tp:>5d} {fp:>5d} {fn:>5d} {s['total']:>5d}")

    misses = [r for r in results if not r.get("cat_correct") and "error" not in r]
    if misses:
        print(f"\n{'MISCLASSIFICATIONS':^95}")
        print("-" * 95)
        for m in misses:
            print(f"  [{m['id']:4d}] {m['file']}")
            print(f"        Expected: {m['expected_cat']:<15s} ({m.get('expected_subcat', '?')})")
            print(f"        Got:      {m['predicted_cat']:<15s} ({m.get('predicted_subcat', '?')})")
            print()

    # Final save
    _save_checkpoint(output_path, PROVIDER, model, results,
                     bucket_stats=bucket_stats, category_stats=category_stats,
                     txt_results=txt_results, img_results=img_results)
    print(f"\nResults saved to: {output_path}")


if __name__ == "__main__":
    main()
