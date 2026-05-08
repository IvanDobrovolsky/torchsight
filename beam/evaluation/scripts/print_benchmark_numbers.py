#!/usr/bin/env python3
"""Regenerate ../BENCHMARK_NUMBERS.md from results/*.json.

Single source of truth for paper tables. Run after any rerun:
  python scripts/print_benchmark_numbers.py
"""
import json
import math
import os
from collections import Counter

ROOT = os.path.join(os.path.dirname(__file__), "..")
RES = os.path.join(ROOT, "results")
OUT = os.path.join(ROOT, "BENCHMARK_NUMBERS.md")
CATS = ["credentials", "pii", "financial", "medical", "confidential", "malicious", "safe"]


def load(name):
    with open(os.path.join(RES, name)) as f:
        return json.load(f)


def wilson(c, n, z=1.96):
    p = c / n
    denom = 1 + z * z / n
    centre = (p + z * z / (2 * n)) / denom
    halfw = (z * math.sqrt((p * (1 - p) + z * z / (4 * n)) / n)) / denom
    return ((centre - halfw) * 100, (centre + halfw) * 100)


def per_cat(d):
    by = {c: [0, 0] for c in CATS}
    for r in d["results"]:
        t = r["expected_cat"].lower()
        p = r["predicted_cat"].lower()
        if t in by:
            by[t][1] += 1
            if t == p:
                by[t][0] += 1
    return {c: by[c][0] / by[c][1] * 100 if by[c][1] else 0 for c in CATS}


def per_src(d):
    by = {}
    for r in d["results"]:
        s = r.get("source", "?")
        by.setdefault(s, [0, 0])
        by[s][1] += 1
        if r.get("cat_correct"):
            by[s][0] += 1
    return {k: v[0] / v[1] * 100 for k, v in by.items()}


def main():
    P = {m: load(f) for m, f in [
        ("Beam q4_K_M", "eval1000_beam_q4_K_M.json"),
        ("Beam q8_0",   "eval1000_beam_q8_0.json"),
        ("Beam f16",    "eval1000_beam_f16.json"),
        ("Sonnet 4",    "eval1000_anthropic_claude-sonnet-4-20250514.json"),
        ("Opus 4",      "eval1000_anthropic_claude-opus-4-20250514.json"),
        ("GPT-5",       "eval1000_openai_gpt-5.json"),
        ("Gemini 2.5",  "eval1000_google_vertex_gemini-2.5-pro.json"),
        ("Regex",       "eval1000_regex_only.json"),
        ("Qwen base",   "eval1000_qwen35_27b_base.json"),
    ]}
    E = {m: load(f) for m, f in [
        ("Beam q4_K_M", "eval_external_torchsight-beam-q4_K_M.json"),
        ("Beam q8_0",   "eval_external_torchsight-beam-q8_0.json"),
        ("Beam f16",    "eval_external_torchsight-beam-f16.json"),
        ("Sonnet 4",    "eval_external_claude-sonnet-4-20250514.json"),
        ("GPT-5",       "eval_external_gpt-5.json"),
        ("Gemini 2.5",  "eval_external_gemini-2.5-pro.json"),
        ("Regex",       "eval_external_regex_only.json"),
        ("Qwen base",   "eval_external_qwen3.5-27b.json"),
    ]}

    lines = ["# TorchSight benchmark numbers (canonical)", "",
             "Auto-generated from `evaluation/results/*.json`. Single source of truth for the paper.",
             "Re-generate after any eval rerun: `python scripts/print_benchmark_numbers.py`.",
             ""]

    lines += ["## Eval-1000 (primary, n=1000)", "",
              "| model | accuracy | 95% Wilson CI | subcategory |",
              "|---|---:|---|---:|"]
    for m in ["Beam q4_K_M", "Beam f16", "Beam q8_0", "Sonnet 4", "Opus 4", "GPT-5", "Gemini 2.5", "Regex", "Qwen base"]:
        n = P[m]["total_samples"]
        c = round(P[m]["category_accuracy"] * n)
        lo, hi = wilson(c, n)
        sub = P[m].get("subcategory_accuracy")
        sub_str = f"{sub*100:.1f}%" if sub is not None else "—"
        lines.append(f"| {m} | {c/n*100:.1f}% | [{lo:.1f}, {hi:.1f}] | {sub_str} |")

    lines += ["", "## Eval-500 (external held-out, n=500)", "",
              "| model | accuracy | 95% Wilson CI |",
              "|---|---:|---|"]
    for m in ["Beam q4_K_M", "Beam f16", "Beam q8_0", "Sonnet 4", "GPT-5", "Gemini 2.5", "Regex", "Qwen base"]:
        n = E[m]["total_samples"]
        c = round(E[m]["category_accuracy"] * n)
        lo, hi = wilson(c, n)
        lines.append(f"| {m} | {c/n*100:.1f}% | [{lo:.1f}, {hi:.1f}] |")

    lines += ["", "## Per-category accuracy (Eval-1000)", "",
              "| category | " + " | ".join(["Beam q4_K_M", "GPT-5", "Sonnet 4", "Opus 4", "Gemini 2.5"]) + " |",
              "|---|" + "---:|" * 5]
    for c in CATS:
        row = [c.capitalize()]
        for m in ["Beam q4_K_M", "GPT-5", "Sonnet 4", "Opus 4", "Gemini 2.5"]:
            row.append(f"{per_cat(P[m])[c]:.1f}%")
        lines.append("| " + " | ".join(row) + " |")

    lines += ["", "## Beam q4_K_M precision / recall / F1 (Eval-1000)", "",
              "| category | precision | recall | F1 |",
              "|---|---:|---:|---:|"]
    d = P["Beam q4_K_M"]
    tp = Counter(); fp = Counter(); fn = Counter()
    for r in d["results"]:
        t, p = r["expected_cat"].lower(), r["predicted_cat"].lower()
        if t == p:
            tp[t] += 1
        else:
            fp[p] += 1; fn[t] += 1
    ps, rs, fs = [], [], []
    for c in CATS:
        pv = tp[c] / (tp[c] + fp[c]) * 100 if (tp[c] + fp[c]) else 0
        rv = tp[c] / (tp[c] + fn[c]) * 100 if (tp[c] + fn[c]) else 0
        f1 = 2 * pv * rv / (pv + rv) if (pv + rv) else 0
        lines.append(f"| {c} | {pv:.1f}% | {rv:.1f}% | {f1:.1f}% |")
        ps.append(pv); rs.append(rv); fs.append(f1)
    lines.append(f"| **macro avg** | **{sum(ps)/7:.1f}%** | **{sum(rs)/7:.1f}%** | **{sum(fs)/7:.1f}%** |")

    lines += ["", "## Regex-only baseline vs Beam q4_K_M (Eval-1000)", "",
              "| category | regex | beam q4 | gap |",
              "|---|---:|---:|---:|"]
    rg = per_cat(P["Regex"]); bq = per_cat(P["Beam q4_K_M"])
    for c in ["credentials", "safe", "pii", "malicious", "financial", "confidential", "medical"]:
        lines.append(f"| {c} | {rg[c]:.1f}% | {bq[c]:.1f}% | +{bq[c]-rg[c]:.1f} pp |")
    lines.append(f"| **Overall** | **{P['Regex']['category_accuracy']*100:.1f}%** | **{P['Beam q4_K_M']['category_accuracy']*100:.1f}%** | **+{(P['Beam q4_K_M']['category_accuracy']-P['Regex']['category_accuracy'])*100:.1f} pp** |")

    lines += ["", "## Eval-500 per-source breakdown", "",
              "Scoring uses the alt_category-aware scorer (see ground-truth `alt_category` field).",
              "",
              "| source | n | Beam q4 | Sonnet 4 | Gemini 2.5 | GPT-5 | Qwen base |",
              "|---|---:|---:|---:|---:|---:|---:|"]
    sources = ["nvd_holdout", "nist_holdout", "mtsamples", "ai4privacy_holdout", "phishing_holdout", "enron_holdout"]
    for s in sources:
        n = sum(1 for r in E["Beam q4_K_M"]["results"] if r.get("source") == s)
        row = [s, str(n)]
        for m in ["Beam q4_K_M", "Sonnet 4", "Gemini 2.5", "GPT-5", "Qwen base"]:
            row.append(f"{per_src(E[m]).get(s, 0):.1f}%")
        lines.append("| " + " | ".join(row) + " |")
    overall = ["**Overall**", "**500**"]
    for m in ["Beam q4_K_M", "Sonnet 4", "Gemini 2.5", "GPT-5", "Qwen base"]:
        overall.append(f"**{E[m]['category_accuracy']*100:.1f}%**")
    lines.append("| " + " | ".join(overall) + " |")

    lines += ["", "## False-positive rates on safe documents (Eval-1000)", "",
              "Computed as 1 − safe-category accuracy.",
              "",
              "| model | FP rate |",
              "|---|---:|"]
    for m in ["Beam q4_K_M", "Beam f16", "Beam q8_0", "Opus 4", "Sonnet 4", "Qwen base", "GPT-5", "Gemini 2.5"]:
        safe_n = sum(1 for r in P[m]["results"] if r["expected_cat"].lower() == "safe")
        safe_c = sum(1 for r in P[m]["results"] if r["expected_cat"].lower() == "safe" and r["predicted_cat"].lower() == "safe")
        lines.append(f"| {m} | {(safe_n-safe_c)/safe_n*100:.1f}% |")

    with open(OUT, "w") as f:
        f.write("\n".join(lines) + "\n")
    print(f"wrote {OUT}")


if __name__ == "__main__":
    main()
