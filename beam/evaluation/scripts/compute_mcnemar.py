#!/usr/bin/env python3
"""Pairwise McNemar's test for Beam q4_K_M vs each baseline on eval-1000.

Discordant counts come from the per-sample `cat_correct` flag in each
result JSON. Continuity-corrected χ² with df=1; p-value via complementary
error function (no scipy dependency).

Usage:
    python compute_mcnemar.py /path/to/results
"""
from __future__ import annotations

import json
import math
import sys
from pathlib import Path

DEFAULT_RESULTS = Path(__file__).resolve().parent.parent / "results"

PAIRS = [
    ("Claude Sonnet 4",   "eval1000_anthropic_claude-sonnet-4-20250514.json"),
    ("Claude Opus 4",     "eval1000_anthropic_claude-opus-4-20250514.json"),
    ("Gemini 2.5 Pro",    "eval1000_google_vertex_gemini-2.5-pro.json"),
    ("GPT-5",             "eval1000_openai_gpt-5.json"),
    ("Qwen 3.5 27B base", "eval1000_qwen35_27b_base.json"),
    ("Beam q8_0",         "eval1000_beam_q8_0.json"),
    ("Beam f16",          "eval1000_beam_f16.json"),
]
BEAM_FILE = "eval1000_beam_q4_K_M.json"


def mcnemar(a_results: list, b_results: list) -> tuple | None:
    a = {r["id"]: bool(r.get("cat_correct")) for r in a_results}
    b = {r["id"]: bool(r.get("cat_correct")) for r in b_results}
    common = set(a) & set(b)
    n10 = sum(1 for i in common if a[i] and not b[i])
    n01 = sum(1 for i in common if not a[i] and b[i])
    if n10 + n01 == 0:
        return None
    chi2 = (abs(n10 - n01) - 1) ** 2 / (n10 + n01)
    p = math.erfc(math.sqrt(chi2 / 2))
    return n10, n01, chi2, p


def main() -> None:
    results_dir = Path(sys.argv[1]) if len(sys.argv) > 1 else DEFAULT_RESULTS
    beam = json.load(open(results_dir / BEAM_FILE))

    print(
        f"McNemar's pairwise tests vs Beam q4_K_M on eval-1000-synthetic\n"
        f"{'comparator':<25s}  {'n_q4>X':>7s}  {'n_X>q4':>7s}  {'chi2':>8s}  "
        f"{'p-value':>11s}  sig"
    )
    print("-" * 85)
    for label, fname in PAIRS:
        path = results_dir / fname
        if not path.exists():
            print(f"  {label:<23s}  (missing: {fname})")
            continue
        other = json.load(open(path))
        out = mcnemar(beam["results"], other["results"])
        if out is None:
            print(f"  {label:<23s}  (no discordant pairs)")
            continue
        n10, n01, chi2, p = out
        sig = "***" if p < 0.001 else "**" if p < 0.01 else "*" if p < 0.05 else "ns"
        p_str = f"{p:.2e}" if p < 1e-4 else f"{p:.4f}"
        print(f"  {label:<23s}  {n10:>7d}  {n01:>7d}  {chi2:>8.2f}  {p_str:>11s}  {sig}")
    print("\nSignificance: *** p<0.001, ** p<0.01, * p<0.05, ns not significant")


if __name__ == "__main__":
    main()
