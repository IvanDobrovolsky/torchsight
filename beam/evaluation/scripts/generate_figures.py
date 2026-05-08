#!/usr/bin/env python3
"""Generate paper figures from eval JSONs using matplotlib/seaborn defaults.

No color overrides. No theme tweaks. Output goes to figures/<n>.pdf and .png.

Figures (Figure 1 architecture is hand-drawn; numbering below picks up at 2):
  fig2_fp_rates              — false-positive rate on safe docs across models
  fig3_confusion_beam_q4     — confusion matrix, Beam q4_K_M, primary benchmark
  fig4_external_by_source    — Beam q4 accuracy per source, external benchmark
  fig5_primary_vs_external   — Beam vs commercial primary→external delta

Usage:
  python generate_figures.py            # regenerate all
  python generate_figures.py fig3       # regenerate one
"""
import json
import os
import sys
from collections import Counter

import matplotlib.pyplot as plt
import numpy as np
import seaborn as sns

ROOT = os.path.join(os.path.dirname(__file__), "..")
RESULTS = os.path.join(ROOT, "results")
FIGURES = os.path.join(ROOT, "figures")
os.makedirs(FIGURES, exist_ok=True)

CATS = ["credentials", "pii", "financial", "medical", "confidential", "malicious", "safe"]


def load(path):
    with open(os.path.join(RESULTS, path)) as f:
        return json.load(f)


def save(fig, name):
    fig.savefig(os.path.join(FIGURES, f"{name}.pdf"), bbox_inches="tight")
    fig.savefig(os.path.join(FIGURES, f"{name}.png"), bbox_inches="tight", dpi=200)
    plt.close(fig)
    print(f"  wrote figures/{name}.pdf and .png")


def fig2_fp_rates():
    """False-positive rate on safe documents across all evaluated models."""
    models = [
        ("Beam q4_K_M", "eval1000_beam_q4_K_M.json"),
        ("Claude Opus 4", "eval1000_anthropic_claude-opus-4-20250514.json"),
        ("Claude Sonnet 4", "eval1000_anthropic_claude-sonnet-4-20250514.json"),
        ("GPT-5", "eval1000_openai_gpt-5.json"),
        ("Gemini 2.5 Pro", "eval1000_google_vertex_gemini-2.5-pro.json"),
    ]
    fp_rates = []
    labels = []
    for label, path in models:
        d = load(path)
        safe = [r for r in d["results"] if r["expected_cat"].lower() == "safe"]
        fp = sum(1 for r in safe if r["predicted_cat"].lower() != "safe")
        fp_rates.append(fp / len(safe) * 100)
        labels.append(label)

    fig, ax = plt.subplots(figsize=(7.5, 4.5))
    ax.bar(labels, fp_rates)
    ax.axhline(10, linestyle="--", linewidth=1)
    ax.set_ylabel("False positive rate (%)")
    ax.set_title("False positive rate on safe documents", pad=14)
    ax.set_ylim(0, 78)
    for i, v in enumerate(fp_rates):
        ax.text(i, v + 1.5, f"{v:.1f}%", ha="center", va="bottom")
    fig.autofmt_xdate(rotation=20)
    fig.tight_layout()
    save(fig, "fig2_fp_rates")


def fig3_confusion_beam_q4():
    """Row-normalized confusion matrix for Beam q4_K_M on primary benchmark."""
    d = load("eval1000_beam_q4_K_M.json")
    n = len(CATS)
    matrix = np.zeros((n, n), dtype=int)
    for r in d["results"]:
        t = r["expected_cat"].lower()
        p = r["predicted_cat"].lower()
        if t in CATS and p in CATS:
            matrix[CATS.index(t), CATS.index(p)] += 1

    row_sums = matrix.sum(axis=1, keepdims=True)
    row_sums[row_sums == 0] = 1
    norm = matrix / row_sums

    fig, ax = plt.subplots(figsize=(7, 6))
    sns.heatmap(
        norm,
        annot=matrix,
        fmt="d",
        cmap="Blues",
        xticklabels=CATS,
        yticklabels=CATS,
        ax=ax,
        cbar_kws={"label": "Row-normalized fraction"},
    )
    ax.set_xlabel("Predicted category")
    ax.set_ylabel("True category")
    ax.set_title("Confusion matrix — Beam q4_K_M on Eval-1000")
    save(fig, "fig3_confusion_beam_q4")


def fig4_external_by_source():
    """Beam q4_K_M accuracy by source on the external benchmark."""
    d = load("eval_external_torchsight-beam-q4_K_M.json")
    by = {}
    for r in d["results"]:
        s = r.get("source", "?")
        by.setdefault(s, [0, 0])
        by[s][1] += 1
        if r.get("cat_correct"):
            by[s][0] += 1

    order = ["nvd_holdout", "nist_holdout", "mtsamples", "ai4privacy_holdout",
             "phishing_holdout", "enron_holdout"]
    labels = [s.replace("_holdout", "").upper() if s != "mtsamples" else "MTSamples" for s in order]
    accs = [by[s][0] / by[s][1] * 100 for s in order]
    ns = [by[s][1] for s in order]

    fig, ax = plt.subplots(figsize=(7.5, 4.5))
    ax.bar(labels, accs)
    ax.set_ylabel("Accuracy (%)")
    ax.set_ylim(0, 118)
    ax.set_title(f"Beam q4_K_M on Eval-500-External (n={sum(ns)})", pad=14)
    for i, (a, n) in enumerate(zip(accs, ns)):
        ax.text(i, a + 1.5, f"{a:.1f}%\n(n={n})", ha="center", va="bottom", fontsize=9)
    fig.autofmt_xdate(rotation=20)
    fig.tight_layout()
    save(fig, "fig4_external_by_source")


def fig5_primary_vs_external():
    """Per-model accuracy on primary vs external benchmarks."""
    pairs = [
        ("Beam q4_K_M",
         "eval1000_beam_q4_K_M.json",
         "eval_external_torchsight-beam-q4_K_M.json"),
        ("Claude Sonnet 4",
         "eval1000_anthropic_claude-sonnet-4-20250514.json",
         "eval_external_claude-sonnet-4-20250514.json"),
        ("Gemini 2.5 Pro",
         "eval1000_google_vertex_gemini-2.5-pro.json",
         "eval_external_gemini-2.5-pro.json"),
        ("GPT-5",
         "eval1000_openai_gpt-5.json",
         "eval_external_gpt-5.json"),
        ("Regex baseline",
         "eval1000_regex_only.json",
         "eval_external_regex_only.json"),
    ]
    labels = []
    primary = []
    external = []
    for label, p_path, e_path in pairs:
        labels.append(label)
        primary.append(load(p_path)["category_accuracy"] * 100)
        external.append(load(e_path)["category_accuracy"] * 100)

    x = np.arange(len(labels))
    width = 0.38
    fig, ax = plt.subplots(figsize=(8, 4.8))
    ax.bar(x - width / 2, primary, width, label="Primary (Eval-1000)")
    ax.bar(x + width / 2, external, width, label="External (Eval-500)")
    ax.set_xticks(x)
    ax.set_xticklabels(labels)
    ax.set_ylabel("Accuracy (%)")
    ax.set_ylim(0, 115)
    ax.set_title("Primary vs external benchmark accuracy", pad=14)
    ax.legend(loc="lower left")
    for i, (p, e) in enumerate(zip(primary, external)):
        ax.text(i - width / 2, p + 1.5, f"{p:.1f}", ha="center", va="bottom", fontsize=9)
        ax.text(i + width / 2, e + 1.5, f"{e:.1f}", ha="center", va="bottom", fontsize=9)
    fig.autofmt_xdate(rotation=15)
    fig.tight_layout()
    save(fig, "fig5_primary_vs_external")


FIGURES_DEF = {
    "fig2": fig2_fp_rates,
    "fig3": fig3_confusion_beam_q4,
    "fig4": fig4_external_by_source,
    "fig5": fig5_primary_vs_external,
}


def main():
    targets = sys.argv[1:] or list(FIGURES_DEF.keys())
    for t in targets:
        if t not in FIGURES_DEF:
            print(f"unknown figure: {t}; choose from {list(FIGURES_DEF)}")
            continue
        print(f"generating {t}")
        FIGURES_DEF[t]()


if __name__ == "__main__":
    main()
