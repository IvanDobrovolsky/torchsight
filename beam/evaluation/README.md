# TorchSight Evaluation

Reproducible benchmarks for the TorchSight paper. Two benchmarks, one
methodology — every Beam quantization and every commercial baseline runs
through the same prompt/parser/scorer.

## Layout

```
evaluation/
├── scripts/        # eval drivers + benchmark builders
├── data/           # eval-1000-synthetic (synthetic) + eval-500-external (held-out)
└── results/        # JSON output per run, indexed by model tag
```

## Benchmarks

| Benchmark | Samples | Source | Ground truth |
|---|---|---|---|
| `eval-1000-synthetic` | 1000 (text + 100 images) | Programmatically generated, stratified across 7 categories × ~50 subcategories | Single-label (no `alt_category`) |
| `eval-500-external` | 500 text samples | Held-out splits of training sources (NVD, NIST, AI4Privacy, Enron, phishing) + MTSamples (excluded from training) | Dual-label for ambiguous boundaries — `alt_category` accepted on 320/500 |

Both directories are gitignored — regenerate from the build scripts (`generate_eval_1000.py`, `build_external_benchmark.py`).

The dual-labelling on external is intentional: an NVD CVE description can
legitimately be classified as `malicious` (vulnerability) or `confidential`
(security disclosure); an Enron business email straddles `pii` and
`confidential`; etc. Scorers accept either label.

## Methodology

Single canonical pipeline in `scripts/eval_beam.py`. Every other Beam-
or Ollama-based eval imports its query/parser/scorer from there.

| Aspect | Setting |
|---|---|
| Prompt format | Alpaca: `### Instruction:\n{INSTRUCTION}\n\n### Input:\n{text}\n\n### Response:\n` |
| SYSTEM prompt | Defined in Modelfile, applied via Ollama TEMPLATE |
| Temperature | Modelfile default (0.1 for Beam quants; commercial models run at 0) |
| `num_predict` | 2048 |
| Stop tokens | `["\n\n\n"]` |
| Text truncation | First 6000 chars per sample (matches Rust scanner) |
| Parser | `parse_beam_response` — extracts JSON arrays, deduplicates by `category:subcategory`, repairs truncated arrays |
| `resolve_category` | Fixes Beam's "confidential" over-prediction by mapping to subcategory prefix when prefix is a known category |
| Primary category | Most-severe non-safe finding by `severity_rank` (`critical < high < medium < low < info`); else `"safe"` |
| Scoring | `pred == expected` OR (alt exists AND `pred == alt`) |

Image samples in `eval-1000-synthetic/images/` go through Llama 3.2 Vision first
(via Ollama `/api/generate` with `images=[base64]`); the resulting
description is then fed to Beam as text. External has no image samples.

## Scripts

| Script | Benchmark | Purpose |
|---|---|---|
| `eval_beam.py` | eval-1000-synthetic | Beam quantizations + Qwen 3.5 27B base, via Ollama |
| `eval_external.py` | eval-500-external | Same Ollama models — imports methodology from `eval_beam.py` |
| `eval_torchsight.py` | eval-1000-synthetic | Full TorchSight CLI pipeline (Beam + 35-pattern regex safety net) |
| `eval_commercial.py` | eval-1000-synthetic | Claude / Gemini / GPT-5 via official APIs |
| `eval_external_claude.py` | eval-500-external | Anthropic API |
| `eval_external_gemini.py` | eval-500-external | Google Vertex API |
| `eval_external_gpt5.py` | eval-500-external | OpenAI API |
| `eval_regex_baseline.py` | both | 35-pattern regex baseline, no LLM |

Benchmark builders:

| Script | Purpose |
|---|---|
| `generate_eval_1000.py` | Build the eval-1000-synthetic corpus from category templates |
| `generate_eval_images.py`, `expand_eval_images.py` | Build/expand the image subset |
| `build_external_benchmark.py` | Sample held-out splits + MTSamples into eval-500-external |

## Running an eval

```bash
# Beam q4_K_M on synthetic
BEAM_MODEL=torchsight/beam:q4_K_M python scripts/eval_beam.py

# Beam q8_0 on external
BEAM_MODEL=torchsight/beam:q8_0 python scripts/eval_external.py

# Qwen base on external (controlled ablation: same prompt, no LoRA)
BEAM_MODEL=qwen3.5:27b python scripts/eval_external.py

# Resume an interrupted run — checkpoints written every sample
BEAM_MODEL=torchsight/beam:q4_K_M python scripts/eval_external.py
```

Output lands in `results/eval_external_<model_tag>.json` (or
`eval1000_results_<tag>.json` for synthetic). Each entry has the
prediction, scoring flags, raw findings, and per-source/per-category
breakdowns in the summary header.

## Reproducibility notes

* Beam GGUFs come from `huggingface.co/torchsight/beam-{q4_K_M,q8_0,f16}`.
  Each is a Qwen 3.5 27B + LoRA fine-tune (training config in
  `beam/scripts/train_lora.py`).
* `qwen3.5:27b` is the unmodified base, pulled from `ollama.com`.
* Modelfiles in `modelfiles/` set `SYSTEM`, `temperature 0.1`, `top_p 0.9`,
  `num_predict 2048`. Modelfiles are identical across quants except for the
  `FROM` line.
* Commercial-model results were generated 2026-03 against the dated model
  IDs in each result file's `model` field. Exact reproduction requires the
  same dated snapshot.

## Known asymmetry

Beam runs at the model's training-time default temperature (0.1, set in
the Modelfile). Commercial baselines run at temperature 0. Both regimes
are essentially deterministic for this task (single-token classification
into one of seven categories), but the asymmetry is documented in the
paper's §6 limitations.
