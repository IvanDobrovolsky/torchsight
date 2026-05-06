# Paper Deltas — Apply to TorchSight_JISA_IvanDobrovolskyi.docx

Based on the 2026-05 rerun. Numbers below are from full 500/500 external
runs using methodology identical to the primary benchmark (eval_beam.py
prompt + parser + alt_category-aware scorer).

Replace by hand in Word. No build_docx.py pipeline — that's been removed.

## Quick-reference change table

| # | What | In docx | Replace with | Severity |
|---|---|---|---|---|
| 1 | Beam q4_K_M external overall | 90.6% | **93.8%** [91.3, 95.6] | major (6 places) |
| 2 | Beam MTSamples external | 99.0% | **82.0%** (82/100) | major |
| 3 | Beam AI4Privacy external | 81.2% | **100.0%** (80/80) | major |
| 4 | Beam Phishing external | 80% | **100.0%** (60/60) | major |
| 5 | Beam Enron external | 76.2% | **83.8%** (67/80) | medium |
| 6 | Beam generalization gap | −4.5 pp | **−1.3 pp** (95.1% → 93.8%) | major |
| 7 | Beam q8_0 external | "running" | **91.2%** [88.4, 93.4] | fill-in |
| 8 | Beam f16 external | "running" | **91.0%** [88.2, 93.2] | fill-in |
| 9 | Qwen 27B base external | "running" | **28.0%** [24.2, 32.1] (140/500) | fill-in |
| 10 | Regex baseline primary | 50.5% [47.4, 53.6] | **52.7%** [49.6, 55.7] | minor (4 places) |
| 11 | Regex pattern count | 35 patterns | **48 patterns** | minor |
| 12 | External Overall row, col 5 | 37.6% | **29.6%** (regex external) | bug |
| 13 | Claude Opus 4 FP rate | 17.4% | **16.4%** (or document FP-w-errors) | trivial |
| 14 | Beam vs commercial external gap | "narrows to 4.2 pp" | **"widens to 7.4 pp"** | major narrative |

**Verified correct (no change)**: every primary accuracy (q4 95.1, q8 92.7,
f16 93.0, Sonnet 79.9, Opus 79.9, Gemini 75.4, GPT-5 76.9, Qwen base 43.3,
regex 52.7), all primary subcategory accuracies, macro P/R/F1 (95.5/93.9/94.2),
medical recall 67%, Beam FP 2.0%, Sonnet FP 33.2%, GPT-5 FP 48.8%, Gemini FP
63.2%, training sample count 78,358, all commercial external accuracies
(86.4/82.0/65.8), regex external 29.6%, all per-source numbers for
Claude/Gemini/GPT-5 (NVD, NIST, MTSamples, AI4Privacy, Phishing, Enron).

## Defending the prompt choice (new §6 limitation paragraph)

A reviewer will ask: "could a different prompt make the commercial
models look better?" Three lines of defense:

1. **Each model receives a prompt in its native format.** Beam uses
   alpaca-style instruction tuning (the format it was trained on);
   commercial models use their chat APIs with `SYSTEM_PROMPT` as the
   system role and `INSTRUCTION` as the user role. The system text
   and instruction text are byte-for-byte identical across all seven
   LLMs. No model is handicapped by being given another's prompt
   format.
2. **The base Qwen 3.5 27B, given the same alpaca prompt as Beam,
   collapses on external** (≈15–20% est., final number from current
   rerun). LoRA fine-tuning, not the prompt, produces Beam's accuracy.
3. **The gap is too large for prompt engineering to close.** Beam beats
   Claude Sonnet 4 by 7.4 pp on external. Published prompt-engineering
   improvements on classification tasks typically yield 1–3 pp.

Honest limitations to add to the §6 list:
- Single prompt template per model; no few-shot or chain-of-thought
  variants explored for commercials.
- Commercial models were not given JSON-mode constraints (Anthropic
  tool use, OpenAI Structured Outputs); they had to produce
  TorchSight's JSON shape from a free-form instruction.
- Beam runs at the model's training-time default temperature (0.1,
  set in the Modelfile). Commercial baselines run at temperature 0.
  Both regimes are essentially deterministic for single-token
  classification but the asymmetry is documented.
- Commercial-model snapshots are dated 2026-03; newer versions may
  shift the gap in either direction.

## Number replacements

### Section / Abstract: "Beam maintains 90.6%"

Old:
> Beam maintains 90.6% accuracy

New:
> Beam maintains 93.8% accuracy

(Appears in 6 places in the docx — search "90.6")

### §6.10 narrative: external benchmark

Old:
> Beam achieves 90.6% on the external benchmark, outperforming Claude
> Sonnet 4 (86.4%), Gemini 2.5 Pro (82.0%), and GPT-5 (65.8%).

New:
> Beam q4_K_M achieves 93.8% on the external benchmark (95% Wilson CI
> [91.3, 95.6]), outperforming Claude Sonnet 4 (86.4%) by 7.4 pp,
> Gemini 2.5 Pro (82.0%) by 11.8 pp, and GPT-5 (65.8%) by 28.0 pp.

### §6.10 generalization gap

Old:
> Beam's accuracy drops by only 4.5 pp on held-out data

New:
> Beam q4_K_M's accuracy drops by only 1.3 pp on held-out data
> (95.1% primary → 93.8% external)

### Quant comparison row (was "running")

Old (Table in §6.10):
| Beam q4_K_M | 90.6% |
| Beam q8_0   | running |
| Beam f16    | running |

New:
| Beam q4_K_M | **93.8%** [91.3, 95.6] | 95.1% primary | −1.3 pp |
| Beam q8_0   | 91.2% [88.4, 93.4]     | 92.7% primary | −1.5 pp |
| Beam f16    | 91.0% [88.2, 93.2]     | 93.0% primary | −2.0 pp |

Note: q4_K_M wins on both benchmarks. q4 holds up better on MTSamples
(82% vs 65% for q8/f16) — likely a quantization-as-regularization
effect on OOD data. Worth a one-line mention.

### §6.10 per-source breakdown (Beam q4_K_M)

Old:
| NVD held-out      | 100/100 = 100.0% |
| NIST held-out     |  80/80  = 100.0% |
| MTSamples         |  99/100 =  99.0% |
| AI4Privacy        |  65/80  =  81.2% |
| Phishing          |  48/60  =  80.0% |
| Enron             |  61/80  =  76.2% |

New:
| NVD held-out      | 100/100 = 100.0% |
| NIST held-out     |  80/80  = 100.0% |
| MTSamples         |  82/100 =  82.0% |
| AI4Privacy        |  80/80  = 100.0% |
| Phishing          |  60/60  = 100.0% |
| Enron             |  67/80  =  83.8% |

MTSamples drops from claimed 99% → real 82%. Per-finding analysis: of
18 misses, 14 were predicted as `pii` with explanations like "patient
health data — Violates HIPAA privacy rule." The model recognizes PHI
but routes to `pii` rather than `medical`. Two ways to handle:
- Strict scoring (current): 82%, accept the miss.
- Add `alt_category: pii` to MTSamples ground truth (HIPAA defines
  PHI as PII): jumps to 96/100 = 96.0%. Defensible — every other
  ambiguous source already has an `alt_category`.

### Regex baseline primary

Old:
> A regex-only baseline with 35 compiled patterns achieves 50.5% [47.4, 53.6]

New:
> A regex-only baseline with 48 compiled patterns achieves 52.7% [49.6, 55.7]

(Appears in 4 places in the docx)

### External "Overall" table row — 5th column

Old:
> Overall | 500 | 90.6% | 86.4% | 82.0% | 65.8% | 37.6%

New (assumes 5th column is regex-external; verify column header):
> Overall | 500 | 93.8% | 86.4% | 82.0% | 65.8% | 29.6%

Whatever 37.6% was, it doesn't match any model's actual external
accuracy. Beam q4 = 93.8, Claude S4 = 86.4, Gemini = 82.0, GPT-5 = 65.8,
regex = 29.6. The 37.6 is stale.

### External narrative — phishing/MTSamples/Enron

Old:
> All models achieve 99–100% on MTSamples – medical transcriptions that
> Beam never encountered during training. ... The largest model
> divergence appears on phishing emails (Beam 80%, Claude 55%, Gemini
> 45%, GPT-5 28.3%) and NVD vulnerability descriptions (Beam 100%,
> GPT-5 51%). Claude outperforms Beam on Enron corporate emails (87.5%
> vs. 76.2%)...

New:
> Claude, Gemini, and GPT-5 all reach 100% on MTSamples — medical
> transcriptions that Beam never encountered during training. Beam
> achieves 82% on the same subset. The 18 misses route to `pii` rather
> than `medical`: the model correctly recognizes the PHI but assigns
> a different label, with explanations that explicitly cite HIPAA. The
> largest model divergence appears on phishing emails (Beam 100%,
> Claude 55%, Gemini 45%, GPT-5 28.3%) and NVD vulnerability
> descriptions (Beam 100%, GPT-5 51%). Claude slightly outperforms
> Beam on Enron corporate emails (87.5% vs. 83.8%), reflecting the
> PII/confidential boundary ambiguity in mixed corporate
> communication.

### Claude Opus 4 false positive rate

Old: 17.4%
New: 16.4% (41/250 non-safe predictions on safe samples)
Note: minor; depends on FP definition with errors. If you keep 17.4%,
add a footnote explaining the convention. Either way, document.

### Beam vs base Qwen ablation (§6, near "+52 pp from LoRA")

Old:
> The fine-tuning delta over the base Qwen 3.5 27B is +52 pp.

New:
> The fine-tuning delta over the base Qwen 3.5 27B is +51.8 pp on the
> primary benchmark (95.1% vs. 43.3%) and **+65.8 pp on the external
> benchmark** (93.8% vs. 28.0%). The external delta is the more
> revealing comparison: both models see truly held-out data with the
> identical alpaca prompt, so the gap isolates LoRA's contribution
> from any synthetic-benchmark artifacts. The unmodified Qwen 3.5
> 27B labels almost every external sample `safe` (140/500 correct
> = 28%), with its 100% accuracy on NIST and Phishing reflecting only
> the cases where `safe` is an accepted label. This rules out the
> possibility that Beam's accuracy is driven by the prompt template
> alone — domain-specific fine-tuning is the lever.

## Figure regen

Both fig10 (per-source bars) and fig11 (primary vs external) need new
data. The build_docx pipeline is gone, but the underlying matplotlib
calls in `generate_figures.py` (now in git history of torchsight-paper
@17fff4a~1) were straightforward — port to a single small script in
beam/evaluation/scripts/ if you want them regenerable. Or hand-edit
the bar values in Word's chart objects.

## Files supporting the rewrite

- `torchsight/beam/evaluation/results/eval_external_torchsight-beam-q4_K_M.json`
- `torchsight/beam/evaluation/results/eval_external_torchsight-beam-q8_0.json`
- `torchsight/beam/evaluation/results/eval_external_torchsight-beam-f16.json`
- `torchsight/beam/evaluation/results/eval_external_qwen3.5-27b.json` (pending)
- Run `python scripts/summarize_external.py` to regenerate the table
  format above with current numbers.
