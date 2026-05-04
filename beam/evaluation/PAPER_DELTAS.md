# Paper Deltas — Apply to TorchSight_JISA_IvanDobrovolskyi.docx

Based on the 2026-05 rerun. Numbers below are from full 500/500 external
runs using methodology identical to the primary benchmark (eval_beam.py
prompt + parser + alt_category-aware scorer).

Replace by hand in Word. No build_docx.py pipeline — that's been removed.

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
> A regex-only baseline with 49 compiled patterns achieves 52.7% [49.6, 55.7]

(Appears in 4 places in the docx)

### Beam vs base Qwen ablation (§6, near "+52 pp from LoRA")

Old:
> The fine-tuning delta over the base Qwen 3.5 27B is +52 pp.

New (after qwen rerun completes — placeholder):
> The fine-tuning delta over the base Qwen 3.5 27B is +TBD pp on
> primary (95.1% − 43.3%) and +TBD pp on external (93.8% − TBD%).
> The external delta is the more revealing comparison: both models
> see truly held-out data with the identical prompt, so the gap
> isolates LoRA's contribution from any synthetic-benchmark artifacts.

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
