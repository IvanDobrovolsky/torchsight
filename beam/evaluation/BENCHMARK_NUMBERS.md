# TorchSight benchmark numbers (canonical)

Auto-generated from `evaluation/results/*.json` — single source of truth.
Re-generate any time with: `python scripts/print_benchmark_numbers.py`.

## Eval-1000 (primary, n=1000)

| model | accuracy | 95% CI | subcat |
|---|---:|---|---:|
| Beam q4_K_M | 95.0% | [93.5, 96.2] | 48.2% |
| Beam f16 | 93.2% | [91.5, 94.6] | 51.1% |
| Beam q8_0 | 93.0% | [91.2, 94.4] | 51.4% |
| Sonnet 4 | 79.9% | [77.3, 82.3] | 23.0% |
| Opus 4 | 79.9% | [77.3, 82.3] | 22.5% |
| GPT-5 | 76.9% | [74.2, 79.4] | 11.6% |
| Gemini 2.5 | 75.4% | [72.6, 78.0] | 21.0% |
| Regex | 52.7% | [49.6, 55.8] | — |
| Qwen base | 86.3% | [84.0, 88.3] | 19.0% |

## Eval-500 (external held-out, n=500)

| model | accuracy | 95% CI |
|---|---:|---|
| Beam q4_K_M | 93.8% | [91.3, 95.6] |
| Beam f16 | 91.2% | [88.4, 93.4] |
| Beam q8_0 | 91.2% | [88.4, 93.4] |
| Sonnet 4 | 86.4% | [83.1, 89.1] |
| GPT-5 | 65.8% | [61.5, 69.8] |
| Gemini 2.5 | 82.0% | [78.4, 85.1] |
| Regex | 29.6% | [25.8, 33.7] |
| Qwen base | 86.6% | [83.3, 89.3] |

## Per-category (Eval-1000)

| category | Beam q4_K_M | GPT-5 | Sonnet 4 | Opus 4 | Gemini 2.5 |
|---|---:|---:|---:|---:|---:|
| Credentials | 96.0% | 99.3% | 100.0% | 100.0% | 100.0% |
| Pii | 100.0% | 88.7% | 90.0% | 87.3% | 89.3% |
| Financial | 100.0% | 63.0% | 61.0% | 63.0% | 63.0% |
| Medical | 68.0% | 48.0% | 40.0% | 55.0% | 80.0% |
| Confidential | 100.0% | 100.0% | 99.0% | 61.0% | 85.0% |
| Malicious | 95.3% | 98.7% | 98.0% | 96.7% | 100.0% |
| Safe | 98.0% | 51.2% | 66.8% | 77.6% | 36.8% |

## Beam q4_K_M precision / recall / F1 (Eval-1000)

| category | precision | recall | F1 |
|---|---:|---:|---:|
| credentials | 100.0% | 96.0% | 98.0% |
| pii | 87.2% | 100.0% | 93.2% |
| financial | 100.0% | 100.0% | 100.0% |
| medical | 100.0% | 68.0% | 81.0% |
| confidential | 90.9% | 100.0% | 95.2% |
| malicious | 92.9% | 95.3% | 94.1% |
| safe | 97.2% | 98.0% | 97.6% |
| **macro avg** | **95.5%** | **93.9%** | **94.1%** |

## Regex-only vs Beam q4_K_M (Eval-1000)

| category | regex | beam q4 | gap |
|---|---:|---:|---:|
| credentials | 84.0% | 96.0% | +12.0 pp |
| safe | 87.2% | 98.0% | +10.8 pp |
| pii | 52.0% | 100.0% | +48.0 pp |
| malicious | 38.0% | 95.3% | +57.3 pp |
| financial | 48.0% | 100.0% | +52.0 pp |
| confidential | 0.0% | 100.0% | +100.0 pp |
| medical | 0.0% | 68.0% | +68.0 pp |
| **Overall** | **52.7%** | **95.0%** | **+42.3 pp** |

## Eval-500 per-source (alt_category-aware scorer)

| source | n | Beam q4 | Sonnet 4 | Gemini 2.5 | GPT-5 | Qwen base |
|---|---:|---:|---:|---:|---:|---:|
| nvd_holdout | 100 | 100.0% | 98.0% | 97.0% | 51.0% | 97.0% |
| nist_holdout | 80 | 100.0% | 92.5% | 91.2% | 88.8% | 95.0% |
| mtsamples | 100 | 82.0% | 100.0% | 100.0% | 100.0% | 100.0% |
| ai4privacy_holdout | 80 | 100.0% | 71.2% | 63.7% | 65.0% | 67.5% |
| phishing_holdout | 60 | 100.0% | 55.0% | 45.0% | 28.3% | 68.3% |
| enron_holdout | 80 | 83.8% | 87.5% | 77.5% | 47.5% | 81.2% |
| **Overall** | **500** | **93.8%** | **86.4%** | **82.0%** | **65.8%** | **86.6%** |

## False-positive rates on safe documents (Eval-1000)

Computed as 1 − (safe accuracy). Operationally critical for DLP usability.

| model | FP rate |
|---|---:|
| Beam q4_K_M | 2.0% |
| Beam f16 | 7.2% |
| Beam q8_0 | 8.0% |
| Opus 4 | 22.4% |
| Sonnet 4 | 33.2% |
| Qwen base | 21.2% |
| GPT-5 | 48.8% |
| Gemini 2.5 | 63.2% |