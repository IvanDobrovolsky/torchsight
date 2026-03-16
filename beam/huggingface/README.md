---
language:
- en
license: apache-2.0
task_categories:
- text-classification
tags:
- cybersecurity
- security
- pii-detection
- credential-detection
- malware
- prompt-injection
- compliance
- privacy
- llm-fine-tuning
- document-classification
size_categories:
- 100K<n<1M
pretty_name: TorchSight Security Classification Dataset
dataset_info:
  features:
  - name: messages
    list:
    - name: role
      dtype: string
    - name: content
      dtype: string
  splits:
  - name: train
    num_examples: 99910
  - name: validation
    num_examples: 5258
configs:
- config_name: chatml
  data_files:
  - split: train
    path: data/train_chatml.jsonl
  - split: validation
    path: data/val_chatml.jsonl
- config_name: alpaca
  data_files:
  - split: train
    path: data/train_alpaca.jsonl
  - split: validation
    path: data/val_alpaca.jsonl
---

# TorchSight Security Classification Dataset

A 105K-sample instruction-tuning dataset for training LLMs to classify documents by security risk. Covers 7 categories and 51 subcategories spanning PII, credentials, financial records, medical data, classified/military content, malicious payloads, and safe files.

Built for [TorchSight](https://github.com/IvanDobrovolsky/torchsight), an on-premise security scanner that runs entirely locally.

## Quick Start

```python
from datasets import load_dataset

ds = load_dataset("torchsight/security-dataset", "chatml")
# or alpaca format:
# ds = load_dataset("torchsight/security-dataset", "alpaca")
```

## Dataset Schema

### ChatML Format (recommended for fine-tuning)

Each sample is a conversation with 3 messages:

| Role | Content |
|------|---------|
| `system` | Classification instructions with output schema |
| `user` | Document text to analyze |
| `assistant` | JSON array of findings |

### Assistant Response Schema

```json
[
  {
    "category": "malicious",
    "subcategory": "malicious.injection",
    "severity": "critical",
    "explanation": "SQL injection payload targeting login form..."
  }
]
```

### Alpaca Format

Fields: `instruction`, `input`, `output` — same content, flat structure.

## Statistics

| Split | Samples |
|-------|---------|
| Train | 99,910 |
| Validation | 5,258 |
| **Total** | **105,168** |

### Category Distribution

| Category | Samples | % |
|----------|---------|---|
| malicious | 66,205 | 59.4% |
| safe | 17,608 | 15.8% |
| credentials | 8,684 | 7.8% |
| pii | 7,697 | 6.9% |
| confidential | 5,703 | 5.1% |
| medical | 3,787 | 3.4% |
| financial | 2,073 | 1.9% |

### Severity Distribution

| Severity | Samples |
|----------|---------|
| warning | 55,063 |
| critical | 32,444 |
| info | 17,608 |
| high | 5,446 |
| medium | 974 |
| low | 222 |

### Subcategories (51)

<details>
<summary>Full subcategory list</summary>

**PII (6):** pii.identity, pii.contact, pii.government_id, pii.biometric, pii.metadata, pii.behavioral

**Credentials (8):** credentials.password, credentials.api_key, credentials.token, credentials.private_key, credentials.connection_string, credentials.cloud_config, credentials.cicd, credentials.container

**Financial (4):** financial.transaction, financial.credit_card, financial.bank_account, financial.tax

**Medical (4):** medical.diagnosis, medical.prescription, medical.lab_result, medical.insurance

**Confidential (9):** confidential.internal, confidential.classified, confidential.military, confidential.military_comms, confidential.intelligence, confidential.weapons_systems, confidential.nuclear, confidential.geospatial, confidential.education

**Malicious (14):** malicious.exploit, malicious.injection, malicious.malware, malicious.phishing, malicious.prompt_injection, malicious.supply_chain, malicious.shell, malicious.xxe, malicious.ssti, malicious.ssrf, malicious.deserialization, malicious.redos, malicious.steganography, malicious.prototype_pollution

**Safe (6):** safe.code, safe.documentation, safe.config, safe.media, safe.email, safe.business

</details>

## Data Sources

All sources are public domain or permissively licensed. No copyleft (GPL/LGPL) data is included.

| Source | Samples | License |
|--------|---------|---------|
| NVD (CVEs 1988–2026) | 50,000 | Public Domain |
| OSSF Malicious Packages | 5,000 | Apache-2.0 |
| SecLists (Payloads) | 3,229 | MIT |
| GitHub Advisories (GHSA) | 3,000 | CC-BY-4.0 |
| Enron Emails | 2,000 | Public Domain (FERC) |
| MTSamples (Medical) | 2,000 | CC0 |
| MITRE ATT&CK | 1,620 | Apache-2.0 |
| deepset Prompt Injection | 263 | Apache-2.0 |
| CRS Reports (Defense) | 156 | Public Domain (17 USC §105) |
| Synthetic Generated | 22,200 | — |

### Excluded Sources

| Dataset | License | Reason |
|---------|---------|--------|
| zefang-liu/phishing-email-dataset | LGPL-3.0 | Copyleft; ambiguous for AI training |
| hackaprompt/hackaprompt-dataset | MIT (gated) | Requires HuggingFace auth |
| Samsung/CredData | Mixed per-file | Unknown licenses across 297 repos |

## Intended Use

- Fine-tuning LLMs for on-premise security scanning and document classification
- Research on LLM-based cybersecurity detection
- Building privacy-preserving security tools that run locally

## Limitations

- English only
- Biased toward malicious samples (59.4%) — use with balanced sampling if needed
- Synthetic data (36%) may not capture all real-world patterns
- Medical and financial categories are smaller — augment for production use

## Citation

```bibtex
@dataset{torchsight_security_2026,
  title={TorchSight Security Classification Dataset},
  author={Dobrovolsky, Ivan},
  year={2026},
  url={https://huggingface.co/datasets/torchsight/security-dataset},
  license={Apache-2.0}
}
```
