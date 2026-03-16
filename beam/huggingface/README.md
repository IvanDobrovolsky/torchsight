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
- 10K<n<100K
pretty_name: TorchSight Security Classification Dataset
dataset_info:
  features:
  - name: instruction
    dtype: string
  - name: input
    dtype: string
  - name: output
    dtype: string
  splits:
  - name: train
    num_examples: 74441
  - name: validation
    num_examples: 3917
configs:
- config_name: default
  data_files:
  - split: train
    path: data/train_alpaca.jsonl
  - split: validation
    path: data/val_alpaca.jsonl
---

# TorchSight Security Classification Dataset

78,358 instruction-tuning samples for training LLMs to classify documents by security risk. 7 categories, 51 subcategories covering PII, credentials, financial records, medical data, classified/military content, malicious payloads, and safe files.

Built for [TorchSight](https://github.com/IvanDobrovolsky/torchsight), an on-premise security scanner that runs locally via [Ollama](https://ollama.com/torchsight/beam).

## Quick Start

```python
from datasets import load_dataset

ds = load_dataset("torchsight/security-dataset")
```

## Schema

Each sample has three fields (Alpaca format):

| Field | Content |
|-------|---------|
| `instruction` | Classification task prompt (7 randomized templates) |
| `input` | Document text to analyze |
| `output` | JSON array of findings |

### Output Format

```json
[
  {
    "category": "credentials",
    "subcategory": "credentials.api_key",
    "severity": "critical",
    "explanation": "AWS access key ID (AKIA...) found in config file"
  }
]
```

## Statistics

| Split | Samples |
|-------|---------|
| Train | 74,441 |
| Validation | 3,917 |
| **Total** | **78,358** |

### Category Distribution

| Category | Subcategories |
|----------|--------------|
| Malicious | injection, exploit, shell, phishing, malware, prompt_injection, supply_chain, deserialization, ssrf, redos, steganography, prototype_pollution, xxe, ssti |
| Confidential | classified, internal, military, military_comms, intelligence, weapons_systems, nuclear, geospatial, education |
| Credentials | password, api_key, token, private_key, connection_string, cloud_config, cicd, container |
| PII | identity, contact, government_id, biometric, metadata, behavioral |
| Safe | documentation, code, config, media, email, business |
| Financial | credit_card, bank_account, tax, transaction |
| Medical | diagnosis, prescription, lab_result, insurance |

## Data Sources

18 public sources, all permissively licensed (public domain, Apache 2.0, MIT, CC-BY 4.0). No copyleft data. Supplemented with synthetic samples and hard negatives for boundary cases.

Full source breakdown: [beam/README.md](https://github.com/IvanDobrovolsky/torchsight/blob/main/beam/README.md)

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
