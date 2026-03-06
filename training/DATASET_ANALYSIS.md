# TorchSight Training Dataset

## Summary

| Metric | Value |
|--------|-------|
| **Total samples** | 89,468 |
| **Real data** | 67,268 (75.2%) |
| **Synthetic data** | 22,200 (24.8%) |
| **Subcategories** | 49 |
| **Min per subcategory** | 500+ |
| **All licenses verified** | Yes |

## Data Sources

| Source | Samples | License | Type |
|--------|---------|---------|------|
| NVD (CVEs 1988-2026) | 50,000 | Public Domain | Vulnerability descriptions |
| OSSF Malicious Packages | 5,000 | Apache-2.0 | Supply chain attacks (npm/pypi) |
| SecLists (Payloads) | 3,229 | MIT | XSS, SQLi, XXE, cmd injection |
| GitHub Advisories (GHSA) | 3,000 | CC-BY-4.0 | Security advisories |
| Enron (Emails) | 2,000 | Public Domain (FERC) | PII, credentials, financial |
| MTSamples (Medical) | 2,000 | CC0 | Medical records + injected PII |
| MITRE ATT&CK | 1,620 | Apache-2.0 | Techniques, malware profiles |
| deepset Prompt Injection | 263 | Apache-2.0 | Prompt injection attacks |
| CRS Reports (Defense) | 156 | Public Domain (17 USC) | Military/classified content |
| **Synthetic Generated** | **22,200** | Generated | All categories |

### Excluded Datasets (License Issues)

| Dataset | License | Reason |
|---------|---------|--------|
| zefang-liu/phishing-email-dataset | LGPL-3.0 | Copyleft; ambiguous for AI training |
| hackaprompt/hackaprompt-dataset | MIT | Gated; requires HuggingFace auth |
| Samsung/CredData | Mixed per-file | 297 repos with unknown licenses |

## Taxonomy (49 subcategories)

### PII (6)
- pii.identity, pii.contact, pii.government_id, pii.biometric, pii.metadata, pii.behavioral

### Credentials (8)
- credentials.password, credentials.api_key, credentials.token, credentials.private_key
- credentials.connection_string, credentials.cloud_config, credentials.cicd, credentials.container

### Financial (4)
- financial.transaction, financial.credit_card, financial.bank_account, financial.tax

### Medical (4)
- medical.diagnosis, medical.prescription, medical.lab_result, medical.insurance

### Confidential (9)
- confidential.internal, confidential.classified, confidential.military, confidential.military_comms
- confidential.intelligence, confidential.weapons_systems, confidential.nuclear
- confidential.geospatial, confidential.education

### Malicious (14)
- malicious.exploit, malicious.injection, malicious.malware, malicious.phishing
- malicious.prompt_injection, malicious.supply_chain, malicious.shell, malicious.xxe
- malicious.ssti, malicious.ssrf, malicious.deserialization, malicious.redos
- malicious.steganography, malicious.prototype_pollution

### Safe (4)
- safe.code, safe.documentation, safe.config, safe.media

## Pipeline

```
download scripts (download_*.py)
        |
        v
raw data (training/data/raw/, training/data/ghsa/, etc.)
        |
        v
processors (*_processor.py) + synth_generator.py
        |
        v
processed JSONL (training/data/processed/*.jsonl + training/data/synthetic/*.jsonl)
        |
        v
process_all.py → combined_train.jsonl (89,468 samples)
        |
        v
sft_converter.py → train_alpaca.jsonl + val_alpaca.jsonl (or chatml)
        |
        v
train_lora.py → LoRA adapter
        |
        v
export_gguf.py → GGUF model → Ollama
```

## Scripts

| Script | Purpose |
|--------|---------|
| `download_nvd.py` | Download NVD CVE data (25 pages) |
| `download_crs.py` | Download CRS report PDFs |
| `download_ghsa.py` | Download GitHub Security Advisories |
| `download_ossf_malicious.py` | Download OSSF malicious packages |
| `processors/enron_processor.py` | Extract PII from Enron emails |
| `processors/seclists_processor.py` | Wrap payloads in realistic contexts |
| `processors/mitre_processor.py` | Process MITRE ATT&CK STIX data |
| `processors/nvd_processor.py` | Map CVEs to taxonomy via CWE |
| `processors/mtsamples_processor.py` | Process medical transcriptions |
| `processors/crs_processor.py` | Process CRS defense reports |
| `processors/prompt_injection_processor.py` | Process deepset prompt injections |
| `processors/ghsa_processor.py` | Process GitHub advisories |
| `processors/ossf_processor.py` | Process OSSF malicious packages |
| `processors/synth_generator.py` | Generate synthetic data (38 generators) |
| `processors/process_all.py` | Run all processors + combine |
| `sft_converter.py` | Convert to SFT format (alpaca/chatml) |
| `train_lora.py` | LoRA fine-tuning script |
| `export_gguf.py` | Merge + export to GGUF for Ollama |
