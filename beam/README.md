# Beam -- TorchSight's Classification Model

LoRA fine-tuned LLM with adjusted weights built to detect cybersecurity threats, classify and describe documents locally on your machine.

[Ollama](https://ollama.com/torchsight/beam) | [HuggingFace](https://huggingface.co/torchsight)

## Model Overview

| | |
|---|---|
| **Name** | `torchsight/beam` |
| **Base model** | Qwen 3.5 27B (dense) |
| **Method** | LoRA fine-tuning (r=128, alpha=256) |
| **Epochs** | 5 |
| **Training data** | 78,358 balanced samples (74,441 train / 3,917 val) across 51 subcategories |
| **Training GPU** | H100 80GB PCIe (~55GB VRAM) |
| **Output formats** | GGUF q4\_K\_M (~17GB), q8\_0 (~28GB), f16 (~54GB) |
| **Inference** | temperature=0 (deterministic) |
| **License** | Apache 2.0 |

q4\_K\_M fits 32GB Apple Silicon. q8\_0 requires 48GB+ GPU or 64GB Mac.

---

## Taxonomy

7 categories, 51 subcategories.

```mermaid
%%{init: {'theme': 'base', 'themeVariables': {'primaryColor': '#7C3AED','primaryTextColor': '#EEEDF5','primaryBorderColor': '#6366F1','lineColor': '#38BDF8','secondaryColor': '#1A1926','tertiaryColor': '#222136','background': '#0F0E17','mainBkg': '#1A1926','nodeBorder': '#6366F1','clusterBkg': '#222136','titleColor': '#A855F7','edgeLabelBackground': '#1A1926'}}}%%

graph LR
    BEAM((Beam<br/>51 subcategories))

    MAL["Malicious (14)"]
    CONF["Confidential (9)"]
    CRED["Credentials (8)"]
    PII["PII (6)"]
    SAFE["Safe (6)"]
    FIN["Financial (4)"]
    MED["Medical (4)"]

    BEAM --- MAL
    BEAM --- CONF
    BEAM --- CRED
    BEAM --- PII
    BEAM --- SAFE
    BEAM --- FIN
    BEAM --- MED

    MAL --- M1["injection<br/>exploit<br/>shell<br/>phishing<br/>malware<br/>prompt_injection<br/>supply_chain"]
    MAL --- M2["deserialization<br/>ssrf · redos<br/>steganography<br/>prototype_pollution<br/>xxe · ssti"]
    CONF --- C1["classified · internal<br/>military · military_comms<br/>intelligence<br/>weapons_systems<br/>nuclear · geospatial<br/>education"]
    CRED --- CR1["password · api_key<br/>token · private_key<br/>connection_string<br/>cloud_config<br/>cicd · container"]
    PII --- P1["identity · contact<br/>government_id<br/>biometric<br/>metadata · behavioral"]
    SAFE --- S1["documentation · code<br/>config · media<br/>email · business"]
    FIN --- F1["credit_card<br/>bank_account<br/>tax · transaction"]
    MED --- MD1["diagnosis<br/>prescription<br/>lab_result · insurance"]

    style BEAM fill:#7C3AED,stroke:#6366F1,color:#EEEDF5
    style MAL fill:#DC2626,stroke:#DC2626,color:#EEEDF5
    style CONF fill:#6366F1,stroke:#6366F1,color:#EEEDF5
    style CRED fill:#EA580C,stroke:#EA580C,color:#EEEDF5
    style PII fill:#A855F7,stroke:#A855F7,color:#EEEDF5
    style SAFE fill:#059669,stroke:#059669,color:#EEEDF5
    style FIN fill:#D97706,stroke:#D97706,color:#EEEDF5
    style MED fill:#38BDF8,stroke:#06B6D4,color:#0F0E17
    style M1 fill:#222136,stroke:#DC2626,color:#EEEDF5
    style M2 fill:#222136,stroke:#DC2626,color:#EEEDF5
    style C1 fill:#222136,stroke:#6366F1,color:#EEEDF5
    style CR1 fill:#222136,stroke:#EA580C,color:#EEEDF5
    style P1 fill:#222136,stroke:#A855F7,color:#EEEDF5
    style S1 fill:#222136,stroke:#059669,color:#EEEDF5
    style F1 fill:#222136,stroke:#D97706,color:#EEEDF5
    style MD1 fill:#222136,stroke:#38BDF8,color:#EEEDF5
```

---

## Severity Levels

| Level | Criteria | Examples |
|-------|----------|----------|
| `critical` | Immediate exploitable risk. Direct exposure of sensitive data or active threat. | Plaintext SSN, active API key, reverse shell, full credit card, classified documents, nuclear data |
| `high` | Significant risk requiring urgent action. Credentials, military data, internal documents with sensitive content. | Database connection strings, OPORD with coordinates, weapons system specs |
| `medium` | Moderate risk requiring review. Partial exposure or suspicious patterns. | Name + DOB without SSN, internal document without classified content, ReDoS pattern |
| `low` | Minor risk. Minimal exposure, public information with some sensitivity. | Email address alone, file metadata with author name, safe-looking config with commented credentials |
| `info` | No risk. Clean file, safe content. | Documentation, clean source code, stock photos |

---

## Evaluation

1,000 text samples across all 7 categories, evaluated with identical system prompts and temperature=0.

| Model | Type | Category Accuracy | Subcategory Accuracy | Avg Time/Sample |
|---|---|---|---|---|
| **Beam q4_K_M** | Local (27B LoRA) | **95.1%** | **48.5%** | 4.4s |
| Beam f16 | Local (27B LoRA) | 93.0% | 51.3% | 4.6s |
| Beam q8_0 | Local (27B LoRA) | 92.7% | 51.3% | 3.2s |
| Claude Sonnet 4 | Commercial API | 79.9% | 23.0% | ~5.5s |
| Claude Opus 4 | Commercial API | 79.9% | 22.5% | ~22s |
| Gemini 2.5 Pro | Commercial API | 75.4% | 21.0% | ~10s |
| Qwen 3.5 27B (base) | Local (no fine-tune) | 43.3% | 4.3% | ~40s |

All three Beam quantizations (92.7--95.1%) outperform every commercial frontier model tested (75.4--79.9%) by 13--20 points. Fine-tuning adds ~52 percentage points over the base Qwen 3.5 27B model.

With the full TorchSight pipeline (Beam + Vision + OCR + regex safety net), accuracy reaches **97.6%** on 1,018 files (966 text + 52 images).

| Model | Cost per 1,000 files | Data leaves machine | Latency |
|---|---|---|---|
| **Beam (any quant)** | $0 | No | 3--5s/file |
| Claude Sonnet 4 | ~$3--5 | Yes | ~5.5s/file |
| Gemini 2.5 Pro | ~$5--10 | Yes | ~10s/file |
| Claude Opus 4 | ~$15--30 | Yes | ~22s/file |

---

## Training Data

### Sources (78,358 samples after rebalancing)

| Source | Samples | License | Provides |
|--------|---------|---------|----------|
| NVD (CVEs 1988-2026) | 50,000 | Public Domain (US Gov) | Vulnerability descriptions mapped to exploit taxonomy |
| AI4Privacy | 5,000 | Apache 2.0 | Synthetic PII across 54 PII classes |
| OSSF Malicious Packages | 5,000 | Apache 2.0 | npm/pypi supply chain attacks |
| Fenrir v2.0 | 5,000 | Apache 2.0 | OWASP Top 10 + ATT&CK + NIST CSF coverage |
| SecLists | 3,229 | MIT | XSS, SQLi, command injection, XXE payloads |
| GHSA (GitHub Advisories) | 3,000 | CC-BY 4.0 | Security advisories with CWE mapping |
| SEC EDGAR | 3,000 | Apache 2.0 / Public Domain | Financial filings, corporate disclosures |
| NIST Training | 3,000 | Public Domain (US Gov) | NIST cybersecurity publications |
| Phishing Dataset | 3,000 | Apache 2.0 | Phishing and legitimate email classification |
| Enron Emails | 2,000 | Public Domain (FERC) | Real corporate email with PII, credentials, financial data |
| MITRE ATT&CK | 1,620 | Royalty-free | Attack techniques, malware profiles |
| Loghub | 1,280 | Free for research | System logs from 16 sources |
| deepset Prompt Injection | 263 | Apache 2.0 | Prompt injection attacks in context |
| PayloadsAllTheThings | 170 | MIT | Web attack payloads |
| CRS Reports | 157 | Public Domain (US Gov) | Congressional defense/military/nuclear analysis |
| CIA FOIA | ~100 | Public Domain (US Gov) | Declassified intelligence with classification markings |
| Army Doctrine (ADP/FM) | 4 | Public Domain (US Gov) | OPORD format, tactical terminology, coordinate systems |
| **Synthetic** | **~33,100** | Generated | All categories (see breakdown below) |
| **Hard Negatives** | **~6,400** | Generated | Boundary cases, safe-looking-dangerous and vice versa |

### Synthetic Breakdown

| Domain | Count | Coverage |
|--------|-------|----------|
| Malicious | 9,900 | Prompt injection, supply chain, SSRF, SSTI, XXE, ReDoS, deserialization, steganography, shells, prototype pollution, phishing |
| Credentials | 6,000 | API keys, tokens, private keys, connection strings, cloud config, CI/CD, container secrets |
| Confidential | 5,700 | Classified docs, military ops/comms, weapons systems, intelligence, geospatial, nuclear, education |
| Safe | 5,000 | Documentation, code, config, media, email, business |
| PII | 2,900 | Government IDs, biometric, metadata, behavioral |
| Financial | 2,600 | Credit cards, bank accounts, tax returns |
| Medical | 1,400 | Insurance, lab results |

### Hard Negatives (~6,400 boundary cases)

| Type | Count | Purpose |
|------|-------|---------|
| Safe-looking dangerous | 3,000 | Hidden credentials, subtle prompt injection, obfuscated attacks |
| Dangerous-looking safe | 2,500 | Tutorial credentials, pentest reports, test code, public records |
| Boundary cases | 900 | Multi-category docs, partial redaction, decodable tokens (JWT/base64 with PII) |

---

## Training Pipeline

```mermaid
%%{init: {'theme': 'base', 'themeVariables': {'primaryColor': '#7C3AED','primaryTextColor': '#EEEDF5','primaryBorderColor': '#6366F1','lineColor': '#38BDF8','secondaryColor': '#1A1926','tertiaryColor': '#222136','background': '#0F0E17','mainBkg': '#1A1926','nodeBorder': '#6366F1','clusterBkg': '#222136','titleColor': '#A855F7','edgeLabelBackground': '#1A1926'}}}%%

graph LR
    A["Download<br/>18 sources"] --> B["Process<br/>9 processors"]
    B --> C["Synthetic<br/>40 generators"]
    C --> D["Hard Negatives<br/>boundary cases"]
    D --> E["Rebalance<br/>+ augment"]
    E --> F["SFT Convert<br/>ChatML format"]
    F --> G["LoRA Train<br/>r=128, 5 epochs"]
    G --> H["Export GGUF<br/>q4_K_M + q8_0"]
    H --> I["Ollama<br/>torchsight/beam"]
```

### LoRA Configuration

| Parameter | Value |
|-----------|-------|
| Rank (r) | 128 |
| Alpha | 256 |
| Target layers | All attention (q,k,v,o\_proj) + gate,up,down\_proj + lm\_head |
| Batch size | 4 x 4 grad accum = 16 effective |
| Learning rate | 2e-5 with cosine decay |
| Precision | bf16 |
| Optimizer | AdamW fused |
| Checkpoint selection | Best model by eval loss |
| Compatible stack | trl 0.11.4 + transformers 4.45.2 + peft 0.13.2 |

---

## Retrain

```bash
cd beam
./train.sh
```

Handles everything: venv setup, dependency install, data download, processing, synthetic generation, rebalancing, SFT conversion, LoRA training, and GGUF export. Auto-detects GPU count and VRAM to select the optimal training strategy.

Requires 80GB+ VRAM per GPU. Beam v1.0 was trained on 8x GH200.

---

## Output Format

The model outputs a JSON array of findings. Each finding has four fields:

```json
[
  {
    "category": "credentials",
    "subcategory": "credentials.api_key",
    "severity": "critical",
    "explanation": "AWS access key ID (AKIA...) found in environment configuration file"
  },
  {
    "category": "pii",
    "subcategory": "pii.identity",
    "severity": "high",
    "explanation": "Full name and Social Security number present in document header"
  }
]
```

For clean files:

```json
[
  {
    "category": "safe",
    "subcategory": "safe.documentation",
    "severity": "info",
    "explanation": "Standard API documentation with no sensitive content"
  }
]
```

---

## Compliance Tags (L4)

Multi-label compliance tags assigned alongside findings.

| Tag | Full Name | Triggered By |
|-----|-----------|--------------|
| `GDPR` | EU General Data Protection Regulation | Any PII (name, email, address, DOB, biometric) |
| `HIPAA` | Health Insurance Portability & Accountability Act | Any PHI (diagnosis, prescription, lab result, insurance) |
| `PCI-DSS` | Payment Card Industry Data Security Standard | Credit card numbers, CVVs, cardholder data |
| `SOX` | Sarbanes-Oxley Act | Financial records of public companies |
| `FERPA` | Family Educational Rights & Privacy Act | Student records, grades, enrollment data |
| `CCPA` | California Consumer Privacy Act | PII of California residents |
| `ITAR` | International Traffic in Arms Regulations | Military/defense technical data, weapons systems |
| `EAR` | Export Administration Regulations | Dual-use technology, encryption |
| `NIST-800-53` | NIST Security Controls | Government/military information systems |
| `NIST-800-171` | CUI Protection | Controlled Unclassified Information in non-federal systems |
| `EO-13526` | Classified National Security Information | Documents with classification markings (TS/S/C) |
| `DoD-5220.22-M` | National Industrial Security Program | Cleared contractor handling of classified info |
| `10-CFR-1045` | Nuclear Classification (DOE) | Restricted Data (RD), Formerly Restricted Data (FRD) |

---

## License

Apache 2.0. See [LICENSE](../LICENSE).

All training data sources are individually licensed for AI model training. See the training data table above for per-source license details. MITRE ATT&CK requires reproducing the MITRE copyright notice (included in dataset metadata). US Government works are not subject to copyright per 17 U.S.C. Section 105.
