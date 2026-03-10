# TorchSight Training Corpus

## Dataset Pipeline

```mermaid
graph LR
    subgraph Public["Public Datasets (18 sources)"]
        ENRON[Enron Emails]
        SECLISTS[SecLists]
        MITRE[MITRE ATT&CK]
        NVD[NVD/NIST]
        EDGAR[SEC EDGAR]
        CIA[CIA FOIA]
        CRS[CRS Reports]
        ARMY[Army Doctrine]
        AI4P[AI4Privacy 300K]
        PHISH[Phishing Dataset]
        FENRIR[Fenrir v2.0]
        PAYLOADS[PayloadsAllTheThings]
        NIST[NIST Training]
        LOGHUB[Loghub]
        GHSA[GitHub Security Advisories]
        OSSF[OpenSSF Malicious Packages]
    end

    subgraph Synthetic["Synthetic Generation"]
        SYNTH_MIL[Military ops / intel]
        SYNTH_TAX[Tax returns]
        SYNTH_HR[HR records]
        SYNTH_EDU[Student records]
        SYNTH_CRED[Cloud / CI-CD / container secrets]
        SYNTH_MODERN[Prompt injection / supply chain / SSRF]
        SYNTH_CLEAN[Clean files]
    end

    Public --> INGEST[Ingest & Normalize]
    Synthetic --> INGEST
    INGEST --> LABEL[Auto-label with prompt-based TorchSight]
    LABEL --> REVIEW[Human Review & Correction]
    REVIEW --> DATASET[(Labeled Dataset · JSONL)]
    DATASET --> SPLIT{Split}
    SPLIT -->|80%| TRAIN[Train]
    SPLIT -->|10%| VAL[Validation]
    SPLIT -->|10%| TEST[Test / Benchmark]
```

## Sources & License Audit

> Every dataset used for training has been verified to permit research and model training.

### Confirmed — Licensed for Training

| Source | Domain | License | Training OK | Records Used | URL |
|--------|--------|---------|-------------|-------------|-----|
| Enron Email Corpus | Corporate, PII | **Public domain** (FERC release) | Yes | 2,000 | https://www.cs.cmu.edu/~enron/ |
| SecLists | Malicious payloads | **MIT** | Yes | 3,229 | https://github.com/danielmiessler/SecLists |
| MITRE ATT&CK | Threat patterns | **Royalty-free** (research/dev/commercial) | Yes (with copyright notice) | 1,620 | https://github.com/mitre/cti |
| NVD (NIST) | Vulnerabilities | **Public domain** (US Gov) | Yes | 3,000 (capped) | https://nvd.nist.gov/vuln/data-feeds |
| SEC EDGAR (via HF) | Financial filings | **Apache 2.0** (HF) / **Public domain** (SEC) | Yes | 3,000 | https://huggingface.co/datasets/eloukas/edgar-corpus |
| CIA FOIA Reading Room | Intelligence, Gov | **Public domain** (US Gov) | Yes | ~100 | https://www.cia.gov/readingroom/ |
| CRS Reports | Defense analysis | **Public domain** (US Gov) | Yes | 157 | https://crsreports.congress.gov/ |
| Army Doctrine (ADP/FM) | Military operations | **Public domain** (US Gov) | Yes | 4 | https://armypubs.army.mil/ |
| AI4Privacy | PII detection | **Apache 2.0** | Yes | 5,000 | https://huggingface.co/datasets/ai4privacy/pii-masking-300k |
| Phishing Dataset | Phishing/legitimate emails | **Apache 2.0** | Yes | 3,000 | https://huggingface.co/datasets/ealvaradob/phishing-dataset |
| Fenrir v2.0 | Cybersecurity (OWASP/ATT&CK) | **Apache 2.0** | Yes | 5,000 | https://huggingface.co/datasets/AlicanKiraz0/Cybersecurity-Dataset-Fenrir-v2.0 |
| PayloadsAllTheThings | Attack payloads | **MIT** | Yes | 170 | https://github.com/swisskyrepo/PayloadsAllTheThings |
| NIST Cybersecurity Training | NIST publications | **Public domain** (US Gov) | Yes | 3,000 | https://huggingface.co/datasets/ethanolivertroy/nist-cybersecurity-training |
| Loghub | System logs | **Free for research** (with attribution) | Yes | 1,280 | https://github.com/logpai/loghub |
| GHSA | Security advisories | **CC-BY 4.0** | Yes (with attribution) | pending | https://github.com/github/advisory-database |
| OSSF Malicious Packages | Supply chain attacks | **Apache 2.0** | Yes | pending | https://github.com/ossf/malicious-packages |

### Excluded — License Issues

| Source | Reason for Exclusion |
|--------|---------------------|
| ~~OWASP WSTG~~ | CC BY-SA 4.0. ShareAlike clause may apply to model weights — Creative Commons' own legal primer (May 2025) states SA conditions apply to trained models. Unacceptable risk for publication. Replaced with Fenrir v2.0 + PayloadsAllTheThings for web attack coverage. |
| ~~MTSamples~~ | CC0 claim is from a Kaggle uploader who scraped mtsamples.com. Original site terms say "educational purposes" only. Provenance chain unclear — replaced with synthetic medical data. |
| ~~MIMIC-III~~ | PhysioNet DUA **explicitly prohibits** sharing data with LLM services. |
| ~~Exploit-DB~~ | GPL v2. Whether model training creates a "derivative work" under GPL is legally debated. Replaced with NVD + Fenrir + PayloadsAllTheThings. |

### Notes on Specific Datasets

- **AI4Privacy**: Apache 2.0 licensed, 300K synthetic PII examples across 54 PII classes. Largest PII training source.
- **MITRE ATT&CK**: License requires reproducing MITRE copyright notice. We include this in our dataset metadata.
- **Fenrir v2.0**: Apache 2.0, covers OWASP Top 10 + MITRE ATT&CK + NIST CSF. Replaces OWASP WSTG.
- **Loghub**: Free for research with attribution (cite the paper). 16 system log sources.
- **US Government works**: Per 17 U.S.C. § 105, works of the US Government are not subject to copyright. This covers CIA FOIA, NVD, SEC EDGAR, CRS Reports, Army doctrine, and NIST publications.

## Military / Defense / Intelligence Sources (all public domain)

These US Government sources provide real documents with classification markings, military terminology, and intelligence formats:

| Source | What It Provides | Coverage |
|--------|-----------------|----------|
| CIA FOIA Reading Room | Declassified intelligence reports with original classification markings | `confidential.classified`, `confidential.intelligence` |
| CRS Reports | Congressional defense analysis — weapons programs, force structure, budget | `confidential.weapons_systems`, `confidential.military` |
| DTIC Public Reports | Defense technical reports, after-action reviews | `confidential.military`, `confidential.military_comms` |
| Army Doctrine (ADP/FM/ATP) | OPORD format, MDMP, tactical terminology, coordinate systems | `confidential.military_comms`, `confidential.geospatial` |
| GAO Defense Reports | Audits of weapons programs, nuclear enterprise, intelligence community | `confidential.weapons_systems`, `confidential.nuclear` |
| DNI Declassified Docs | Declassified NIEs, PDBs, intelligence assessments | `confidential.intelligence`, `confidential.classified` |

### Synthetic (33,100 generated samples)

| Domain | What | Count |
|--------|------|-------|
| Credentials | API keys, tokens, private keys, connection strings, cloud config, CI/CD, container secrets | 6,000 |
| Confidential | Classified, military ops/comms, weapons systems, intelligence, geospatial, nuclear, education | 5,700 |
| Malicious | Prompt injection, supply chain, SSRF, SSTI, XXE, ReDoS, shell, deserialization, steganography, prototype pollution, phishing | 9,900 |
| Financial | Credit cards, bank accounts, tax returns | 2,600 |
| Medical | Insurance, lab results | 1,400 |
| PII | Government IDs, biometric, metadata, behavioral | 2,900 |
| Safe | Documentation, code, config, media | 5,000 |

### Hard Negatives (6,400 boundary-case samples)

| Type | What | Count |
|------|------|-------|
| Safe-looking dangerous | Hidden credentials, subtle prompt injection, social engineering, obfuscated attacks, casual financial, unexpected PII | 3,000 |
| Dangerous-looking safe | Tutorial credentials, pentest reports, test code, safe configs, public records | 2,500 |
| Boundary cases | Multi-category docs, partial redaction, decodable tokens (JWT/base64 with PII) | 900 |

## Label Taxonomy

### Category (L1) → Subcategory (L2)

```
pii
  ├── pii.identity           name, DOB, SSN, gender, nationality
  ├── pii.contact            phone, email, address
  ├── pii.government_id      driver's license, passport, national ID
  ├── pii.biometric          fingerprint, face photo, iris scan
  ├── pii.metadata           EXIF GPS, PDF author, Office properties
  └── pii.behavioral         browsing history, search queries, location traces

credentials
  ├── credentials.password          plaintext or hashed passwords
  ├── credentials.api_key           AWS, GCP, Stripe, etc.
  ├── credentials.token             OAuth, JWT, session tokens
  ├── credentials.private_key       SSH, PGP, TLS keys
  ├── credentials.connection_string database URIs, JDBC
  ├── credentials.cloud_config      AWS/GCP/Azure configs, terraform state
  ├── credentials.cicd              GitHub Actions, Jenkins, GitLab CI secrets
  └── credentials.container         Dockerfile ENV, K8s secrets, Helm values

financial
  ├── financial.credit_card    card numbers, CVV, expiry
  ├── financial.bank_account   account/routing numbers
  ├── financial.tax            W-2, 1099, tax returns
  └── financial.transaction    invoices, payments, wire transfers

medical
  ├── medical.diagnosis        conditions, diseases
  ├── medical.prescription     medications, dosages
  ├── medical.lab_result       blood work, imaging
  └── medical.insurance        policy numbers, claims

confidential
  ├── confidential.classified      TOP SECRET / SECRET / CONFIDENTIAL
  ├── confidential.internal        internal-only corporate docs
  ├── confidential.legal           NDAs, contracts, attorney-client
  ├── confidential.military        operations, coordinates, force disposition
  ├── confidential.military_comms  OPORDs, FRAGOs, SITREPs, INTREPs
  ├── confidential.weapons_systems weapons specs, export-controlled data
  ├── confidential.intelligence    HUMINT, SIGINT, IMINT, OSINT reports
  ├── confidential.geospatial      MGRS coordinates, targeting data, imagery
  ├── confidential.nuclear         RD, FRD, CNWDI, NNPI
  └── confidential.education       FERPA-protected student records

malicious
  ├── malicious.injection            SQLi, XSS, command injection
  ├── malicious.exploit              buffer overflow, RCE, PoC
  ├── malicious.shell                reverse shell, web shell, backdoor
  ├── malicious.obfuscated           base64 payloads, encoded shellcode
  ├── malicious.phishing             fake login, credential harvesting
  ├── malicious.malware              C2 beacon, keylogger, ransomware
  ├── malicious.prompt_injection     LLM jailbreaks, indirect injection
  ├── malicious.supply_chain         dependency confusion, typosquatting
  ├── malicious.deserialization      pickle, YAML, Java deserialization
  ├── malicious.ssrf                 cloud metadata, internal service probes
  ├── malicious.redos                catastrophic backtracking regexes
  ├── malicious.steganography        hidden data in images/audio
  ├── malicious.prototype_pollution  __proto__ manipulation
  ├── malicious.xxe                  XML External Entity injection
  └── malicious.ssti                 server-side template injection

safe
  ├── safe.documentation       README, docs, manuals
  ├── safe.code                clean source code
  ├── safe.config              non-sensitive configuration
  └── safe.media               photos, artwork
```

### Severity (L3)

| Level | When |
|-------|------|
| `critical` | Immediate risk — exposed SSN, active API key, exploit code, classified data |
| `high` | Significant risk — credentials, internal documents, military data |
| `medium` | Moderate risk — partial PII, suspicious patterns, file metadata leaks |
| `low` | Minor risk — minimal exposure, public information with some sensitivity |
| `info` | Clean file or minimal exposure |

### Compliance Tags (L4, multi-label)

`GDPR` `HIPAA` `PCI-DSS` `SOX` `FERPA` `CCPA` `ITAR` `EAR` `EO-13526` `NIST-800-53` `NIST-800-171` `DoD-5220.22-M` `10-CFR-1045`

## Annotation Schema

```json
{
  "id": "enron-00421",
  "source": "enron",
  "source_license": "public_domain",
  "domain": "corporate",
  "input": {
    "type": "text | image",
    "filename": "meeting_notes.txt",
    "content": "...",
    "ocr_text": null,
    "vision_description": null
  },
  "findings": [
    {
      "category": "pii",
      "subcategory": "pii.identity",
      "severity": "critical",
      "description": "Email contains SSN and personal identity",
      "extracted_data": {
        "full_name": "John Smith",
        "ssn": "482-39-1843"
      },
      "compliance": ["GDPR", "CCPA"]
    }
  ],
  "metadata": {
    "annotator": "auto-v1 | human",
    "verified": false,
    "difficulty": "easy | medium | hard",
    "split": "train | val | test"
  }
}
```

## Dataset Composition (78,358 samples)

```mermaid
pie title Dataset by Category
    "malicious (injection, phishing, exploits, shells)" : 29157
    "pii (identity, contact, metadata)" : 24408
    "safe (docs, code, config, logs)" : 12488
    "confidential (classified, military, intel)" : 10739
    "financial (EDGAR filings, tax, credit cards)" : 9155
    "credentials (API keys, tokens, passwords)" : 7297
    "medical (diagnosis, prescription, insurance)" : 3398
```

### Data Sources Breakdown

| Source Type | Samples | % |
|------------|---------|---|
| Real data (13 public datasets) | 30,456 | 44.6% |
| Synthetic generation | 33,100 | 48.4% |
| Hard negatives (boundary cases) | 6,400 | 9.4% |
| Rebalance augmentation | ~6,900 | ~10% |

## Training Plan

```mermaid
graph TB
    DATA[(78K balanced samples)] --> LORA[LoRA Fine-tune]
    LORA --> BEAM[torchsight/beam v1.0]
    BEAM --> GGUF[Export GGUF Q8 + F16]
    GGUF --> OLLAMA[Ollama Registry]
    OLLAMA --> USER[User runs locally]

    subgraph Hardware
        LAMBDA[Lambda Cloud · 1x H100]
        TIME[~2-4 hours]
    end

    LORA --> LAMBDA
```
