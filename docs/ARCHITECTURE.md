# TorchSight Architecture

## System Overview

```mermaid
graph TB
    subgraph CLI["CLI Interface"]
        REPL[Interactive REPL]
        ARGS[CLI Arguments]
    end

    subgraph Scanner["File Scanner"]
        DISC[Discovery] --> CLASS[Classifier]
        CLASS -->|text| TEXT_A[Text Analyzer]
        CLASS -->|image| IMG_A[Image Analyzer]
    end

    subgraph ImagePipeline["Image Analysis Pipeline"]
        OCR[Tesseract OCR] -->|extracted text| COMBINE[Combine]
        VISION[Vision Model] -->|description| COMBINE
        COMBINE --> LLM_IMG[Text Model Deep Analysis]
    end

    subgraph TextPipeline["Text Analysis Pipeline"]
        READ[Read File] --> LLM_TXT[Text Model Deep Analysis]
    end

    subgraph Models["Local LLM Layer · Ollama"]
        MISTRAL[mistral:7b — text analysis]
        LLAMA_V[llama3.2-vision — image description]
        CUSTOM[torchsight-v1 — fine-tuned · planned]
    end

    subgraph Output["Output"]
        REPORT[PDF / JSON / Markdown Report]
        SESSION[Session Memory — follow-up Q&A]
    end

    REPL --> DISC
    ARGS --> DISC
    TEXT_A --> TextPipeline
    IMG_A --> ImagePipeline
    LLM_TXT --> MISTRAL
    LLM_IMG --> MISTRAL
    VISION --> LLAMA_V
    LLM_IMG --> REPORT
    LLM_TXT --> REPORT
    REPORT --> SESSION
```

## Detection Categories

```mermaid
graph LR
    subgraph Categories
        PII[pii]
        CRED[credentials]
        FIN[financial]
        MED[medical]
        CONF[confidential]
        MAL[malicious]
        SAFE[safe]
    end

    PII --> PII_ID[identity]
    PII --> PII_CONTACT[contact]
    PII --> PII_GOV[government_id]
    PII --> PII_BIO[biometric]

    CRED --> CRED_PW[password]
    CRED --> CRED_API[api_key]
    CRED --> CRED_TOK[token]
    CRED --> CRED_PK[private_key]
    CRED --> CRED_CS[connection_string]

    FIN --> FIN_CC[credit_card]
    FIN --> FIN_BANK[bank_account]
    FIN --> FIN_TAX[tax]
    FIN --> FIN_TX[transaction]

    MED --> MED_DX[diagnosis]
    MED --> MED_RX[prescription]
    MED --> MED_LAB[lab_result]
    MED --> MED_INS[insurance]

    CONF --> CONF_CLS[classified]
    CONF --> CONF_INT[internal]
    CONF --> CONF_LEG[legal]
    CONF --> CONF_MIL[military]
    CONF --> CONF_EDU[education]

    MAL --> MAL_INJ[injection]
    MAL --> MAL_EXP[exploit]
    MAL --> MAL_SH[shell]
    MAL --> MAL_OBF[obfuscated]
    MAL --> MAL_PH[phishing]
    MAL --> MAL_MW[malware]
```

## Compliance Mapping

| Tag | Regulation | Triggered by |
|-----|-----------|-------------|
| GDPR | EU General Data Protection | Any PII of individuals |
| HIPAA | US Health Insurance Portability | Medical records, PHI |
| PCI-DSS | Payment Card Industry | Credit card numbers, CVVs |
| SOX | Sarbanes-Oxley | Financial records of public companies |
| FERPA | Family Educational Rights | Student records, transcripts |
| CCPA | California Consumer Privacy | PII of California residents |
| ITAR | Int'l Traffic in Arms | Military/defense documents |
| EAR | Export Administration | Dual-use technology |

## Severity Levels

| Level | Meaning | Examples |
|-------|---------|---------|
| `critical` | Immediate exposure risk | Plaintext SSN, active API key, reverse shell |
| `warning` | Moderate risk, needs review | Partial PII, internal doc without markings |
| `info` | Low risk or clean | Safe file classification |

## Tech Stack

| Component | Technology |
|-----------|-----------|
| CLI | Rust, clap, dialoguer, indicatif |
| LLM inference | Ollama (local) |
| Text model | mistral:7b (→ torchsight-v1) |
| Vision model | llama3.2-vision |
| OCR | Tesseract |
| Reports | genpdf (PDF), serde_json |
| Training | Python, HuggingFace transformers, PEFT/LoRA |

## Inference Requirements

| Tier | RAM | GPU | Speed (1000 files) |
|------|-----|-----|---------------------|
| Minimum | 8 GB | CPU only | ~12 hours |
| Recommended | 16 GB | 8+ GB VRAM | ~1 hour |
| Optimal | 32 GB | 12+ GB VRAM | ~25 min |
