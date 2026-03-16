# TorchSight Training Pipeline

## Quick Start

```bash
cd training
uv venv && source .venv/bin/activate
uv pip install requests tqdm datasets beautifulsoup4 lxml

# Download all datasets
python scripts/download_all.py

# Process, generate, balance, convert
python scripts/processors/process_all.py
python scripts/processors/synth_generator.py
python scripts/processors/hard_negatives_generator.py
python scripts/rebalance_dataset.py
python scripts/sft_converter.py

# Train (on GPU machine)
python scripts/train_lora.py
python scripts/export_gguf.py
```

## Directory Structure

```
training/
├── scripts/
│   ├── download_all.py              # master downloader (18 datasets)
│   ├── download_enron.py            # Enron emails (public domain)
│   ├── download_seclists.py         # SecLists payloads (MIT)
│   ├── download_mitre.py            # MITRE ATT&CK (royalty-free)
│   ├── download_nvd.py              # NVD/NIST CVEs (public domain)
│   ├── download_ai4privacy.py       # AI4Privacy PII (Apache 2.0)
│   ├── download_phishing.py         # Phishing dataset (Apache 2.0)
│   ├── download_edgar.py            # SEC EDGAR filings (Apache 2.0 / public domain)
│   ├── download_fenrir.py           # Fenrir cybersecurity (Apache 2.0)
│   ├── download_payloads.py         # PayloadsAllTheThings (MIT)
│   ├── download_nist_training.py    # NIST publications (public domain)
│   ├── download_loghub.py           # System logs (research-free)
│   ├── download_cia_foia.py         # CIA declassified (public domain)
│   ├── download_crs.py              # CRS defense reports (public domain)
│   ├── download_army_doctrine.py    # Army doctrine (public domain)
│   ├── download_ghsa.py             # GitHub Security Advisories (CC-BY 4.0)
│   ├── download_ossf_malicious.py   # OpenSSF malicious packages (Apache 2.0)
│   ├── processors/                  # Raw → JSONL processors
│   ├── rebalance_dataset.py         # Balance and augment
│   └── sft_converter.py             # Convert to ChatML/Alpaca format
├── data/
│   ├── raw/                         # downloaded originals (gitignored)
│   ├── processed/                   # normalized JSONL (gitignored)
│   ├── synthetic/                   # generated samples (gitignored)
│   └── sft/                         # final training format (gitignored)
└── README.md
```

## Dataset Summary

**Total: 78,358 balanced samples** (74,441 train / 3,917 val)

| Category | Samples | % |
|----------|---------|---|
| malicious | 29,157 | 37.2% |
| pii | 24,408 | 31.2% |
| safe | 12,488 | 15.9% |
| confidential | 10,739 | 13.7% |
| financial | 9,155 | 11.7% |
| credentials | 7,297 | 9.3% |
| medical | 3,398 | 4.3% |

## License Audit

All training data sources are verified safe for AI model training and publication:

- **Public domain (US Gov):** Enron, NVD, CIA FOIA, CRS, Army Doctrine, SEC EDGAR, NIST
- **Apache 2.0:** AI4Privacy, Phishing Dataset, Fenrir v2.0, OSSF
- **MIT:** SecLists, PayloadsAllTheThings
- **Royalty-free:** MITRE ATT&CK
- **CC-BY 4.0:** GHSA
- **Free for research:** Loghub

**Excluded:** OWASP (CC-BY-SA ShareAlike risk), MTSamples (provenance unclear), Exploit-DB (GPL), MIMIC-III (DUA prohibits)

## Documentation

- [Corpus Details](../docs/CORPUS.md) — full license audit, label taxonomy, annotation schema
- [Architecture](../docs/ARCHITECTURE.md) — system design, detection categories
