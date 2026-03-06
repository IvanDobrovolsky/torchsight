# TorchSight Training Pipeline

## Quick Start

```bash
cd training/scripts
python download_all.py              # all datasets (~2.5GB)
python download_all.py --skip enron # skip large ones
python download_all.py --only seclists mtsamples  # specific ones
```

## Directory Structure

```
training/
├── scripts/
│   ├── download_all.py        # master downloader
│   ├── download_enron.py      # Enron emails (public domain)
│   ├── download_seclists.py   # SecLists payloads (MIT)
│   ├── download_mitre.py      # MITRE ATT&CK (Apache 2.0)
│   ├── download_exploitdb.py  # Exploit-DB (GPL v2)
│   ├── download_nvd.py        # NVD/NIST CVEs (public domain)
│   ├── download_mtsamples.py  # MTSamples medical (free)
│   └── download_owasp.py      # OWASP payloads (Apache 2.0)
├── data/
│   ├── raw/                   # downloaded originals (gitignored)
│   ├── processed/             # normalized JSONL (gitignored)
│   └── synthetic/             # generated samples (gitignored)
└── README.md
```

## Documentation

- [Architecture](../docs/ARCHITECTURE.md) — system design, detection categories, tech stack
- [Corpus](../docs/CORPUS.md) — dataset sources, label taxonomy, annotation schema
