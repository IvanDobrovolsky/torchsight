"""
Master script — downloads all public datasets for TorchSight training.

All datasets have been verified to permit research and model training.
See docs/CORPUS.md for full license audit.

Datasets:
  1. Enron Email Corpus     — PII, corporate (public domain, FERC)
  2. SecLists               — injection payloads (MIT)
  3. MITRE ATT&CK           — threat patterns (royalty-free)
  4. NVD (NIST)             — vulnerability data (public domain)
  5. CIA FOIA               — declassified intelligence (public domain)
  6. CRS Reports            — defense analysis (public domain)
  7. Army Doctrine           — military publications (public domain)
  8. GAO Reports            — defense audits (public domain)
  9. DTIC                   — defense technical reports (public domain)
  10. ai4privacy            — 300K PII-labeled examples (Apache 2.0)
  11. Phishing Dataset      — phishing email/SMS text (Apache 2.0)
  12. SEC EDGAR             — financial filings (public domain)
  13. Fenrir v2.0           — cybersecurity dataset (Apache 2.0)
  14. PayloadsAllTheThings  — web attack payloads (MIT)
  15. NIST Training         — cybersecurity training (public domain)
  16. Loghub                — system log datasets (research)

Excluded (license issues):
  - MIMIC-III: PhysioNet DUA prohibits LLM training
  - Exploit-DB: GPL v2, derivative work status unclear

Not automated (require manual access):
  - CourtListener: https://www.courtlistener.com/api/ (API access)
  - MIDV-500: https://arxiv.org/abs/1807.05786 (request from authors)

Usage:
  python download_all.py                    # download all
  python download_all.py --skip enron       # skip large downloads
  python download_all.py --only military    # only military datasets
  python download_all.py --only new         # only new HuggingFace datasets
"""

import argparse
import importlib
import sys

DATASETS = [
    ("enron", "download_enron", "Enron Email Corpus (~1.7GB)", "public_domain"),
    ("seclists", "download_seclists", "SecLists (~200MB)", "MIT"),
    ("mitre", "download_mitre", "MITRE ATT&CK CTI (~50MB)", "royalty_free"),
    ("nvd", "download_nvd", "NVD CVE Feeds (~50MB)", "public_domain"),
    ("cia_foia", "download_cia_foia", "CIA FOIA Declassified (~10MB)", "public_domain"),
    ("crs", "download_crs", "CRS Defense Reports (~20MB)", "public_domain"),
    ("army", "download_army_doctrine", "Army Doctrine Publications (~50MB)", "public_domain"),
    ("gao", "download_gao", "GAO Defense/Nuclear Reports (~10MB)", "public_domain"),
    ("dtic", "download_dtic", "DTIC Public Reports (~10MB)", "public_domain"),
    ("ai4privacy", "download_ai4privacy", "ai4privacy PII-masking-300k", "Apache_2.0"),
    ("phishing", "download_phishing", "Phishing Email/SMS Dataset", "Apache_2.0"),
    ("edgar", "download_edgar", "SEC EDGAR Filings (5K samples)", "public_domain"),
    ("fenrir", "download_fenrir", "Fenrir Cybersecurity v2.0", "Apache_2.0"),
    ("payloads", "download_payloads", "PayloadsAllTheThings (~200MB)", "MIT"),
    ("nist_training", "download_nist_training", "NIST Cybersecurity Training", "public_domain"),
    ("loghub", "download_loghub", "Loghub System Logs", "research"),
    ("prompt_injection", "download_prompt_injection", "Prompt Injection Datasets (HF)", "Apache_2.0"),
]

# Group tags for --only flag
GROUPS = {
    "military": {"cia_foia", "crs", "army", "gao", "dtic"},
    "security": {"seclists", "mitre", "nvd", "payloads", "fenrir", "nist_training"},
    "pii": {"enron", "ai4privacy", "phishing"},
    "new": {"ai4privacy", "phishing", "edgar", "fenrir", "payloads", "nist_training", "loghub", "prompt_injection"},
}


def main():
    parser = argparse.ArgumentParser(description="Download TorchSight training datasets")
    parser.add_argument("--skip", nargs="*", default=[], help="Datasets to skip")
    parser.add_argument("--only", nargs="*", default=[], help="Only download these (supports group names: military, security, pii)")
    args = parser.parse_args()

    print()
    print("  TorchSight Dataset Downloader")
    print("  ─────────────────────────────")
    print("  All datasets verified for training/research use")
    print()

    skip = set(args.skip)

    # Resolve group names
    only = set()
    if args.only:
        for name in args.only:
            if name in GROUPS:
                only.update(GROUPS[name])
            else:
                only.add(name)

    for name, module_name, desc, license_type in DATASETS:
        if name in skip:
            print(f"  [SKIP] {desc}")
            continue
        if only and name not in only:
            continue

        print(f"\n  ── {desc} [{license_type}] ──")
        try:
            mod = importlib.import_module(module_name)
            mod.download()
        except Exception as e:
            print(f"  [FAIL] {name}: {e}")
            continue

    print()
    print("  ── Manual Downloads Required ──")
    print("  CourtListener:  https://www.courtlistener.com/api/  (public domain)")
    print("  MIDV-500:       https://arxiv.org/abs/1807.05786    (CC/public domain)")
    print()
    print("  ── Excluded (license issues) ──")
    print("  MIMIC-III:      PhysioNet DUA prohibits LLM training")
    print("  Exploit-DB:     GPL v2, derivative work status unclear")
    print()


if __name__ == "__main__":
    sys.path.insert(0, ".")
    main()
