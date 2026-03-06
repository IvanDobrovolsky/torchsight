"""
Master script — downloads all public datasets for TorchSight training.

All datasets have been verified to permit research and model training.
See docs/CORPUS.md for full license audit.

Datasets:
  1. Enron Email Corpus     — PII, corporate (public domain, FERC)
  2. SecLists               — injection payloads (MIT)
  3. MITRE ATT&CK           — threat patterns (royalty-free)
  4. NVD (NIST)             — vulnerability data (public domain)
  5. MTSamples              — medical transcriptions (CC0)
  6. OWASP WSTG             — web attack patterns (CC BY-SA 4.0)
  7. CIA FOIA               — declassified intelligence (public domain)
  8. CRS Reports            — defense analysis (public domain)
  9. Army Doctrine           — military publications (public domain)
  10. GAO Reports            — defense audits (public domain)
  11. DTIC                   — defense technical reports (public domain)

Excluded (license issues):
  - MIMIC-III: PhysioNet DUA prohibits LLM training
  - Exploit-DB: GPL v2, derivative work status unclear

Not automated (require manual access):
  - SEC EDGAR: https://www.sec.gov/edgar/ (bulk download)
  - CourtListener: https://www.courtlistener.com/api/ (API access)
  - MIDV-500: https://arxiv.org/abs/1807.05786 (request from authors)

Usage:
  python download_all.py                    # download all
  python download_all.py --skip enron       # skip large downloads
  python download_all.py --only military    # only military datasets
"""

import argparse
import importlib
import sys

DATASETS = [
    ("enron", "download_enron", "Enron Email Corpus (~1.7GB)", "public_domain"),
    ("seclists", "download_seclists", "SecLists (~200MB)", "MIT"),
    ("mitre", "download_mitre", "MITRE ATT&CK CTI (~50MB)", "royalty_free"),
    ("nvd", "download_nvd", "NVD CVE Feeds (~50MB)", "public_domain"),
    ("mtsamples", "download_mtsamples", "MTSamples Medical (~5MB)", "CC0"),
    ("owasp", "download_owasp", "OWASP WSTG (~30MB)", "CC_BY_SA_4.0"),
    ("cia_foia", "download_cia_foia", "CIA FOIA Declassified (~10MB)", "public_domain"),
    ("crs", "download_crs", "CRS Defense Reports (~20MB)", "public_domain"),
    ("army", "download_army_doctrine", "Army Doctrine Publications (~50MB)", "public_domain"),
    ("gao", "download_gao", "GAO Defense/Nuclear Reports (~10MB)", "public_domain"),
    ("dtic", "download_dtic", "DTIC Public Reports (~10MB)", "public_domain"),
]

# Group tags for --only flag
GROUPS = {
    "military": {"cia_foia", "crs", "army", "gao", "dtic"},
    "security": {"seclists", "mitre", "nvd", "owasp"},
    "pii": {"enron", "mtsamples"},
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
    print("  SEC EDGAR:      https://www.sec.gov/edgar/          (public domain)")
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
