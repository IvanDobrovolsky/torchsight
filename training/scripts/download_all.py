"""
Master script — downloads all public datasets for TorchSight training.

Datasets:
  1. Enron Email Corpus     — PII, corporate (public domain)
  2. SecLists               — injection payloads (MIT)
  3. MITRE ATT&CK           — threat patterns (Apache 2.0)
  4. Exploit-DB             — exploit code (GPL v2)
  5. NVD (NIST)             — vulnerability data (public domain)
  6. MTSamples              — medical transcriptions (free)
  7. OWASP WSTG             — web attack patterns (Apache 2.0)

Not automated (require manual access):
  - MIMIC-III: https://physionet.org/content/mimiciii/ (credentialed)
  - SEC EDGAR: https://www.sec.gov/cgi-bin/browse-edgar (bulk download)
  - CourtListener: https://www.courtlistener.com/api/ (API access)
  - CIA FOIA: https://www.cia.gov/readingroom/ (manual search)
  - MIDV-500: https://arxiv.org/abs/1807.05786 (request from authors)
  - CMS: https://data.cms.gov (bulk download portal)

Usage:
  python download_all.py           # download all
  python download_all.py --skip enron   # skip large downloads
"""

import argparse
import importlib
import sys

DATASETS = [
    ("enron", "download_enron", "Enron Email Corpus (~1.7GB)"),
    ("seclists", "download_seclists", "SecLists (~200MB)"),
    ("mitre", "download_mitre", "MITRE ATT&CK CTI (~50MB)"),
    ("exploitdb", "download_exploitdb", "Exploit-DB (~600MB)"),
    ("nvd", "download_nvd", "NVD CVE Feeds (~50MB)"),
    ("mtsamples", "download_mtsamples", "MTSamples Medical (~5MB)"),
    ("owasp", "download_owasp", "OWASP WSTG (~30MB)"),
]


def main():
    parser = argparse.ArgumentParser(description="Download TorchSight training datasets")
    parser.add_argument("--skip", nargs="*", default=[], help="Datasets to skip")
    parser.add_argument("--only", nargs="*", default=[], help="Only download these")
    args = parser.parse_args()

    print()
    print("  TorchSight Dataset Downloader")
    print("  ─────────────────────────────")
    print()

    skip = set(args.skip)
    only = set(args.only) if args.only else None

    for name, module_name, desc in DATASETS:
        if name in skip:
            print(f"  [SKIP] {desc}")
            continue
        if only and name not in only:
            continue

        print(f"\n  ── {desc} ──")
        try:
            mod = importlib.import_module(module_name)
            mod.download()
        except Exception as e:
            print(f"  [FAIL] {name}: {e}")
            continue

    print()
    print("  ── Manual Downloads Required ──")
    print("  MIMIC-III:      https://physionet.org/content/mimiciii/")
    print("  SEC EDGAR:      https://www.sec.gov/cgi-bin/browse-edgar")
    print("  CourtListener:  https://www.courtlistener.com/api/")
    print("  CIA FOIA:       https://www.cia.gov/readingroom/")
    print("  MIDV-500:       https://arxiv.org/abs/1807.05786")
    print()


if __name__ == "__main__":
    sys.path.insert(0, ".")
    main()
