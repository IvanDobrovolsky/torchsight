#!/usr/bin/env python3
"""
MTSamples Processor for TorchSight Training

Processes medical transcriptions, injects synthetic PII,
classifies by content type, and outputs labeled JSONL.

Targets: medical.diagnosis, medical.prescription, medical.lab_result
"""

import csv
import json
import random
import re
import sys
from pathlib import Path

RAW_DIR = Path(__file__).parent.parent.parent / "data" / "raw"
OUT_DIR = Path(__file__).parent.parent.parent / "data" / "processed"

# Synthetic PII pools for injection
FIRST_NAMES = [
    "James", "Mary", "Robert", "Patricia", "John", "Jennifer", "Michael", "Linda",
    "David", "Elizabeth", "William", "Barbara", "Richard", "Susan", "Joseph", "Jessica",
    "Thomas", "Sarah", "Christopher", "Karen", "Daniel", "Lisa", "Matthew", "Nancy",
    "Anthony", "Betty", "Mark", "Margaret", "Donald", "Sandra", "Steven", "Ashley",
    "Andrew", "Dorothy", "Kenneth", "Kimberly", "Joshua", "Emily", "Kevin", "Donna",
]

LAST_NAMES = [
    "Smith", "Johnson", "Williams", "Brown", "Jones", "Garcia", "Miller", "Davis",
    "Rodriguez", "Martinez", "Hernandez", "Lopez", "Gonzalez", "Wilson", "Anderson",
    "Thomas", "Taylor", "Moore", "Jackson", "Martin", "Lee", "Perez", "Thompson",
    "White", "Harris", "Sanchez", "Clark", "Ramirez", "Lewis", "Robinson", "Walker",
]

CITIES = [
    ("Houston", "TX", "77001"), ("Los Angeles", "CA", "90001"),
    ("Chicago", "IL", "60601"), ("Phoenix", "AZ", "85001"),
    ("Philadelphia", "PA", "19101"), ("San Antonio", "TX", "78201"),
    ("San Diego", "CA", "92101"), ("Dallas", "TX", "75201"),
    ("Jacksonville", "FL", "32099"), ("Austin", "TX", "78701"),
    ("Columbus", "OH", "43085"), ("Charlotte", "NC", "28201"),
    ("Indianapolis", "IN", "46201"), ("Denver", "CO", "80201"),
    ("Seattle", "WA", "98101"), ("Nashville", "TN", "37201"),
]

# Patterns to detect content type
DIAGNOSIS_PATTERNS = re.compile(
    r'(?:diagnosis|assessment|impression|findings?|conclusion)\s*:', re.IGNORECASE
)
MEDICATION_PATTERNS = re.compile(
    r'(?:medication|prescription|drug|dose|dosage|mg|mcg|units?\s+(?:daily|bid|tid|qid|prn))',
    re.IGNORECASE
)
LAB_PATTERNS = re.compile(
    r'(?:hemoglobin|hematocrit|white\s+blood|platelet|glucose|cholesterol|creatinine|'
    r'potassium|sodium|bilirubin|albumin|WBC|RBC|BUN|GFR|HbA1c|TSH|PSA|'
    r'mg/dL|mmol/L|mEq/L|g/dL|cells/mcL)',
    re.IGNORECASE
)


def generate_pii() -> dict:
    """Generate a synthetic patient identity."""
    first = random.choice(FIRST_NAMES)
    last = random.choice(LAST_NAMES)
    city, state, zip_code = random.choice(CITIES)

    dob_year = random.randint(1940, 2005)
    dob_month = random.randint(1, 12)
    dob_day = random.randint(1, 28)

    ssn = f"{random.randint(100, 899)}-{random.randint(10, 99)}-{random.randint(1000, 9999)}"
    mrn = f"MRN-{random.randint(100000, 999999)}"
    phone = f"({random.randint(200, 999)}) {random.randint(200, 999)}-{random.randint(1000, 9999)}"
    street_num = random.randint(100, 9999)
    streets = ["Oak St", "Maple Ave", "Cedar Blvd", "Pine Dr", "Elm Way", "Main St", "Park Ave"]

    return {
        "full_name": f"{first} {last}",
        "first_name": first,
        "last_name": last,
        "dob": f"{dob_month:02d}/{dob_day:02d}/{dob_year}",
        "ssn": ssn,
        "mrn": mrn,
        "phone": phone,
        "address": f"{street_num} {random.choice(streets)}",
        "city": city,
        "state": state,
        "zip_code": zip_code,
    }


def inject_pii(text: str, pii: dict) -> str:
    """Prepend a synthetic patient header to the transcription."""
    header = (
        f"PATIENT: {pii['full_name']}\n"
        f"DOB: {pii['dob']}\n"
        f"SSN: {pii['ssn']}\n"
        f"MRN: {pii['mrn']}\n"
        f"PHONE: {pii['phone']}\n"
        f"ADDRESS: {pii['address']}, {pii['city']}, {pii['state']} {pii['zip_code']}\n"
        f"{'=' * 60}\n\n"
    )
    return header + text


def classify_content(text: str) -> list[str]:
    """Determine which medical subcategories apply."""
    subcats = []
    if DIAGNOSIS_PATTERNS.search(text):
        subcats.append("medical.diagnosis")
    if MEDICATION_PATTERNS.search(text):
        subcats.append("medical.prescription")
    if LAB_PATTERNS.search(text):
        subcats.append("medical.lab_result")
    if not subcats:
        subcats.append("medical.diagnosis")  # default
    return subcats


def process(max_samples: int = 2000, seed: int = 42):
    """Process MTSamples into labeled JSONL."""
    random.seed(seed)
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    out_path = OUT_DIR / "mtsamples.jsonl"

    csv_path = RAW_DIR / "mtsamples.csv"
    if not csv_path.exists():
        print(f"ERROR: MTSamples not found at {csv_path}")
        sys.exit(1)

    all_samples = []
    counts = {}

    with open(csv_path, errors="ignore") as f:
        reader = csv.DictReader(f)
        for row in reader:
            text = row.get("transcription", "").strip()
            if not text or len(text) < 100:
                continue

            specialty = row.get("medical_specialty", "").strip()
            description = row.get("description", "").strip()
            keywords = row.get("keywords", "").strip()

            # Classify content
            subcategories = classify_content(text)

            # Inject synthetic PII
            pii = generate_pii()
            enriched_text = inject_pii(text[:3500], pii)

            # Build findings
            findings = []

            # PII finding (from injected data)
            findings.append({
                "category": "pii",
                "subcategory": "pii.identity",
                "severity": "critical",
                "compliance": ["GDPR", "CCPA", "HIPAA"],
                "fields": {
                    "full_name": pii["full_name"],
                    "dob": pii["dob"],
                    "ssn": pii["ssn"],
                },
            })

            # Medical findings
            for subcat in subcategories:
                fields = {"medical_specialty": specialty}
                if keywords:
                    fields["keywords"] = keywords[:200]

                findings.append({
                    "category": "medical",
                    "subcategory": subcat,
                    "severity": "critical",
                    "compliance": ["HIPAA"],
                    "fields": fields,
                })
                counts[subcat] = counts.get(subcat, 0) + 1

            all_samples.append({
                "text": enriched_text,
                "findings": findings,
                "specialty": specialty,
            })

    # Sample if needed
    if len(all_samples) > max_samples:
        random.shuffle(all_samples)
        all_samples = all_samples[:max_samples]

    with open(out_path, "w") as fout:
        for i, sample in enumerate(all_samples):
            record = {
                "id": f"mtsamples_{i:05d}",
                "source": "mtsamples",
                "source_license": "CC0",
                "text": sample["text"],
                "findings": sample["findings"],
            }
            fout.write(json.dumps(record) + "\n")

    print(f"Wrote {len(all_samples):,} samples to {out_path}")
    print("\nCategory distribution:")
    for sub, count in sorted(counts.items()):
        print(f"  {sub}: {count}")


if __name__ == "__main__":
    max_n = int(sys.argv[1]) if len(sys.argv) > 1 else 2000
    process(max_samples=max_n)
