#!/usr/bin/env python3
"""Process HuggingFace prompt injection datasets into training JSONL."""

import json
import hashlib
import random
from pathlib import Path

DATA_DIR = Path(__file__).resolve().parent.parent.parent / "data"
OUT_DIR = Path(__file__).resolve().parent.parent.parent / "data" / "processed"

# Contexts to wrap raw injection attempts in realistic scenarios
CONTEXTS = [
    "User message in a customer support chatbot:\n\n{text}",
    "Input received from web form field 'comments':\n\n{text}",
    "API request body (parsed JSON string field):\n\n{text}",
    "User query submitted to AI assistant:\n\n{text}",
    "Feedback form submission:\n\n{text}",
    "Search query entered by user:\n\n{text}",
    "Content of uploaded text file:\n\n{text}",
    "Email body forwarded to AI summarizer:\n\n{text}",
    "Slack message sent to AI bot:\n\n{text}",
    "User prompt in code generation tool:\n\n{text}",
]


def make_id(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()[:16]


def process_deepset():
    """Process deepset/prompt-injections dataset."""
    data_file = DATA_DIR / "prompt_injection_deepset" / "data.jsonl"
    if not data_file.exists():
        print(f"  {data_file} not found, skipping")
        return []

    samples = []
    with open(data_file) as f:
        for line in f:
            row = json.loads(line)
            text = row.get("text", "").strip()
            label = row.get("label", 0)

            if not text or len(text) < 10:
                continue

            # label=1 means injection attempt
            if label == 1:
                context = random.choice(CONTEXTS).format(text=text)
                samples.append({
                    "id": f"pi-deepset-{make_id(text)}",
                    "source": "deepset/prompt-injections",
                    "source_license": "Apache-2.0",
                    "text": context,
                    "findings": [{
                        "category": "malicious",
                        "subcategory": "malicious.prompt_injection",
                        "severity": "high",
                        "compliance": ["OWASP-LLM-01"],
                        "evidence": text[:200],
                        "explanation": "Prompt injection attempt detected — user input attempts to override system instructions or manipulate AI behavior."
                    }]
                })

    print(f"  deepset: {len(samples)} injection samples")
    return samples


def process_geekyrakshit():
    """Process geekyrakshit/prompt-injection-dataset."""
    data_file = DATA_DIR / "prompt_injection_geekyrakshit" / "data.jsonl"
    if not data_file.exists():
        print(f"  {data_file} not found, skipping")
        return []

    samples = []
    seen = set()
    with open(data_file) as f:
        for line in f:
            row = json.loads(line)
            text = row.get("text", "") or row.get("prompt", "") or ""
            text = text.strip()
            label = row.get("label", 0)

            if not text or len(text) < 10:
                continue

            # Deduplicate
            key = text[:100]
            if key in seen:
                continue
            seen.add(key)

            if label == 1:
                context = random.choice(CONTEXTS).format(text=text)
                samples.append({
                    "id": f"pi-geeky-{make_id(text)}",
                    "source": "geekyrakshit/prompt-injection-dataset",
                    "source_license": "Apache-2.0",
                    "text": context,
                    "findings": [{
                        "category": "malicious",
                        "subcategory": "malicious.prompt_injection",
                        "severity": "high",
                        "compliance": ["OWASP-LLM-01"],
                        "evidence": text[:200],
                        "explanation": "Prompt injection attempt — input designed to manipulate, override, or extract system-level instructions from an AI model."
                    }]
                })

    # Cap at 5000
    if len(samples) > 5000:
        random.shuffle(samples)
        samples = samples[:5000]

    print(f"  geekyrakshit: {len(samples)} injection samples")
    return samples


def main():
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    out_file = OUT_DIR / "prompt_injection.jsonl"

    print("Processing prompt injection datasets...")
    samples = process_deepset() + process_geekyrakshit()

    # Deduplicate across both
    seen_ids = set()
    unique = []
    for s in samples:
        if s["id"] not in seen_ids:
            seen_ids.add(s["id"])
            unique.append(s)

    # Cap total at 5000
    if len(unique) > 5000:
        random.shuffle(unique)
        unique = unique[:5000]

    with open(out_file, "w") as f:
        for s in unique:
            f.write(json.dumps(s) + "\n")

    print(f"Saved {len(unique)} prompt injection samples to {out_file}")
    return len(unique)


if __name__ == "__main__":
    main()
