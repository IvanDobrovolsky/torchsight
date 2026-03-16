#!/usr/bin/env python3
"""
SecLists Processor for TorchSight Training

Categorizes payloads by attack type, wraps them in realistic
file contexts, and outputs labeled JSONL samples.

Targets: malicious.injection, malicious.shell, malicious.obfuscated,
         malicious.xxe, malicious.ssti, malicious.ssrf, credentials.password
"""

import json
import random
import sys
from pathlib import Path

RAW_DIR = Path(__file__).parent.parent.parent / "data" / "raw" / "SecLists"
OUT_DIR = Path(__file__).parent.parent.parent / "data" / "processed"

# Mapping: relative path pattern -> (subcategory, injection_type)
PAYLOAD_MAP = {
    # SQLi
    "Fuzzing/Databases/SQLi/Generic-SQLi.txt": ("malicious.injection", "SQL"),
    "Fuzzing/Databases/SQLi/quick-SQLi.txt": ("malicious.injection", "SQL"),
    "Fuzzing/Databases/SQLi/Auth_Bypass.txt": ("malicious.injection", "SQL"),
    "Fuzzing/Databases/SQLi/BlindSQLi.fuzzdb.txt": ("malicious.injection", "SQL"),
    "Fuzzing/Databases/SQLi/MySQL-SQLi-Login-Bypass.fuzzdb.txt": ("malicious.injection", "SQL"),
    "Fuzzing/Databases/SQLi/MSSQL-SQLi-Login-Bypass.fuzzdb.txt": ("malicious.injection", "SQL"),
    "Fuzzing/Databases/SQLi/oracle.txt": ("malicious.injection", "SQL"),
    "Fuzzing/Databases/SQLi/NoSQL.txt": ("malicious.injection", "NoSQL"),
    # XSS
    "Fuzzing/XSS/XSS-Jhaddix.txt": ("malicious.injection", "XSS"),
    "Fuzzing/XSS/human-friendly/XSS-BruteLogic.txt": ("malicious.injection", "XSS"),
    "Fuzzing/XSS/human-friendly/XSS-Cheat-Sheet-PortSwigger.txt": ("malicious.injection", "XSS"),
    "Fuzzing/XSS/human-friendly/XSS-With-Context-Jhaddix.txt": ("malicious.injection", "XSS"),
    "Fuzzing/XSS/XSS-Polyglots.txt": ("malicious.injection", "XSS"),
    # Command injection
    "Fuzzing/command-injection-commix.txt": ("malicious.injection", "cmd"),
    "Fuzzing/UnixAttacks.fuzzdb.txt": ("malicious.injection", "cmd"),
    # LDAP
    "Fuzzing/LDAP.Fuzzing.txt": ("malicious.injection", "LDAP"),
    # XXE
    "Fuzzing/XXE-Fuzzing.txt": ("malicious.xxe", "XXE"),
    # SSTI
    "Fuzzing/template-engines-expression.txt": ("malicious.ssti", "SSTI"),
    "Fuzzing/template-engines-special-vars.txt": ("malicious.ssti", "SSTI"),
    # SSI
    "Fuzzing/SSI-Injection-Jhaddix.txt": ("malicious.injection", "SSI"),
}

# Context templates for wrapping raw payloads
CONTEXT_TEMPLATES = {
    "SQL": [
        'SELECT * FROM users WHERE username = \'{payload}\';',
        'GET /api/users?id={payload} HTTP/1.1\nHost: example.com',
        '# Application log\n[2024-01-15 14:22:33] Query executed: SELECT name FROM products WHERE id = {payload}',
        'username={payload}&password=admin&submit=Login',
    ],
    "XSS": [
        '<html><body>\n<div class="user-content">{payload}</div>\n</body></html>',
        '<!-- User comment -->\n<p>{payload}</p>',
        'GET /search?q={payload} HTTP/1.1\nHost: example.com',
        '<input type="text" value="{payload}" name="search">',
    ],
    "cmd": [
        '#!/bin/bash\n# Deploy script\ntar -xzf {payload}',
        'GET /api/ping?host={payload} HTTP/1.1\nHost: internal.corp',
        '# Server log\n[ERROR] Failed to process: {payload}',
        'filename={payload}',
    ],
    "XXE": [
        '<?xml version="1.0"?>\n{payload}',
        'POST /api/import HTTP/1.1\nContent-Type: application/xml\n\n{payload}',
    ],
    "SSTI": [
        'GET /profile?name={payload} HTTP/1.1\nHost: example.com',
        '{{% block content %}}\n<h1>Hello {payload}</h1>\n{{% endblock %}}',
    ],
    "LDAP": [
        'GET /api/user?filter={payload} HTTP/1.1',
        '# LDAP query log\nsearchFilter: {payload}',
    ],
    "SSI": [
        '<html>\n<body>\n{payload}\n</body>\n</html>',
    ],
    "NoSQL": [
        'POST /api/login HTTP/1.1\nContent-Type: application/json\n\n{payload}',
    ],
}

# Password context templates
PASSWORD_CONTEXTS = [
    'DB_PASSWORD={payload}\nDB_HOST=localhost\nDB_PORT=5432',
    'password: {payload}\nusername: admin\nhost: db.internal.corp',
    '# credentials.txt\nadmin:{payload}',
    'spring.datasource.password={payload}\nspring.datasource.url=jdbc:mysql://localhost:3306/app',
    'REDIS_URL=redis://default:{payload}@redis.internal:6379',
]


def read_payloads(rel_path: str, max_lines: int = 2000) -> list[str]:
    """Read payload lines from a SecLists file."""
    full_path = RAW_DIR / rel_path
    if not full_path.exists():
        return []

    lines = []
    try:
        with open(full_path, errors="ignore") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    lines.append(line)
    except Exception:
        return []

    if len(lines) > max_lines:
        random.shuffle(lines)
        lines = lines[:max_lines]

    return lines


def read_webshells(max_files: int = 300) -> list[dict]:
    """Read web shell files as complete samples."""
    shells_dir = RAW_DIR / "Web-Shells"
    if not shells_dir.exists():
        return []

    samples = []
    for root, _, files in __import__("os").walk(shells_dir):
        for f in files:
            path = Path(root) / f
            if path.suffix in (".php", ".jsp", ".asp", ".aspx", ".sh", ".cfm", ".py"):
                try:
                    text = path.read_text(errors="ignore")[:4000]
                    samples.append({
                        "text": text,
                        "shell_type": path.suffix.lstrip("."),
                        "filename": f,
                    })
                except Exception:
                    pass

    return samples[:max_files]


def wrap_payload(payload: str, injection_type: str) -> str:
    """Wrap a raw payload in a realistic file context."""
    templates = CONTEXT_TEMPLATES.get(injection_type, ['{payload}'])
    template = random.choice(templates)
    return template.format(payload=payload)


def process(max_per_category: int = 2000, seed: int = 42):
    """Process SecLists into labeled JSONL."""
    random.seed(seed)
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    out_path = OUT_DIR / "seclists.jsonl"

    if not RAW_DIR.exists():
        print(f"ERROR: SecLists not found at {RAW_DIR}")
        sys.exit(1)

    all_samples = []
    category_counts = {}

    # Process payload files
    for rel_path, (subcategory, injection_type) in PAYLOAD_MAP.items():
        payloads = read_payloads(rel_path, max_lines=max_per_category)
        if not payloads:
            continue

        for payload in payloads:
            context_text = wrap_payload(payload, injection_type)
            sample = {
                "source_file": rel_path,
                "text": context_text,
                "findings": [{
                    "category": "malicious",
                    "subcategory": subcategory,
                    "severity": "critical",
                    "compliance": [],
                    "fields": {
                        "payload": payload[:500],
                        "injection_type": injection_type,
                    },
                }],
            }
            all_samples.append(sample)
            category_counts[subcategory] = category_counts.get(subcategory, 0) + 1

    # Process web shells
    shells = read_webshells()
    for shell in shells:
        sample = {
            "source_file": f"Web-Shells/{shell['filename']}",
            "text": shell["text"],
            "findings": [{
                "category": "malicious",
                "subcategory": "malicious.shell",
                "severity": "critical",
                "compliance": [],
                "fields": {
                    "shell_type": shell["shell_type"],
                    "filename": shell["filename"],
                },
            }],
        }
        all_samples.append(sample)
        category_counts["malicious.shell"] = category_counts.get("malicious.shell", 0) + 1

    # Process passwords (sample from common credentials)
    pw_files = [
        "Passwords/Common-Credentials/10k-most-common.txt",
        "Passwords/Default-Credentials/default-passwords.csv",
    ]
    pw_payloads = []
    for pf in pw_files:
        pw_payloads.extend(read_payloads(pf, max_lines=250))

    for pw in pw_payloads[:max_per_category]:
        template = random.choice(PASSWORD_CONTEXTS)
        context_text = template.format(payload=pw)
        sample = {
            "source_file": "Passwords/",
            "text": context_text,
            "findings": [{
                "category": "credentials",
                "subcategory": "credentials.password",
                "severity": "critical",
                "compliance": ["NIST-800-53"],
                "fields": {"password": pw},
            }],
        }
        all_samples.append(sample)
        category_counts["credentials.password"] = category_counts.get("credentials.password", 0) + 1

    # Shuffle and write
    random.shuffle(all_samples)

    with open(out_path, "w") as fout:
        for i, sample in enumerate(all_samples):
            record = {
                "id": f"seclists_{i:05d}",
                "source": "seclists",
                "source_license": "MIT",
                "text": sample["text"],
                "findings": sample["findings"],
            }
            fout.write(json.dumps(record) + "\n")

    print(f"Wrote {len(all_samples):,} samples to {out_path}")
    print("\nCategory distribution:")
    for sub, count in sorted(category_counts.items()):
        print(f"  {sub}: {count}")


if __name__ == "__main__":
    max_n = int(sys.argv[1]) if len(sys.argv) > 1 else 2000
    process(max_per_category=max_n)
