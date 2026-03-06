#!/usr/bin/env python3
"""
TorchSight PDF Report Generator

Reads scan results JSON (stdin or file) and produces a styled PDF report.

Usage:
    torchsight scan /path | python report/generate.py
    python report/generate.py report.json
    python report/generate.py report.json -o my_report.pdf
"""

import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

from jinja2 import Environment, FileSystemLoader
from weasyprint import HTML


SCRIPT_DIR = Path(__file__).parent.resolve()
TEMPLATE_DIR = SCRIPT_DIR
LOGO_PATH = SCRIPT_DIR.parent / "public" / "logo.svg"


def human_size(size_bytes: int) -> str:
    if size_bytes < 1024:
        return f"{size_bytes} B"
    elif size_bytes < 1024 * 1024:
        return f"{size_bytes / 1024:.1f} KB"
    elif size_bytes < 1024 * 1024 * 1024:
        return f"{size_bytes / (1024 * 1024):.1f} MB"
    else:
        return f"{size_bytes / (1024 * 1024 * 1024):.2f} GB"


def prepare_report_data(raw: dict) -> dict:
    """Transform raw JSON into template-friendly data."""
    files = raw.get("files", [])

    # Compute counts
    all_findings = [f for file in files for f in file.get("findings", [])]
    non_safe = [f for f in all_findings if f.get("category") != "safe"]

    critical = sum(1 for f in non_safe if f.get("severity") == "Critical")
    warning = sum(1 for f in non_safe if f.get("severity") == "Warning")
    info = sum(1 for f in non_safe if f.get("severity") == "Info")

    flagged_files = []
    clean_files = []

    for file in files:
        findings = file.get("findings", [])
        has_issues = any(f.get("category") != "safe" for f in findings)

        file_data = {
            "path": file.get("path", "unknown"),
            "kind": file.get("kind", "unknown"),
            "size": file.get("size", 0),
            "size_human": human_size(file.get("size", 0)),
            "findings": findings,
        }

        if has_issues:
            flagged_files.append(file_data)
        else:
            clean_files.append(file_data)

    # Parse timestamp
    ts_raw = raw.get("timestamp", "")
    try:
        ts = datetime.fromisoformat(ts_raw.replace("Z", "+00:00"))
        timestamp = ts.strftime("%Y-%m-%d %H:%M:%S UTC")
    except (ValueError, AttributeError):
        timestamp = ts_raw or datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    return {
        "timestamp": timestamp,
        "total_files": len(files),
        "total_findings": len(non_safe),
        "critical_count": critical,
        "warning_count": warning,
        "info_count": info,
        "clean_count": len(clean_files),
        "flagged_files": flagged_files,
        "clean_files": clean_files,
        "logo_path": LOGO_PATH.as_uri(),
    }


def generate_pdf(report_json: dict, output_path: str) -> str:
    """Generate PDF from report JSON."""
    env = Environment(loader=FileSystemLoader(str(TEMPLATE_DIR)))
    template = env.get_template("template.html")

    data = prepare_report_data(report_json)
    html_content = template.render(**data)

    HTML(string=html_content, base_url=str(SCRIPT_DIR)).write_pdf(output_path)
    return output_path


def main():
    # Read input
    if len(sys.argv) > 1 and sys.argv[1] != "-o":
        input_file = sys.argv[1]
        with open(input_file) as f:
            report = json.load(f)
    else:
        report = json.load(sys.stdin)

    # Output path
    output = None
    if "-o" in sys.argv:
        idx = sys.argv.index("-o")
        if idx + 1 < len(sys.argv):
            output = sys.argv[idx + 1]

    if not output:
        ts = datetime.now().strftime("%Y-%m-%d_%H%M%S")
        output = f"torchsight_report_{ts}.pdf"

    path = generate_pdf(report, output)
    print(path)


if __name__ == "__main__":
    main()
