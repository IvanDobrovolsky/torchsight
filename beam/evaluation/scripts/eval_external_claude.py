#!/usr/bin/env python3
"""Run an Anthropic Claude model on the 500-sample external held-out benchmark.

The model is set via the `MODEL` env var (default: claude-sonnet-4). Run
this with `MODEL=claude-opus-4-20250514 python eval_external_claude.py` to
benchmark Opus. The output filename is derived from MODEL so concurrent
runs against different Claude variants do not collide.

All parsing, scoring, and result-snapshot logic is shared with the other
external evaluators via `external_eval_lib.run_benchmark`.
"""

import os
import time

import requests

from external_eval_lib import INSTRUCTION, SYSTEM_PROMPT, run_benchmark


API_KEY = os.environ.get("ANTHROPIC_API_KEY", "")
MODEL = os.environ.get("MODEL", "claude-sonnet-4-20250514")
API_URL = "https://api.anthropic.com/v1/messages"


def query_claude(text: str) -> str:
    """Send one document to Claude and return the raw response string.

    Retries up to 5 times on transient errors; honors HTTP 429 with
    exponential backoff capped at 120 seconds.
    """
    payload = {
        "model": MODEL,
        "max_tokens": 4096,
        "temperature": 0,
        "system": SYSTEM_PROMPT,
        "messages": [
            {"role": "user", "content": [
                {"type": "text", "text": f"{INSTRUCTION}\n\n{text}"},
            ]},
        ],
    }
    headers = {
        "x-api-key": API_KEY,
        "anthropic-version": "2023-06-01",
        "Content-Type": "application/json",
    }
    for attempt in range(5):
        try:
            response = requests.post(API_URL, json=payload, headers=headers, timeout=300)
            if response.status_code == 429:
                wait_seconds = min(2 ** attempt * 10, 120)
                print(f" [rate-limited {wait_seconds}s]", end="", flush=True)
                time.sleep(wait_seconds)
                continue
            response.raise_for_status()
            return response.json()["content"][0]["text"]
        except Exception:
            if attempt < 4:
                time.sleep(2 ** attempt * 2)
                continue
            raise
    raise RuntimeError("Exhausted retries without a response")


if __name__ == "__main__":
    model_tag = MODEL.replace("/", "-").replace(":", "-")
    run_benchmark(
        query_fn=query_claude,
        model_label=MODEL,
        output_filename=f"eval_external_{model_tag}.json",
        required_env_var="ANTHROPIC_API_KEY",
    )
