#!/usr/bin/env python3
"""Run OpenAI GPT-5 on the 500-sample external held-out benchmark.

GPT-5 is the only model in the suite that does not run at temperature=0:
the OpenAI chat-completions endpoint rejects a `temperature` parameter for
the `gpt-5` model, so the request omits it and GPT-5 samples at the
service default. This is documented as a methodology constraint in the
paper Methods section.

All parsing, scoring, and result-snapshot logic is shared with the other
external evaluators via `external_eval_lib.run_benchmark`.
"""

import os
import time

import requests

from external_eval_lib import INSTRUCTION, SYSTEM_PROMPT, run_benchmark


API_KEY = os.environ.get("OPENAI_API_KEY", "")
MODEL = "gpt-5"
OUTPUT_FILENAME = "eval_external_gpt-5.json"
API_URL = "https://api.openai.com/v1/chat/completions"


def query_gpt5(text: str) -> str:
    """Send one document to GPT-5 and return the raw response string.

    Retries up to 5 times on transient errors; honors HTTP 429 with
    exponential backoff capped at 120 seconds.
    """
    payload = {
        "model": MODEL,
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": [
                {"type": "text", "text": f"{INSTRUCTION}\n\n{text}"},
            ]},
        ],
        "max_completion_tokens": 16384,
    }
    headers = {
        "Authorization": f"Bearer {API_KEY}",
        "Content-Type": "application/json",
    }
    for attempt in range(5):
        try:
            response = requests.post(API_URL, json=payload, headers=headers, timeout=300)
            if response.status_code == 429:
                wait_seconds = min(2 ** attempt * 10, 120)
                print(f" [rate-limited, wait {wait_seconds}s]", end="", flush=True)
                time.sleep(wait_seconds)
                continue
            response.raise_for_status()
            return response.json()["choices"][0]["message"]["content"]
        except Exception:
            if attempt < 4:
                time.sleep(2 ** attempt * 2)
                continue
            raise
    raise RuntimeError("Exhausted retries without a response")


if __name__ == "__main__":
    run_benchmark(
        query_fn=query_gpt5,
        model_label=MODEL,
        output_filename=OUTPUT_FILENAME,
        required_env_var="OPENAI_API_KEY",
    )
