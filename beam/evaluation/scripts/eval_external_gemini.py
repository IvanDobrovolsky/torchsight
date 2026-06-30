#!/usr/bin/env python3
"""Run Google Gemini 2.5 Pro on the 500-sample external held-out benchmark.

Talks to Vertex AI (not Generative Language API) so usage rolls up to a
GCP project for cost tracking. Authentication uses Application Default
Credentials — run `gcloud auth application-default login` first, or set
`GOOGLE_APPLICATION_CREDENTIALS` to a service-account JSON.

Set the GCP project and location with `GCP_PROJECT` and `GCP_LOCATION`
env vars. Defaults are placeholders — the real run requires both to be
overridden.

All parsing, scoring, and result-snapshot logic is shared with the other
external evaluators via `external_eval_lib.run_benchmark`.
"""

import os
import sys
import time

from external_eval_lib import INSTRUCTION, SYSTEM_PROMPT, run_benchmark


MODEL = os.environ.get("MODEL", "gemini-2.5-pro")
GCP_PROJECT = os.environ.get("GCP_PROJECT", "your-gcp-project")
GCP_LOCATION = os.environ.get("GCP_LOCATION", "us-central1")

_client = None


def get_client():
    """Lazy-load the Vertex AI client to keep import cost low for --help."""
    global _client
    if _client is None:
        from google import genai
        _client = genai.Client(
            vertexai=True,
            project=GCP_PROJECT,
            location=GCP_LOCATION,
        )
    return _client


def query_gemini(text: str) -> str:
    """Send one document to Gemini and return the raw response string.

    Retries up to 5 times on transient errors. Vertex SDK does not expose
    HTTP status codes directly, so we detect rate limits by string match.
    """
    from google.genai import types

    client = get_client()
    config = types.GenerateContentConfig(
        system_instruction=SYSTEM_PROMPT,
        temperature=0,
        max_output_tokens=4096,
    )
    for attempt in range(5):
        try:
            response = client.models.generate_content(
                model=MODEL,
                contents=[types.Part.from_text(text=f"{INSTRUCTION}\n\n{text}")],
                config=config,
            )
            return response.text
        except Exception as exc:
            is_rate_limit = "429" in str(exc) or "quota" in str(exc).lower()
            if is_rate_limit:
                wait_seconds = min(2 ** attempt * 10, 120)
                print(f" [rate-limited {wait_seconds}s]", end="", flush=True)
                time.sleep(wait_seconds)
                continue
            if attempt < 4:
                time.sleep(2 ** attempt * 2)
                continue
            raise
    raise RuntimeError("Exhausted retries without a response")


def preflight() -> None:
    """Refuse to start if Vertex AI credentials or project are not configured."""
    if GCP_PROJECT == "your-gcp-project":
        sys.stderr.write(
            "ERROR: GCP_PROJECT is unset. Set it to your Vertex AI project id, e.g.\n"
            "  GCP_PROJECT=my-project GCP_LOCATION=us-central1 python eval_external_gemini.py\n"
        )
        sys.exit(1)
    has_adc = os.path.exists(os.path.expanduser("~/.config/gcloud/application_default_credentials.json"))
    has_sa_key = bool(os.environ.get("GOOGLE_APPLICATION_CREDENTIALS"))
    if not (has_adc or has_sa_key):
        sys.stderr.write(
            "ERROR: No Vertex AI credentials found. Run one of:\n"
            "  gcloud auth application-default login\n"
            "  export GOOGLE_APPLICATION_CREDENTIALS=/path/to/service-account.json\n"
        )
        sys.exit(1)


if __name__ == "__main__":
    preflight()
    model_tag = MODEL.replace("/", "-").replace(":", "-")
    run_benchmark(
        query_fn=query_gemini,
        model_label=MODEL,
        output_filename=f"eval_external_{model_tag}.json",
    )
