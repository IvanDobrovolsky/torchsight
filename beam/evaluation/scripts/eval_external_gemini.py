#!/usr/bin/env python3
"""Run Gemini 2.5 Pro on the external validation benchmark (500 samples) via Vertex AI."""
import json, os, re, sys, time

EVAL_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "data", "eval-500-external")
GROUND_TRUTH = os.path.join(EVAL_DIR, "ground-truth.json")
RESULTS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "results")
MODEL = os.environ.get("MODEL", "gemini-2.5-pro")
GCP_PROJECT = os.environ.get("GCP_PROJECT", "dehum-research-ml")
GCP_LOCATION = os.environ.get("GCP_LOCATION", "us-central1")

SYSTEM_PROMPT = """You are TorchSight, a cybersecurity document classifier. Analyze the provided text and identify ALL security-relevant findings.

For each finding, output a JSON object with:
- category: one of [pii, credentials, financial, medical, confidential, malicious, safe]
- subcategory: specific type (e.g., pii.identity, malicious.injection, credentials.api_key)
- severity: one of [critical, high, medium, low, info]
- explanation: detailed explanation including specific values found (redact sensitive parts, e.g., SSN: 412-XX-7890, API key: sk_live_51HG...). Explain what was found, why it matters, and the risk.

If a document contains multiple types of sensitive data, return a finding for EACH one.
If the text is clean/safe, output a single finding with category "safe".

Respond ONLY with a JSON array of findings."""

INSTRUCTION = "Analyze the following text for security threats, sensitive data, and policy violations."

_client = None
def get_client():
    global _client
    if _client is None:
        from google import genai
        _client = genai.Client(vertexai=True, project=GCP_PROJECT, location=GCP_LOCATION)
    return _client

def query_gemini(text):
    from google.genai import types
    client = get_client()
    config = types.GenerateContentConfig(
        system_instruction=SYSTEM_PROMPT, temperature=0, max_output_tokens=4096,
    )
    for attempt in range(5):
        try:
            resp = client.models.generate_content(
                model=MODEL,
                contents=[types.Part.from_text(text=f"{INSTRUCTION}\n\n{text}")],
                config=config,
            )
            return resp.text
        except Exception as e:
            if "429" in str(e) or "quota" in str(e).lower():
                wait = min(2 ** attempt * 10, 120)
                print(f" [rate-limited {wait}s]", end="", flush=True)
                time.sleep(wait); continue
            if attempt < 4: time.sleep(2 ** attempt * 2); continue
            raise

def parse_response(response):
    findings = []; seen = set()
    def process(parsed):
        for f in parsed:
            if not isinstance(f, dict) or "category" not in f: continue
            cat = f.get("category","").lower().strip()
            key = f"{cat}:{f.get('subcategory','')}"
            if key in seen: continue
            seen.add(key); f["category"] = cat; findings.append(f)
    for m in re.finditer(r'\[.*?\]', response or "", re.DOTALL):
        try:
            parsed = json.loads(m.group())
            if isinstance(parsed, list): process(parsed)
        except: continue
    if not findings and response:
        bp = response.find('[')
        if bp >= 0:
            depth=0; last=None; in_s=False; esc=False
            for i, ch in enumerate(response[bp:]):
                if esc: esc=False; continue
                if ch=='\\' and in_s: esc=True; continue
                if ch=='"': in_s=not in_s; continue
                if in_s: continue
                if ch=='{': depth+=1
                elif ch=='}':
                    depth-=1
                    if depth==0: last=i
            if last:
                try:
                    parsed = json.loads(response[bp:bp+last+1]+"]")
                    if isinstance(parsed, list): process(parsed)
                except: pass
    return findings

def get_primary_category(findings):
    non_safe = [f for f in findings if f.get("category","") != "safe"]
    if not non_safe: return "safe"
    rank = {"critical":0,"high":1,"medium":2,"low":3,"info":4}
    non_safe.sort(key=lambda f: rank.get(f.get("severity","info"),4))
    return non_safe[0].get("category","unknown")

def main():
    with open(GROUND_TRUTH) as f: samples = json.load(f)
    os.makedirs(RESULTS_DIR, exist_ok=True)
    model_tag = MODEL.replace("/","-").replace(":","-")
    output_path = os.path.join(RESULTS_DIR, f"eval_external_{model_tag}.json")
    results = []; done_ids = set()
    if os.path.exists(output_path):
        with open(output_path) as f: existing = json.load(f)
        results = existing.get("results", []); done_ids = {r["id"] for r in results}
        print(f"Resuming: {len(done_ids)} done")
    print(f"Gemini ({MODEL}) on {len(samples)} external samples\n{'='*80}")
    for sample in samples:
        if sample["id"] in done_ids: continue
        fp = os.path.join(EVAL_DIR, sample["file"])
        if not os.path.exists(fp): continue
        with open(fp, "r", errors="replace") as f: content = f.read()[:6000]
        print(f"  [{sample['id']:4d}] {sample['source']:<25s}", end="", flush=True)
        start = time.time()
        try:
            response = query_gemini(content)
            elapsed = time.time() - start
            findings = parse_response(response)
            pred = get_primary_category(findings)
            exp = sample["category"]; alt = sample.get("alt_category", "")
            ok = (pred == exp) or (alt and pred == alt)
            print(f" {elapsed:5.1f}s  cat={pred:<14s} [{'OK' if ok else 'MISS':4s}]")
            results.append({"id":sample["id"],"file":sample["file"],"source":sample["source"],
                "expected_cat":exp,"predicted_cat":pred,"cat_correct":ok,"elapsed":elapsed})
        except Exception as e:
            elapsed = time.time() - start
            print(f" {elapsed:5.1f}s  ERROR: {e}")
            results.append({"id":sample["id"],"file":sample["file"],"source":sample["source"],
                "expected_cat":sample["category"],"predicted_cat":"error","cat_correct":False,"error":str(e)})
        total = len(results); correct = sum(1 for r in results if r.get("cat_correct"))
        with open(output_path, "w") as f:
            json.dump({"model":MODEL,"benchmark":"external-500","timestamp":time.strftime("%Y-%m-%d %H:%M:%S"),
                "total_samples":total,"category_accuracy":correct/total if total else 0,"results":results}, f, indent=2)
    total = len(results); correct = sum(1 for r in results if r.get("cat_correct"))
    print(f"\n{'='*80}\n{MODEL}: {correct}/{total} = {correct/total*100:.1f}%")
    src = {}
    for r in results:
        s=r.get("source","?")
        if s not in src: src[s]={"t":0,"c":0}
        src[s]["t"]+=1
        if r.get("cat_correct"): src[s]["c"]+=1
    for s in sorted(src):
        v=src[s]; print(f"  {s:<25s} {v['c']:>3d}/{v['t']:<3d} = {v['c']/v['t']*100:.1f}%")
    print(f"\nSaved: {output_path}")

if __name__ == "__main__": main()
