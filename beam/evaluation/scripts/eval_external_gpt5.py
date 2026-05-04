#!/usr/bin/env python3
"""Run GPT-5 on the external validation benchmark (500 samples)."""
import json, os, re, sys, time, requests

EVAL_DIR = os.path.join(os.path.dirname(__file__), "..", "data", "eval-500-external")
GROUND_TRUTH = os.path.join(EVAL_DIR, "ground-truth.json")
RESULTS_DIR = os.path.join(os.path.dirname(__file__), "..", "results")
API_KEY = os.environ.get("OPENAI_API_KEY", "")

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

def query_gpt5(text):
    payload = {
        "model": "gpt-5",
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": [{"type": "text", "text": f"{INSTRUCTION}\n\n{text}"}]},
        ],
        "max_completion_tokens": 16384,
    }
    headers = {"Authorization": f"Bearer {API_KEY}", "Content-Type": "application/json"}
    for attempt in range(5):
        try:
            r = requests.post("https://api.openai.com/v1/chat/completions", json=payload, headers=headers, timeout=300)
            if r.status_code == 429:
                wait = min(2 ** attempt * 10, 120)
                print(f" [rate-limited, wait {wait}s]", end="", flush=True)
                time.sleep(wait)
                continue
            r.raise_for_status()
            return r.json()["choices"][0]["message"]["content"]
        except Exception as e:
            if attempt < 4:
                time.sleep(2 ** attempt * 2)
                continue
            raise
    raise Exception("Max retries")

def parse_response(response):
    findings = []
    seen = set()
    def process(parsed):
        for f in parsed:
            if not isinstance(f, dict) or "category" not in f: continue
            cat = f.get("category","").lower().strip()
            key = f"{cat}:{f.get('subcategory','')}"
            if key in seen: continue
            seen.add(key)
            f["category"] = cat
            findings.append(f)
    for m in re.finditer(r'\[.*?\]', response or "", re.DOTALL):
        try:
            parsed = json.loads(m.group())
            if isinstance(parsed, list): process(parsed)
        except: continue
    if not findings and response:
        bp = response.find('[')
        if bp >= 0:
            depth = 0; last = None; in_s = False; esc = False
            for i, ch in enumerate(response[bp:]):
                if esc: esc = False; continue
                if ch == '\\' and in_s: esc = True; continue
                if ch == '"': in_s = not in_s; continue
                if in_s: continue
                if ch == '{': depth += 1
                elif ch == '}':
                    depth -= 1
                    if depth == 0: last = i
            if last:
                try:
                    parsed = json.loads(response[bp:bp+last+1] + "]")
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
    if not API_KEY:
        print("ERROR: OPENAI_API_KEY not set"); sys.exit(1)
    with open(GROUND_TRUTH) as f:
        samples = json.load(f)
    os.makedirs(RESULTS_DIR, exist_ok=True)
    output_path = os.path.join(RESULTS_DIR, "eval_external_gpt-5.json")
    results = []; done_ids = set()
    if os.path.exists(output_path):
        with open(output_path) as f:
            existing = json.load(f)
        results = existing.get("results", [])
        done_ids = {r["id"] for r in results}
        print(f"Resuming: {len(done_ids)} done")
    print(f"GPT-5 on {len(samples)} external samples\n{'='*80}")
    for sample in samples:
        if sample["id"] in done_ids: continue
        fp = os.path.join(EVAL_DIR, sample["file"])
        if not os.path.exists(fp): continue
        with open(fp, "r", errors="replace") as f:
            content = f.read()[:6000]
        print(f"  [{sample['id']:4d}] {sample['source']:<25s}", end="", flush=True)
        start = time.time()
        try:
            response = query_gpt5(content)
            elapsed = time.time() - start
            findings = parse_response(response)
            pred = get_primary_category(findings)
            ok = pred == sample["category"]
            print(f" {elapsed:5.1f}s  cat={pred:<14s} [{'OK' if ok else 'MISS':4s}]")
            results.append({"id":sample["id"],"file":sample["file"],"source":sample["source"],
                "expected_cat":sample["category"],"predicted_cat":pred,"cat_correct":ok,"elapsed":elapsed})
        except Exception as e:
            elapsed = time.time() - start
            print(f" {elapsed:5.1f}s  ERROR: {e}")
            results.append({"id":sample["id"],"file":sample["file"],"source":sample["source"],
                "expected_cat":sample["category"],"predicted_cat":"error","cat_correct":False,"error":str(e)})
        total = len(results); correct = sum(1 for r in results if r.get("cat_correct"))
        with open(output_path, "w") as f:
            json.dump({"model":"gpt-5","benchmark":"external-500","timestamp":time.strftime("%Y-%m-%d %H:%M:%S"),
                "total_samples":total,"category_accuracy":correct/total if total else 0,"results":results}, f, indent=2)
    total = len(results); correct = sum(1 for r in results if r.get("cat_correct"))
    print(f"\n{'='*80}\nGPT-5 external: {correct}/{total} = {correct/total*100:.1f}%")
    src_stats = {}
    for r in results:
        s = r.get("source","?")
        if s not in src_stats: src_stats[s] = {"t":0,"c":0}
        src_stats[s]["t"] += 1
        if r.get("cat_correct"): src_stats[s]["c"] += 1
    for s in sorted(src_stats):
        v = src_stats[s]; print(f"  {s:<25s} {v['c']:>3d}/{v['t']:<3d} = {v['c']/v['t']*100:.1f}%")
    print(f"\nSaved: {output_path}")

if __name__ == "__main__":
    main()
