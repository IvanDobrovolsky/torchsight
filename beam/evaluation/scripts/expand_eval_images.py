#!/usr/bin/env python3
"""Expand eval-1000-synthetic image set: scrape safe images + generate more sensitive ones.

Adds ~30 images to bring total from 21 to ~50:
- ~15 safe images from public domain sources (Lorem Picsum / Unsplash)
- ~15 sensitive Playwright-rendered images (new scenarios)
"""
import json
import os
import random
import string
import time
import urllib.request
from pathlib import Path
from faker import Faker

random.seed(2026_02)
fake = Faker()
Faker.seed(2026_02)

OUT_DIR = Path(__file__).parent.parent / "data" / "eval-1000-synthetic" / "images"
OUT_DIR.mkdir(parents=True, exist_ok=True)

GROUND_TRUTH_PATH = Path(__file__).parent.parent / "data" / "eval-1000-synthetic" / "ground-truth.json"

with open(GROUND_TRUTH_PATH) as f:
    GROUND_TRUTH = json.load(f)

# Remove any previously added expansion images (IDs > 1021)
GROUND_TRUTH = [s for s in GROUND_TRUTH if s["id"] <= 1021]
SAMPLE_ID = 1021


def next_id():
    global SAMPLE_ID
    SAMPLE_ID += 1
    return SAMPLE_ID


def save_sample(category, subcategory, severity, filename, note, alt_category="", alt_subcategory=""):
    sid = next_id()
    entry = {
        "id": sid,
        "file": f"images/{filename}",
        "category": category,
        "subcategory": subcategory,
        "severity": severity,
        "bucket": "images",
        "note": note,
    }
    if alt_category:
        entry["alt_category"] = alt_category
        entry["alt_subcategory"] = alt_subcategory
    GROUND_TRUTH.append(entry)
    return sid


def rand_hex(n):
    return "".join(random.choices("0123456789abcdef", k=n))


def rand_aws_key():
    return "AKIA" + "".join(random.choices(string.ascii_uppercase + string.digits, k=16))


def rand_aws_secret():
    return "".join(random.choices(string.ascii_letters + string.digits + "+/", k=40))


def rand_password():
    return "".join(random.choices(string.ascii_letters, k=8)) + "".join(
        random.choices(string.digits, k=3)
    ) + random.choice("!@#$%")


def rand_ssn():
    return f"{random.randint(100,999)}-{random.randint(10,99)}-{random.randint(1000,9999)}"


def rand_cc():
    prefix = random.choice(["4532", "5412", "3782", "6011"])
    rest = "".join([str(random.randint(0, 9)) for _ in range(12)])
    return f"{prefix} {rest[:4]} {rest[4:8]} {rest[8:12]}"


# ============================================================
# PART 1: SCRAPE SAFE IMAGES
# ============================================================

# Lorem Picsum uses Unsplash photos (free, no attribution required for non-commercial)
# These are all real photographs - landscapes, objects, architecture, nature
SAFE_IMAGES = [
    # Tech / office / architecture
    {"picsum_id": 0, "desc": "Laptop on wooden desk", "subcat": "safe.documentation"},
    {"picsum_id": 2, "desc": "Mountain landscape", "subcat": "safe.documentation"},
    {"picsum_id": 10, "desc": "Forest landscape", "subcat": "safe.documentation"},
    {"picsum_id": 20, "desc": "Bird on branch", "subcat": "safe.documentation"},
    {"picsum_id": 26, "desc": "Bookshelf library", "subcat": "safe.documentation"},
    {"picsum_id": 48, "desc": "Skyline architecture", "subcat": "safe.documentation"},
    {"picsum_id": 60, "desc": "Leipzig cityscape", "subcat": "safe.documentation"},
    {"picsum_id": 119, "desc": "Sunset ocean waves", "subcat": "safe.documentation"},
    {"picsum_id": 160, "desc": "City street view", "subcat": "safe.documentation"},
    {"picsum_id": 180, "desc": "Coffee cup closeup", "subcat": "safe.documentation"},
    {"picsum_id": 201, "desc": "Snowy mountain peaks", "subcat": "safe.documentation"},
    {"picsum_id": 250, "desc": "Flowers in garden", "subcat": "safe.documentation"},
    {"picsum_id": 306, "desc": "Office keyboard closeup", "subcat": "safe.documentation"},
    {"picsum_id": 366, "desc": "Lake reflection", "subcat": "safe.documentation"},
    {"picsum_id": 403, "desc": "Abstract light trails", "subcat": "safe.documentation"},
]


def download_safe_images():
    """Download safe images from Lorem Picsum (Unsplash photos)."""
    print("\n=== Downloading safe images from Lorem Picsum ===\n")
    for img in SAFE_IMAGES:
        filename = f"img-safe-photo-{img['picsum_id']:03d}.jpg"
        filepath = OUT_DIR / filename
        if filepath.exists():
            print(f"  SKIP {filename} (already exists)")
            save_sample("safe", img["subcat"], "info", filename, img["desc"])
            continue

        url = f"https://picsum.photos/id/{img['picsum_id']}/1200/800"
        print(f"  Downloading {filename} ({img['desc']})...", end=" ", flush=True)
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "TorchSight-Eval/1.0"})
            with urllib.request.urlopen(req, timeout=30) as resp:
                data = resp.read()
            with open(filepath, "wb") as f:
                f.write(data)
            print(f"OK ({len(data)//1024}KB)")
            save_sample("safe", img["subcat"], "info", filename, img["desc"])
        except Exception as e:
            print(f"FAILED: {e}")
        time.sleep(0.5)  # Be polite


# ============================================================
# PART 2: GENERATE MORE SENSITIVE IMAGES WITH PLAYWRIGHT
# ============================================================

TERMINAL_CSS = """
body { margin: 0; padding: 0; background: #1e1e1e; }
.terminal {
    background: #0d1117; color: #c9d1d9; font-family: 'Menlo', 'Courier New', monospace;
    font-size: 13px; line-height: 1.5; padding: 16px; border-radius: 8px;
    margin: 20px; box-shadow: 0 4px 20px rgba(0,0,0,0.5);
}
.titlebar {
    background: #21262d; padding: 8px 12px; border-radius: 8px 8px 0 0;
    display: flex; align-items: center; gap: 8px; margin: 20px 20px 0 20px;
}
.dot { width: 12px; height: 12px; border-radius: 50%; }
.dot-red { background: #ff5f57; }
.dot-yellow { background: #febc2e; }
.dot-green { background: #28c840; }
.prompt { color: #7ee787; }
.comment { color: #8b949e; }
.error { color: #f85149; }
.highlight { color: #ffa657; }
.string { color: #a5d6ff; }
"""

FORM_CSS = """
body { margin: 0; font-family: -apple-system, 'Segoe UI', sans-serif; background: #f5f5f5; }
.form-container {
    max-width: 650px; margin: 30px auto; background: white; border-radius: 8px;
    box-shadow: 0 2px 10px rgba(0,0,0,0.1); padding: 30px;
}
h2 { color: #333; border-bottom: 2px solid #0066cc; padding-bottom: 10px; }
.field { margin-bottom: 15px; }
.field label { display: block; font-weight: 600; color: #555; margin-bottom: 4px; font-size: 13px; }
.field input, .field select, .field textarea {
    width: 100%; padding: 8px; border: 1px solid #ddd; border-radius: 4px;
    font-size: 14px; box-sizing: border-box; background: #fafafa;
}
.row { display: flex; gap: 15px; }
.row .field { flex: 1; }
.section-title { color: #0066cc; font-size: 15px; font-weight: 600; margin: 20px 0 10px; border-bottom: 1px solid #eee; padding-bottom: 5px; }
"""

EMAIL_CSS = """
body { margin: 0; font-family: -apple-system, 'Segoe UI', sans-serif; background: #f0f0f0; }
.email {
    max-width: 700px; margin: 30px auto; background: white; border-radius: 8px;
    box-shadow: 0 2px 10px rgba(0,0,0,0.1); overflow: hidden;
}
.email-header { background: #f8f9fa; padding: 16px 20px; border-bottom: 1px solid #e0e0e0; }
.email-header .from { font-weight: 600; color: #333; }
.email-header .meta { color: #666; font-size: 13px; margin-top: 4px; }
.email-body { padding: 20px; color: #333; line-height: 1.6; }
.email-body a { color: #0066cc; }
.btn { display: inline-block; background: #dc3545; color: white; padding: 12px 30px;
       border-radius: 4px; text-decoration: none; font-weight: 600; margin: 15px 0; }
"""

SLACK_CSS = """
body { margin: 0; font-family: 'Lato', -apple-system, sans-serif; background: #1a1d21; }
.slack {
    max-width: 750px; margin: 20px auto; background: #1a1d21; border-radius: 8px;
    color: #d1d2d3; padding: 10px 20px;
}
.channel { color: #d1d2d3; font-weight: 700; font-size: 16px; padding: 10px 0;
           border-bottom: 1px solid #35373b; margin-bottom: 15px; }
.msg { display: flex; gap: 10px; margin-bottom: 16px; }
.avatar { width: 36px; height: 36px; border-radius: 4px; flex-shrink: 0;
          display: flex; align-items: center; justify-content: center; font-size: 18px; }
.msg-content { flex: 1; }
.msg-header { margin-bottom: 4px; }
.msg-header .name { font-weight: 700; color: #d1d2d3; }
.msg-header .time { color: #616061; font-size: 12px; margin-left: 8px; }
.msg-text { color: #d1d2d3; line-height: 1.5; font-size: 14px; }
.msg-text code { background: #1d2025; padding: 2px 5px; border-radius: 3px; color: #e01e5a; font-size: 13px; }
.code-block { background: #1d2025; padding: 10px; border-radius: 6px; font-family: monospace;
              font-size: 12px; color: #d1d2d3; margin: 8px 0; white-space: pre; overflow-x: auto; }
"""

TABLE_CSS = """
body { margin: 0; font-family: -apple-system, 'Segoe UI', sans-serif; background: #f5f5f5; }
.container { max-width: 900px; margin: 30px auto; background: white; border-radius: 8px;
             box-shadow: 0 2px 10px rgba(0,0,0,0.1); padding: 25px; }
h2 { color: #333; margin: 0 0 20px; }
table { width: 100%; border-collapse: collapse; font-size: 13px; }
th { background: #f0f0f0; padding: 10px; text-align: left; font-weight: 600; color: #333;
     border-bottom: 2px solid #ddd; }
td { padding: 8px 10px; border-bottom: 1px solid #eee; color: #444; }
tr:hover { background: #f9f9f9; }
.badge { display: inline-block; padding: 2px 8px; border-radius: 10px; font-size: 11px; font-weight: 600; }
.badge-active { background: #d4edda; color: #155724; }
.badge-admin { background: #f8d7da; color: #721c24; }
"""

DOCUMENT_CSS = """
body { margin: 0; font-family: 'Times New Roman', serif; background: #e8e8e8; }
.document {
    max-width: 700px; margin: 30px auto; background: white; padding: 50px 60px;
    box-shadow: 0 2px 15px rgba(0,0,0,0.2); min-height: 500px;
}
.header { text-align: center; border-bottom: 3px double #333; padding-bottom: 15px; margin-bottom: 20px; }
.classification { color: red; font-weight: bold; font-size: 18px; letter-spacing: 3px; }
p { line-height: 1.8; color: #333; text-align: justify; }
.stamp { color: red; font-weight: bold; font-size: 14px; border: 2px solid red; padding: 5px 10px; display: inline-block; transform: rotate(-5deg); margin: 20px 0; }
"""


def generate_sensitive_images():
    """Generate additional sensitive images using Playwright."""
    from playwright.sync_api import sync_playwright

    print("\n=== Generating sensitive images with Playwright ===\n")

    images = []

    # --- CREDENTIALS ---

    # Postman-like API testing tool with exposed keys
    name = fake.name()
    api_key = f"sk-proj-{''.join(random.choices(string.ascii_letters + string.digits, k=48))}"
    images.append({
        "filename": "img-postman-api-key.png",
        "category": "credentials", "subcategory": "credentials.api_key",
        "severity": "critical", "note": "API testing tool showing OpenAI key in request header",
        "html": f"""<style>
body {{ margin: 0; font-family: -apple-system, sans-serif; background: #2d2d2d; }}
.app {{ max-width: 800px; margin: 20px auto; background: #1e1e1e; border-radius: 8px; overflow: hidden; }}
.toolbar {{ background: #ff6c37; color: white; padding: 10px 16px; font-weight: 600; font-size: 14px; }}
.tab {{ background: #2d2d2d; padding: 8px 16px; display: flex; gap: 10px; font-size: 13px; }}
.tab span {{ color: #ff6c37; padding: 4px 12px; border-bottom: 2px solid #ff6c37; }}
.content {{ padding: 16px; color: #d4d4d4; font-size: 13px; }}
.method {{ display: inline-block; background: #49cc90; color: white; padding: 3px 8px; border-radius: 3px; font-weight: 600; font-size: 12px; }}
.url-bar {{ background: #333; border: 1px solid #555; border-radius: 4px; padding: 8px 12px; margin: 10px 0; display: flex; gap: 10px; align-items: center; }}
.url {{ color: #d4d4d4; flex: 1; }}
.section {{ margin: 15px 0; }}
.section-title {{ color: #aaa; font-size: 12px; text-transform: uppercase; margin-bottom: 8px; }}
table {{ width: 100%; border-collapse: collapse; }}
th {{ text-align: left; color: #888; font-size: 11px; padding: 6px 8px; border-bottom: 1px solid #333; }}
td {{ padding: 6px 8px; color: #d4d4d4; border-bottom: 1px solid #333; font-family: monospace; font-size: 12px; }}
.key {{ color: #61dafb; }}
.val {{ color: #ce9178; word-break: break-all; }}
</style>
<div class="app">
<div class="toolbar">Postman — {name}'s Workspace</div>
<div class="tab"><span>Chat Completions</span></div>
<div class="content">
  <div class="url-bar"><span class="method">POST</span><span class="url">https://api.openai.com/v1/chat/completions</span></div>
  <div class="section">
    <div class="section-title">Headers (4)</div>
    <table>
      <tr><th>Key</th><th>Value</th></tr>
      <tr><td class="key">Content-Type</td><td class="val">application/json</td></tr>
      <tr><td class="key">Authorization</td><td class="val">Bearer {api_key}</td></tr>
      <tr><td class="key">OpenAI-Organization</td><td class="val">org-{''.join(random.choices(string.ascii_letters, k=24))}</td></tr>
      <tr><td class="key">User-Agent</td><td class="val">PostmanRuntime/7.36.0</td></tr>
    </table>
  </div>
  <div class="section">
    <div class="section-title">Body (JSON)</div>
    <div style="background:#333;padding:12px;border-radius:4px;font-family:monospace;font-size:12px;color:#d4d4d4;">
{{"model": "gpt-4", "messages": [{{"role": "user", "content": "Hello"}}]}}</div>
  </div>
</div>
</div>"""
    })

    # CI/CD pipeline log with secrets
    db_pass = rand_password()
    images.append({
        "filename": "img-cicd-secrets-log.png",
        "category": "credentials", "subcategory": "credentials.password",
        "severity": "critical", "note": "GitHub Actions log leaking database password and API token",
        "html": f"""<style>{TERMINAL_CSS}
.log-line {{ padding: 1px 0; }}
.timestamp {{ color: #6e7681; }}
.step {{ color: #58a6ff; font-weight: bold; }}
.warning {{ color: #d29922; }}
.success {{ color: #3fb950; }}
</style>
<div class="titlebar"><div class="dot dot-red"></div><div class="dot dot-yellow"></div><div class="dot dot-green"></div>
<span style="color:#8b949e;font-size:13px;">GitHub Actions — deploy-production #487</span></div>
<div class="terminal" style="font-size:12px;">
<div class="log-line"><span class="timestamp">2025-01-15T14:23:01Z</span> <span class="step">Run: Deploy to production</span></div>
<div class="log-line"><span class="timestamp">2025-01-15T14:23:02Z</span> Setting up environment variables...</div>
<div class="log-line"><span class="timestamp">2025-01-15T14:23:02Z</span> <span class="warning">WARNING: Secret masking failed for 2 variables</span></div>
<div class="log-line"><span class="timestamp">2025-01-15T14:23:03Z</span> DATABASE_URL=postgres://deploy_user:{db_pass}@prod-db.internal:5432/myapp</div>
<div class="log-line"><span class="timestamp">2025-01-15T14:23:03Z</span> STRIPE_SECRET_KEY=sk_live_51HG{''.join(random.choices(string.ascii_letters + string.digits, k=40))}</div>
<div class="log-line"><span class="timestamp">2025-01-15T14:23:04Z</span> Running database migrations...</div>
<div class="log-line"><span class="timestamp">2025-01-15T14:23:08Z</span> <span class="success">✓</span> Migration 20250115_add_users_table applied</div>
<div class="log-line"><span class="timestamp">2025-01-15T14:23:09Z</span> <span class="success">✓</span> Migration 20250115_add_payments_index applied</div>
<div class="log-line"><span class="timestamp">2025-01-15T14:23:10Z</span> Deploying containers...</div>
<div class="log-line"><span class="timestamp">2025-01-15T14:23:15Z</span> <span class="success">✓</span> web-1 healthy</div>
<div class="log-line"><span class="timestamp">2025-01-15T14:23:18Z</span> <span class="success">✓</span> web-2 healthy</div>
<div class="log-line"><span class="timestamp">2025-01-15T14:23:20Z</span> <span class="success">Deploy complete!</span></div>
</div>"""
    })

    # Browser devtools showing JWT token
    jwt_header = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9"
    jwt_payload = "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9"
    jwt_sig = "".join(random.choices(string.ascii_letters + string.digits + "-_", k=86))
    images.append({
        "filename": "img-devtools-jwt-token.png",
        "category": "credentials", "subcategory": "credentials.token",
        "severity": "high", "note": "Browser DevTools showing JWT auth token in local storage",
        "html": f"""<style>
body {{ margin: 0; font-family: -apple-system, sans-serif; background: #1e1e1e; }}
.devtools {{ max-width: 850px; margin: 20px auto; background: #242424; border-radius: 8px; overflow: hidden; }}
.tab-bar {{ background: #1e1e1e; display: flex; border-bottom: 1px solid #3c3c3c; }}
.tab {{ padding: 8px 16px; color: #999; font-size: 12px; cursor: pointer; }}
.tab.active {{ color: #fff; border-bottom: 2px solid #1a73e8; }}
.panel {{ padding: 12px; }}
.storage-nav {{ display: flex; gap: 0; border-bottom: 1px solid #3c3c3c; padding: 0 12px; }}
.nav-item {{ padding: 6px 12px; color: #999; font-size: 12px; }}
.nav-item.active {{ color: #8ab4f8; border-bottom: 2px solid #8ab4f8; }}
.tree {{ padding: 12px; font-size: 12px; color: #d4d4d4; }}
.tree-item {{ padding: 3px 0; padding-left: 16px; }}
.tree-icon {{ color: #999; margin-right: 6px; }}
.kv-table {{ width: 100%; border-collapse: collapse; margin-top: 8px; }}
.kv-table th {{ text-align: left; color: #999; font-size: 11px; padding: 6px 10px; border-bottom: 1px solid #3c3c3c; }}
.kv-table td {{ padding: 6px 10px; font-family: monospace; font-size: 11px; color: #d4d4d4; border-bottom: 1px solid #3c3c3c; word-break: break-all; }}
</style>
<div class="devtools">
  <div class="tab-bar">
    <div class="tab">Elements</div><div class="tab">Console</div><div class="tab">Network</div>
    <div class="tab active">Application</div><div class="tab">Performance</div>
  </div>
  <div class="storage-nav">
    <div class="nav-item active">Local Storage</div><div class="nav-item">Session Storage</div>
    <div class="nav-item">Cookies</div><div class="nav-item">IndexedDB</div>
  </div>
  <div class="panel" style="display:flex;">
    <div class="tree" style="width:200px;border-right:1px solid #3c3c3c;">
      <div class="tree-item"><span class="tree-icon">▼</span> Local Storage</div>
      <div class="tree-item" style="padding-left:32px;color:#8ab4f8;">https://app.company.com</div>
    </div>
    <div style="flex:1;padding-left:12px;">
      <table class="kv-table">
        <tr><th>Key</th><th>Value</th></tr>
        <tr><td>auth_token</td><td style="color:#ce9178;">{jwt_header}.{jwt_payload}.{jwt_sig}</td></tr>
        <tr><td>refresh_token</td><td style="color:#ce9178;">rt_{''.join(random.choices(string.ascii_letters + string.digits, k=64))}</td></tr>
        <tr><td>user_id</td><td>usr_28491</td></tr>
        <tr><td>user_role</td><td>admin</td></tr>
        <tr><td>session_expiry</td><td>2025-02-15T00:00:00Z</td></tr>
      </table>
    </div>
  </div>
</div>"""
    })

    # --- PII ---

    # Employee directory / HR spreadsheet
    employees = []
    for _ in range(8):
        employees.append({
            "name": fake.name(),
            "email": fake.company_email(),
            "ssn": rand_ssn(),
            "salary": f"${random.randint(65,180)},{random.randint(100,999)}",
            "dept": random.choice(["Engineering", "Sales", "Marketing", "Finance", "HR", "Legal"]),
        })

    emp_rows = ""
    for e in employees:
        emp_rows += f"""<tr>
            <td>{e['name']}</td><td>{e['email']}</td>
            <td>{e['ssn']}</td><td>{e['salary']}</td><td>{e['dept']}</td>
        </tr>"""

    images.append({
        "filename": "img-hr-employee-directory.png",
        "category": "pii", "subcategory": "pii.identity",
        "severity": "critical", "note": "HR spreadsheet with SSNs and salary data",
        "alt_category": "financial", "alt_subcategory": "financial.salary",
        "html": f"""<style>{TABLE_CSS}
.header-bar {{ background: #217346; color: white; padding: 8px 16px; font-size: 13px; display: flex; justify-content: space-between; }}
</style>
<div class="container">
  <div class="header-bar"><span>📊 HR_Employee_Master_2025.xlsx — Sheet1</span><span>Confidential</span></div>
  <h2>Employee Directory — Q1 2025</h2>
  <table>
    <tr><th>Full Name</th><th>Email</th><th>SSN</th><th>Salary</th><th>Department</th></tr>
    {emp_rows}
  </table>
</div>"""
    })

    # Passport scan
    name = fake.name()
    dob = fake.date_of_birth(minimum_age=25, maximum_age=60).strftime("%d %b %Y")
    passport_no = f"{''.join(random.choices(string.ascii_uppercase, k=2))}{''.join(random.choices(string.digits, k=7))}"
    images.append({
        "filename": "img-passport-scan.png",
        "category": "pii", "subcategory": "pii.identity",
        "severity": "critical", "note": "Scanned passport with full name, DOB, and passport number",
        "html": f"""<style>
body {{ margin: 0; font-family: 'Courier New', monospace; background: #e8e8e8; }}
.passport {{ max-width: 650px; margin: 30px auto; background: linear-gradient(135deg, #1a237e 0%, #283593 100%);
             border-radius: 8px; padding: 25px; color: white; box-shadow: 0 4px 20px rgba(0,0,0,0.3); }}
.country {{ font-size: 11px; letter-spacing: 3px; text-transform: uppercase; opacity: 0.8; }}
.title {{ font-size: 22px; font-weight: bold; letter-spacing: 2px; margin: 5px 0 20px; }}
.content {{ display: flex; gap: 20px; }}
.photo {{ width: 120px; height: 150px; background: #c0c0c0; border: 2px solid #fff; border-radius: 4px;
          display: flex; align-items: center; justify-content: center; color: #666; font-size: 40px; }}
.fields {{ flex: 1; }}
.field {{ margin-bottom: 10px; }}
.field-label {{ font-size: 9px; color: rgba(255,255,255,0.6); letter-spacing: 1px; text-transform: uppercase; }}
.field-value {{ font-size: 16px; font-weight: bold; letter-spacing: 1px; }}
.mrz {{ background: rgba(0,0,0,0.3); padding: 12px; margin-top: 15px; border-radius: 4px;
        font-family: 'OCR-B', 'Courier New', monospace; font-size: 13px; letter-spacing: 2px; word-break: break-all; }}
</style>
<div class="passport">
  <div class="country">United States of America</div>
  <div class="title">PASSPORT</div>
  <div class="content">
    <div class="photo">👤</div>
    <div class="fields">
      <div class="field"><div class="field-label">Surname</div><div class="field-value">{name.split()[-1].upper()}</div></div>
      <div class="field"><div class="field-label">Given Names</div><div class="field-value">{' '.join(name.split()[:-1]).upper()}</div></div>
      <div class="field"><div class="field-label">Nationality</div><div class="field-value">UNITED STATES</div></div>
      <div class="field"><div class="field-label">Date of Birth</div><div class="field-value">{dob.upper()}</div></div>
      <div class="field"><div class="field-label">Passport No.</div><div class="field-value">{passport_no}</div></div>
      <div class="field"><div class="field-label">Date of Expiry</div><div class="field-value">15 MAR 2030</div></div>
    </div>
  </div>
  <div class="mrz">P&lt;USA{name.split()[-1].upper()}&lt;&lt;{name.split()[0].upper()}&lt;&lt;&lt;&lt;&lt;&lt;&lt;&lt;&lt;&lt;&lt;&lt;&lt;&lt;&lt;&lt;&lt;&lt;&lt;&lt;&lt;&lt;&lt;&lt;<br/>{passport_no}0USA{''.join(random.choices(string.digits, k=20))}&lt;&lt;&lt;&lt;&lt;&lt;&lt;&lt;&lt;&lt;&lt;&lt;&lt;&lt;00</div>
</div>"""
    })

    # Driver's license
    dl_name = fake.name()
    dl_addr = fake.address().replace('\n', ', ')
    dl_num = f"{''.join(random.choices(string.ascii_uppercase, k=1))}{''.join(random.choices(string.digits, k=12))}"
    images.append({
        "filename": "img-drivers-license.png",
        "category": "pii", "subcategory": "pii.identity",
        "severity": "high", "note": "Driver's license scan with name, address, DOB, license number",
        "html": f"""<style>
body {{ margin: 0; font-family: 'Arial', sans-serif; background: #e8e8e8; }}
.dl {{ max-width: 550px; margin: 40px auto; background: linear-gradient(135deg, #f0f4ff 0%, #dde4ff 100%);
       border-radius: 12px; padding: 20px; box-shadow: 0 4px 20px rgba(0,0,0,0.2);
       border: 1px solid #b0b8d4; position: relative; }}
.state {{ color: #1a237e; font-size: 18px; font-weight: bold; letter-spacing: 2px; }}
.dl-title {{ color: #c62828; font-size: 11px; letter-spacing: 1px; }}
.content {{ display: flex; gap: 15px; margin-top: 15px; }}
.photo {{ width: 100px; height: 120px; background: #c0c8e0; border: 2px solid #8090b0; border-radius: 4px;
          display: flex; align-items: center; justify-content: center; color: #666; font-size: 35px; }}
.info {{ flex: 1; font-size: 12px; color: #333; }}
.info .row {{ display: flex; margin-bottom: 6px; }}
.info .label {{ color: #666; font-size: 10px; width: 40px; flex-shrink: 0; }}
.info .value {{ font-weight: 600; font-size: 13px; }}
.dl-number {{ font-size: 16px; font-weight: bold; color: #c62828; letter-spacing: 1px; margin-top: 10px; }}
.barcode {{ background: repeating-linear-gradient(90deg, #000 0px, #000 2px, #fff 2px, #fff 4px);
            height: 30px; margin-top: 15px; border-radius: 2px; }}
</style>
<div class="dl">
  <div class="state">CALIFORNIA</div>
  <div class="dl-title">DRIVER LICENSE</div>
  <div class="content">
    <div class="photo">👤</div>
    <div class="info">
      <div class="dl-number">DL {dl_num}</div>
      <div class="row"><span class="label">1</span><span class="value">{dl_name.split()[-1].upper()}</span></div>
      <div class="row"><span class="label">2</span><span class="value">{' '.join(dl_name.split()[:-1]).upper()}</span></div>
      <div class="row"><span class="label">8</span><span class="value">{dl_addr}</span></div>
      <div class="row"><span class="label">3</span><span class="value">{fake.date_of_birth(minimum_age=21, maximum_age=55).strftime('%m/%d/%Y')}</span></div>
      <div class="row"><span class="label">EXP</span><span class="value">01/15/2030</span></div>
      <div class="row"><span class="label">CLASS</span><span class="value">C</span></div>
    </div>
  </div>
  <div class="barcode"></div>
</div>"""
    })

    # --- MALICIOUS ---

    # Fake login page (credential harvesting)
    images.append({
        "filename": "img-phishing-login-page.png",
        "category": "malicious", "subcategory": "malicious.phishing",
        "severity": "critical", "note": "Credential harvesting fake Microsoft login page",
        "html": f"""<style>
body {{ margin: 0; font-family: 'Segoe UI', sans-serif; background: #f2f2f2; }}
.login {{ max-width: 440px; margin: 40px auto; background: white; padding: 44px; box-shadow: 0 2px 6px rgba(0,0,0,0.2); }}
.ms-logo {{ font-size: 22px; font-weight: 600; color: #242424; margin-bottom: 16px; }}
.ms-logo span {{ color: #f25022; }}
.subtitle {{ color: #1b1b1b; font-size: 24px; font-weight: 300; margin-bottom: 24px; }}
.input {{ width: 100%; padding: 8px 10px; border: none; border-bottom: 2px solid #666;
          font-size: 15px; margin-bottom: 16px; outline: none; box-sizing: border-box; background: #f5f5f5; }}
.forgot {{ color: #0067b8; font-size: 13px; cursor: pointer; display: block; margin-bottom: 20px; }}
.btn {{ background: #0067b8; color: white; border: none; padding: 10px 0; width: 100%;
        font-size: 15px; cursor: pointer; }}
.create {{ margin-top: 20px; font-size: 13px; color: #666; }}
.create a {{ color: #0067b8; text-decoration: none; }}
.url-bar {{ background: #f0f0f0; padding: 8px 16px; font-size: 12px; color: #666; border-bottom: 1px solid #ddd; text-align: center; }}
.url-bar .lock {{ color: #5a5a5a; }}
.url-bar .domain {{ color: #c00; }}
</style>
<div class="url-bar"><span class="lock">🔒</span> https://<span class="domain">microsofl-login.security-verify.com</span>/auth/signin</div>
<div class="login">
  <div class="ms-logo"><span>■■</span> Microsoft</div>
  <div class="subtitle">Sign in</div>
  <input class="input" type="text" value="john.doe@company.com" />
  <input class="input" type="password" value="••••••••••" />
  <a class="forgot">Forgot password?</a>
  <button class="btn">Sign in</button>
  <div class="create">No account? <a>Create one!</a></div>
</div>"""
    })

    # Social engineering chat / pretexting
    images.append({
        "filename": "img-slack-social-engineering.png",
        "category": "malicious", "subcategory": "malicious.social_engineering",
        "severity": "high", "note": "Slack impersonation — fake IT admin requesting credentials",
        "html": f"""<style>{SLACK_CSS}</style>
<div class="slack">
  <div class="channel"># it-helpdesk</div>
  <div class="msg">
    <div class="avatar" style="background:#4a154b;">👨‍💻</div>
    <div class="msg-content">
      <div class="msg-header"><span class="name">IT-Admin-Support</span> <span class="time">2:14 PM</span></div>
      <div class="msg-text">@channel 🚨 <b>URGENT: Security Update Required</b><br><br>
We've detected unauthorized access attempts on our Azure AD. All employees must verify their credentials immediately to prevent account lockout.<br><br>
Please click below and enter your corporate email + password:<br>
<a style="color:#1264a3;">https://company-sso-verify.azurewebsites.net/auth</a><br><br>
⚠️ Accounts not verified within 2 hours will be <b>temporarily suspended</b>.</div>
    </div>
  </div>
  <div class="msg">
    <div class="avatar" style="background:#2eb67d;">SJ</div>
    <div class="msg-content">
      <div class="msg-header"><span class="name">{fake.name()}</span> <span class="time">2:16 PM</span></div>
      <div class="msg-text">Done! Thanks for the heads up</div>
    </div>
  </div>
  <div class="msg">
    <div class="avatar" style="background:#e01e5a;">ML</div>
    <div class="msg-content">
      <div class="msg-header"><span class="name">{fake.name()}</span> <span class="time">2:17 PM</span></div>
      <div class="msg-text">Just verified mine too. Is this related to that phishing attempt last week?</div>
    </div>
  </div>
  <div class="msg">
    <div class="avatar" style="background:#4a154b;">👨‍💻</div>
    <div class="msg-content">
      <div class="msg-header"><span class="name">IT-Admin-Support</span> <span class="time">2:18 PM</span></div>
      <div class="msg-text">Yes, this is a follow-up security measure. Everyone please verify ASAP. Thank you for your cooperation! 🙏</div>
    </div>
  </div>
</div>"""
    })

    # --- FINANCIAL ---

    # Invoice with bank details
    company = fake.company()
    iban = f"DE{''.join(random.choices(string.digits, k=20))}"
    swift = "".join(random.choices(string.ascii_uppercase, k=8))
    acct = "".join(random.choices(string.digits, k=10))
    images.append({
        "filename": "img-invoice-bank-details.png",
        "category": "financial", "subcategory": "financial.bank_account",
        "severity": "high", "note": "Invoice showing bank account, IBAN, SWIFT/BIC details",
        "html": f"""<style>
body {{ margin: 0; font-family: -apple-system, sans-serif; background: #e8e8e8; }}
.invoice {{ max-width: 650px; margin: 30px auto; background: white; padding: 40px; box-shadow: 0 2px 15px rgba(0,0,0,0.15); }}
.header {{ display: flex; justify-content: space-between; align-items: flex-start; border-bottom: 3px solid #2c3e50; padding-bottom: 15px; margin-bottom: 20px; }}
.company {{ font-size: 22px; font-weight: bold; color: #2c3e50; }}
.inv-title {{ color: #e74c3c; font-size: 28px; font-weight: bold; }}
.meta {{ display: flex; justify-content: space-between; margin-bottom: 25px; font-size: 13px; color: #555; }}
table {{ width: 100%; border-collapse: collapse; margin: 20px 0; }}
th {{ background: #2c3e50; color: white; padding: 10px; text-align: left; font-size: 13px; }}
td {{ padding: 10px; border-bottom: 1px solid #eee; font-size: 13px; }}
.total {{ text-align: right; font-size: 20px; font-weight: bold; color: #2c3e50; margin: 15px 0; }}
.bank {{ background: #f8f9fa; padding: 15px; border-radius: 6px; margin-top: 20px; font-size: 13px; }}
.bank-title {{ font-weight: bold; color: #2c3e50; margin-bottom: 10px; }}
.bank-row {{ display: flex; margin-bottom: 5px; }}
.bank-label {{ width: 130px; color: #666; }}
.bank-value {{ font-weight: 600; font-family: monospace; }}
</style>
<div class="invoice">
  <div class="header">
    <div><div class="company">{company}</div><div style="color:#666;font-size:12px;">{fake.address().replace(chr(10),', ')}</div></div>
    <div class="inv-title">INVOICE</div>
  </div>
  <div class="meta">
    <div><b>Bill To:</b><br>{fake.company()}<br>{fake.address().replace(chr(10),', ')}</div>
    <div><b>Invoice #:</b> INV-2025-{random.randint(1000,9999)}<br><b>Date:</b> January 15, 2025<br><b>Due:</b> February 14, 2025</div>
  </div>
  <table>
    <tr><th>Description</th><th>Qty</th><th>Unit Price</th><th>Amount</th></tr>
    <tr><td>Enterprise Software License</td><td>1</td><td>$24,500.00</td><td>$24,500.00</td></tr>
    <tr><td>Implementation Services</td><td>40 hrs</td><td>$250.00</td><td>$10,000.00</td></tr>
    <tr><td>Annual Support & Maintenance</td><td>1</td><td>$4,900.00</td><td>$4,900.00</td></tr>
  </table>
  <div class="total">Total Due: $39,400.00</div>
  <div class="bank">
    <div class="bank-title">Wire Transfer Payment Details</div>
    <div class="bank-row"><span class="bank-label">Bank Name:</span><span class="bank-value">Deutsche Bank AG</span></div>
    <div class="bank-row"><span class="bank-label">Account Name:</span><span class="bank-value">{company}</span></div>
    <div class="bank-row"><span class="bank-label">Account Number:</span><span class="bank-value">{acct}</span></div>
    <div class="bank-row"><span class="bank-label">IBAN:</span><span class="bank-value">{iban}</span></div>
    <div class="bank-row"><span class="bank-label">SWIFT/BIC:</span><span class="bank-value">{swift}</span></div>
    <div class="bank-row"><span class="bank-label">Routing Number:</span><span class="bank-value">{''.join(random.choices(string.digits, k=9))}</span></div>
  </div>
</div>"""
    })

    # --- MEDICAL ---

    # Lab results
    patient = fake.name()
    dob2 = fake.date_of_birth(minimum_age=30, maximum_age=70).strftime("%m/%d/%Y")
    mrn = f"MRN-{''.join(random.choices(string.digits, k=8))}"
    images.append({
        "filename": "img-lab-results.png",
        "category": "medical", "subcategory": "medical.diagnosis",
        "severity": "critical", "note": "Lab results showing patient name, DOB, MRN, and HIV test result",
        "alt_category": "pii", "alt_subcategory": "pii.health",
        "html": f"""<style>
body {{ margin: 0; font-family: -apple-system, sans-serif; background: #e8e8e8; }}
.report {{ max-width: 650px; margin: 30px auto; background: white; padding: 35px; box-shadow: 0 2px 15px rgba(0,0,0,0.15); }}
.logo {{ color: #0066cc; font-size: 20px; font-weight: bold; }}
.subtitle {{ color: #666; font-size: 12px; }}
.patient-info {{ background: #f0f4ff; padding: 12px; border-radius: 6px; margin: 15px 0; font-size: 13px; display: grid; grid-template-columns: 1fr 1fr; gap: 8px; }}
.pi-label {{ color: #666; font-size: 11px; }}
.pi-value {{ font-weight: 600; }}
h3 {{ color: #0066cc; border-bottom: 2px solid #0066cc; padding-bottom: 5px; font-size: 15px; }}
table {{ width: 100%; border-collapse: collapse; font-size: 12px; margin: 10px 0; }}
th {{ background: #f0f0f0; padding: 8px; text-align: left; }}
td {{ padding: 8px; border-bottom: 1px solid #eee; }}
.abnormal {{ color: #c00; font-weight: bold; }}
.normal {{ color: #28a745; }}
</style>
<div class="report">
  <div class="logo">🏥 MedLab Diagnostics</div>
  <div class="subtitle">4521 Medical Center Drive, Suite 200 • Lab Director: Dr. James Wilson, MD</div>
  <div class="patient-info">
    <div><span class="pi-label">Patient Name</span><br><span class="pi-value">{patient}</span></div>
    <div><span class="pi-label">Date of Birth</span><br><span class="pi-value">{dob2}</span></div>
    <div><span class="pi-label">MRN</span><br><span class="pi-value">{mrn}</span></div>
    <div><span class="pi-label">Ordering Physician</span><br><span class="pi-value">Dr. {fake.name()}</span></div>
  </div>
  <h3>Laboratory Results — Collected: 01/14/2025</h3>
  <table>
    <tr><th>Test</th><th>Result</th><th>Reference Range</th><th>Flag</th></tr>
    <tr><td>Complete Blood Count (CBC)</td><td></td><td></td><td></td></tr>
    <tr><td style="padding-left:20px;">WBC</td><td>7.2 K/uL</td><td>4.5-11.0</td><td class="normal">Normal</td></tr>
    <tr><td style="padding-left:20px;">Hemoglobin</td><td>10.8 g/dL</td><td>12.0-16.0</td><td class="abnormal">LOW</td></tr>
    <tr><td style="padding-left:20px;">Platelets</td><td>145 K/uL</td><td>150-400</td><td class="abnormal">LOW</td></tr>
    <tr><td>Metabolic Panel</td><td></td><td></td><td></td></tr>
    <tr><td style="padding-left:20px;">Glucose</td><td>186 mg/dL</td><td>70-100</td><td class="abnormal">HIGH</td></tr>
    <tr><td style="padding-left:20px;">Creatinine</td><td>1.8 mg/dL</td><td>0.7-1.3</td><td class="abnormal">HIGH</td></tr>
    <tr><td>HIV 1/2 Ab/Ag</td><td class="abnormal">REACTIVE</td><td>Non-Reactive</td><td class="abnormal">ABNORMAL</td></tr>
    <tr><td>Hepatitis C Ab</td><td>Non-Reactive</td><td>Non-Reactive</td><td class="normal">Normal</td></tr>
  </table>
  <p style="font-size:11px;color:#666;margin-top:20px;">⚠️ CONFIDENTIAL — Protected Health Information under HIPAA. Unauthorized disclosure is prohibited.</p>
</div>"""
    })

    # Prescription
    rx_patient = fake.name()
    rx_dob = fake.date_of_birth(minimum_age=40, maximum_age=75).strftime("%m/%d/%Y")
    images.append({
        "filename": "img-prescription-rx.png",
        "category": "medical", "subcategory": "medical.prescription",
        "severity": "high", "note": "Prescription with patient info, controlled substance (Adderall)",
        "html": f"""<style>
body {{ margin: 0; font-family: 'Georgia', serif; background: #e8e8e8; }}
.rx {{ max-width: 550px; margin: 40px auto; background: white; padding: 30px;
       border: 2px solid #333; box-shadow: 0 2px 15px rgba(0,0,0,0.15); }}
.rx-header {{ text-align: center; border-bottom: 2px solid #333; padding-bottom: 15px; margin-bottom: 15px; }}
.doctor {{ font-size: 18px; font-weight: bold; color: #1a237e; }}
.clinic {{ font-size: 12px; color: #555; }}
.rx-symbol {{ font-size: 36px; color: #333; margin: 10px 0; }}
.rx-field {{ margin: 10px 0; font-size: 14px; }}
.rx-label {{ font-weight: bold; color: #555; }}
.rx-line {{ border-bottom: 1px solid #999; padding-bottom: 3px; display: inline-block; min-width: 300px; }}
.sig {{ margin-top: 30px; border-top: 1px solid #999; padding-top: 10px; }}
.controlled {{ background: #fff3cd; border: 1px solid #ffc107; padding: 6px 12px; font-size: 11px; color: #856404; border-radius: 4px; margin-top: 15px; }}
</style>
<div class="rx">
  <div class="rx-header">
    <div class="doctor">Dr. {fake.name()}, MD</div>
    <div class="clinic">Westside Medical Associates<br>{fake.address().split(chr(10))[0]} • Tel: ({random.randint(200,999)}) {random.randint(200,999)}-{random.randint(1000,9999)}</div>
    <div class="clinic">DEA# B{random.choice('ABCDEFG')}{''.join(random.choices(string.digits, k=7))}</div>
  </div>
  <div class="rx-field"><span class="rx-label">Patient:</span> <span class="rx-line">{rx_patient}</span></div>
  <div class="rx-field"><span class="rx-label">DOB:</span> <span class="rx-line">{rx_dob}</span> &nbsp; <span class="rx-label">Date:</span> <span class="rx-line">01/15/2025</span></div>
  <div class="rx-field"><span class="rx-label">Address:</span> <span class="rx-line">{fake.address().split(chr(10))[0]}</span></div>
  <div class="rx-symbol">℞</div>
  <div class="rx-field" style="font-size:16px;">
    <b>Amphetamine/Dextroamphetamine (Adderall XR)</b><br>
    30mg capsules<br>
    #60 (sixty)<br><br>
    Sig: Take 1 capsule by mouth twice daily<br>
    Refills: 0 (zero) — Schedule II
  </div>
  <div class="controlled">⚠️ SCHEDULE II CONTROLLED SUBSTANCE — DEA Form 222 Required</div>
  <div class="sig">
    <div class="rx-label">Prescriber Signature:</div>
    <div style="font-family:'Brush Script MT',cursive;font-size:28px;color:#1a237e;margin-top:5px;">Dr. Signature</div>
  </div>
</div>"""
    })

    # --- CONFIDENTIAL ---

    # NDA / Legal document
    party1 = fake.company()
    party2 = fake.company()
    images.append({
        "filename": "img-nda-agreement.png",
        "category": "confidential", "subcategory": "confidential.legal",
        "severity": "medium", "note": "Non-Disclosure Agreement with company names and terms",
        "html": f"""<style>{DOCUMENT_CSS}
.signature-block {{ display: flex; justify-content: space-between; margin-top: 40px; }}
.sig-box {{ width: 45%; }}
.sig-line {{ border-top: 1px solid #333; margin-top: 40px; padding-top: 5px; font-size: 12px; }}
</style>
<div class="document">
  <div class="header">
    <div style="font-size:22px;font-weight:bold;">NON-DISCLOSURE AGREEMENT</div>
    <div style="font-size:13px;color:#666;">Effective Date: January 15, 2025</div>
  </div>
  <p>This Non-Disclosure Agreement ("Agreement") is entered into between <b>{party1}</b> ("Disclosing Party") and <b>{party2}</b> ("Receiving Party"), collectively referred to as the "Parties."</p>
  <p><b>1. DEFINITION OF CONFIDENTIAL INFORMATION.</b> "Confidential Information" means any proprietary information, trade secrets, technical data, business strategies, customer lists, financial projections, source code, algorithms, product roadmaps, and any other information designated as confidential.</p>
  <p><b>2. OBLIGATIONS.</b> The Receiving Party agrees to: (a) hold all Confidential Information in strict confidence; (b) not disclose any Confidential Information to third parties without prior written consent; (c) use Confidential Information solely for the purpose of evaluating a potential business relationship.</p>
  <p><b>3. TERM.</b> This Agreement shall remain in effect for a period of five (5) years from the Effective Date. The obligations regarding trade secrets shall survive indefinitely.</p>
  <p><b>4. REMEDIES.</b> The Parties acknowledge that unauthorized disclosure may cause irreparable harm and that monetary damages may be insufficient. The Disclosing Party shall be entitled to seek injunctive relief.</p>
  <p><b>5. GOVERNING LAW.</b> This Agreement shall be governed by the laws of the State of Delaware.</p>
  <div class="signature-block">
    <div class="sig-box">
      <div class="sig-line"><b>{party1}</b><br>By: {fake.name()}, CEO</div>
    </div>
    <div class="sig-box">
      <div class="sig-line"><b>{party2}</b><br>By: {fake.name()}, CTO</div>
    </div>
  </div>
</div>"""
    })

    # Board meeting minutes
    images.append({
        "filename": "img-board-minutes.png",
        "category": "confidential", "subcategory": "confidential.internal",
        "severity": "high", "note": "Board meeting minutes with acquisition plans and revenue figures",
        "html": f"""<style>{DOCUMENT_CSS}
ul {{ line-height: 2; color: #333; }}
</style>
<div class="document">
  <div class="header">
    <div style="font-size:18px;font-weight:bold;">{fake.company()} — Board of Directors</div>
    <div style="font-size:14px;margin-top:5px;">CONFIDENTIAL MEETING MINUTES</div>
    <div style="font-size:12px;color:#666;">January 15, 2025 — Special Session</div>
  </div>
  <div class="stamp">BOARD CONFIDENTIAL — DO NOT DISTRIBUTE</div>
  <p><b>Present:</b> {', '.join(fake.name() for _ in range(5))}</p>
  <p><b>1. Q4 Financial Review</b></p>
  <ul>
    <li>Q4 revenue: <b>$47.3M</b> (up 23% YoY), EBITDA margin: 18.2%</li>
    <li>Annual recurring revenue (ARR) reached <b>$142M</b></li>
    <li>Cash position: $89.4M, burn rate: $3.1M/month</li>
  </ul>
  <p><b>2. Project Falcon — Acquisition Target</b></p>
  <ul>
    <li>Target: <b>{fake.company()}</b> (codename: "Falcon")</li>
    <li>Proposed acquisition price: <b>$280M</b> (4.2x revenue multiple)</li>
    <li>Due diligence completion: February 28, 2025</li>
    <li>Board approved proceeding to LOI stage — vote: 5-0</li>
  </ul>
  <p><b>3. Series D Fundraise</b></p>
  <ul>
    <li>Target: $150M at $1.2B pre-money valuation</li>
    <li>Lead investor discussions with {fake.company()} Capital</li>
    <li>Expected close: Q2 2025</li>
  </ul>
  <p style="font-size:11px;color:#888;margin-top:30px;">Minutes prepared by {fake.name()}, Corporate Secretary</p>
</div>"""
    })

    # --- SAFE (Playwright) ---

    # Terminal with safe commands (git log, docker ps)
    images.append({
        "filename": "img-safe-terminal-git.png",
        "category": "safe", "subcategory": "safe.code",
        "severity": "info", "note": "Terminal showing git log output — no sensitive content",
        "html": f"""<style>{TERMINAL_CSS}</style>
<div class="titlebar"><div class="dot dot-red"></div><div class="dot dot-yellow"></div><div class="dot dot-green"></div>
<span style="color:#8b949e;font-size:13px;">Terminal — ~/projects/webapp</span></div>
<div class="terminal">
<span class="prompt">$ </span>git log --oneline -10<br>
<span class="highlight">a3f8b21</span> feat: add user authentication middleware<br>
<span class="highlight">9c2d1e7</span> fix: resolve race condition in cache layer<br>
<span class="highlight">5b8a4f3</span> docs: update API documentation for v2 endpoints<br>
<span class="highlight">1e7c9d2</span> refactor: extract database connection pooling<br>
<span class="highlight">8f3a6b5</span> test: add integration tests for payment flow<br>
<span class="highlight">2d9e1c4</span> chore: update dependencies to latest versions<br>
<span class="highlight">7a5b8d3</span> feat: implement webhook retry mechanism<br>
<span class="highlight">4c1f2e6</span> fix: handle edge case in date parsing<br>
<span class="highlight">6e8d3a1</span> perf: optimize database queries for dashboard<br>
<span class="highlight">3b7c5f9</span> feat: add CSV export for analytics reports<br><br>
<span class="prompt">$ </span>docker ps<br>
CONTAINER ID   IMAGE                    STATUS          PORTS<br>
a1b2c3d4e5f6   webapp:latest            Up 3 hours      0.0.0.0:8080->8080/tcp<br>
f6e5d4c3b2a1   postgres:16              Up 3 hours      0.0.0.0:5432->5432/tcp<br>
1a2b3c4d5e6f   redis:7-alpine           Up 3 hours      0.0.0.0:6379->6379/tcp<br>
</div>"""
    })

    # Safe: error logs (no secrets)
    images.append({
        "filename": "img-safe-error-logs.png",
        "category": "safe", "subcategory": "safe.logs",
        "severity": "info", "note": "Application error logs — stack traces but no credentials or PII",
        "html": f"""<style>{TERMINAL_CSS}
.log-info {{ color: #58a6ff; }}
.log-warn {{ color: #d29922; }}
.log-error {{ color: #f85149; }}
.log-debug {{ color: #8b949e; }}
.log-ts {{ color: #6e7681; }}
</style>
<div class="titlebar"><div class="dot dot-red"></div><div class="dot dot-yellow"></div><div class="dot dot-green"></div>
<span style="color:#8b949e;font-size:13px;">Terminal — tail -f /var/log/app/server.log</span></div>
<div class="terminal" style="font-size:11px;">
<span class="log-ts">[2025-01-15 14:23:01.234]</span> <span class="log-info">INFO </span> Server starting on port 8080<br>
<span class="log-ts">[2025-01-15 14:23:01.567]</span> <span class="log-info">INFO </span> Connected to database (pool_size=20)<br>
<span class="log-ts">[2025-01-15 14:23:01.890]</span> <span class="log-info">INFO </span> Redis connection established<br>
<span class="log-ts">[2025-01-15 14:23:15.123]</span> <span class="log-warn">WARN </span> Slow query detected: GET /api/users (2340ms)<br>
<span class="log-ts">[2025-01-15 14:23:18.456]</span> <span class="log-error">ERROR</span> Request failed: POST /api/orders<br>
<span class="log-ts">[2025-01-15 14:23:18.457]</span> <span class="log-error">ERROR</span>   at OrderService.create (src/services/order.ts:145)<br>
<span class="log-ts">[2025-01-15 14:23:18.458]</span> <span class="log-error">ERROR</span>   at Router.handle (node_modules/express/lib/router.js:74)<br>
<span class="log-ts">[2025-01-15 14:23:18.459]</span> <span class="log-error">ERROR</span>   Cause: ValidationError: quantity must be positive integer<br>
<span class="log-ts">[2025-01-15 14:23:22.789]</span> <span class="log-info">INFO </span> Health check passed (latency: 2ms)<br>
<span class="log-ts">[2025-01-15 14:23:30.012]</span> <span class="log-warn">WARN </span> Rate limit approaching for client_id=app-mobile (890/1000)<br>
<span class="log-ts">[2025-01-15 14:23:45.345]</span> <span class="log-debug">DEBUG</span> Cache hit ratio: 94.2% (last 5m)<br>
<span class="log-ts">[2025-01-15 14:23:50.678]</span> <span class="log-info">INFO </span> Deployment webhook received, preparing graceful shutdown<br>
<span class="log-ts">[2025-01-15 14:23:51.001]</span> <span class="log-info">INFO </span> Draining connections (15 active)...<br>
<span class="log-ts">[2025-01-15 14:23:55.234]</span> <span class="log-info">INFO </span> All connections closed, shutting down<br>
</div>"""
    })

    # Safe: Terraform plan (infrastructure, no secrets)
    images.append({
        "filename": "img-safe-terraform-plan.png",
        "category": "safe", "subcategory": "safe.code",
        "severity": "info", "note": "Terraform plan output showing infrastructure changes — no secrets",
        "html": f"""<style>{TERMINAL_CSS}
.add {{ color: #3fb950; }}
.change {{ color: #d29922; }}
.destroy {{ color: #f85149; }}
</style>
<div class="titlebar"><div class="dot dot-red"></div><div class="dot dot-yellow"></div><div class="dot dot-green"></div>
<span style="color:#8b949e;font-size:13px;">Terminal — terraform plan</span></div>
<div class="terminal" style="font-size:12px;">
Terraform will perform the following actions:<br><br>
<span class="comment"># aws_ecs_service.webapp will be updated in-place</span><br>
<span class="change">~ resource "aws_ecs_service" "webapp"</span> {{<br>
&nbsp;&nbsp;&nbsp;&nbsp;id&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;= "arn:aws:ecs:us-east-1:***:service/prod/webapp"<br>
&nbsp;&nbsp;&nbsp;&nbsp;name&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;= "webapp"<br>
&nbsp;&nbsp;<span class="change">~ desired_count&nbsp;&nbsp;&nbsp;= 3 -> 5</span><br>
&nbsp;&nbsp;<span class="change">~ task_definition = "webapp:42" -> "webapp:43"</span><br>
}}<br><br>
<span class="comment"># aws_cloudwatch_metric_alarm.high_cpu will be created</span><br>
<span class="add">+ resource "aws_cloudwatch_metric_alarm" "high_cpu"</span> {{<br>
&nbsp;&nbsp;<span class="add">+ alarm_name&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;= "webapp-high-cpu"</span><br>
&nbsp;&nbsp;<span class="add">+ comparison&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;= "GreaterThanThreshold"</span><br>
&nbsp;&nbsp;<span class="add">+ threshold&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;= 80</span><br>
&nbsp;&nbsp;<span class="add">+ period&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;= 300</span><br>
}}<br><br>
<span class="comment"># aws_s3_bucket.old_logs will be destroyed</span><br>
<span class="destroy">- resource "aws_s3_bucket" "old_logs"</span> {{<br>
&nbsp;&nbsp;<span class="destroy">- bucket = "company-old-logs-2023"</span><br>
}}<br><br>
Plan: <span class="add">1 to add</span>, <span class="change">1 to change</span>, <span class="destroy">1 to destroy</span>.<br>
</div>"""
    })

    # Render all with Playwright
    with sync_playwright() as p:
        browser = p.chromium.launch()
        page = browser.new_page(viewport={"width": 900, "height": 700})

        for img in images:
            filepath = OUT_DIR / img["filename"]
            if filepath.exists():
                print(f"  SKIP {img['filename']} (already exists)")
            else:
                page.set_content(img["html"])
                time.sleep(0.3)
                page.screenshot(path=str(filepath), full_page=True)
                size = os.path.getsize(filepath) // 1024
                print(f"  Generated {img['filename']} ({size}KB)")

            save_sample(
                img["category"], img["subcategory"], img["severity"],
                img["filename"], img["note"],
                img.get("alt_category", ""), img.get("alt_subcategory", ""),
            )

        browser.close()


# ============================================================
# MAIN
# ============================================================

def main():
    download_safe_images()
    generate_sensitive_images()

    # Save updated ground truth
    with open(GROUND_TRUTH_PATH, "w") as f:
        json.dump(GROUND_TRUTH, f, indent=2)

    total_images = sum(1 for s in GROUND_TRUTH if s["file"].startswith("images/"))
    print(f"\n=== Done! Total image samples: {total_images} ===")
    print(f"Ground truth updated: {GROUND_TRUTH_PATH}")

    # Summary by category
    cats = {}
    for s in GROUND_TRUTH:
        if s["file"].startswith("images/"):
            cats[s["category"]] = cats.get(s["category"], 0) + 1
    for c in sorted(cats):
        print(f"  {c:<15s} {cats[c]}")


if __name__ == "__main__":
    main()
