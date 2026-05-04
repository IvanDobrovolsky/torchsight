#!/usr/bin/env python3
"""Generate 50 realistic image samples for TorchSight eval.
- Sensitive: rendered via Playwright (terminal, IDE, email, forms, chat)
- Safe: scraped from public domain sources (Unsplash, Wikipedia, gov sites)
"""
import json
import os
import random
import string
import time
from pathlib import Path
from faker import Faker
from playwright.sync_api import sync_playwright

fake = Faker()
Faker.seed(2026)
random.seed(2026)

OUT_DIR = Path(__file__).parent.parent / "data" / "eval-1000-synthetic" / "images"
OUT_DIR.mkdir(parents=True, exist_ok=True)

GROUND_TRUTH_PATH = Path(__file__).parent.parent / "data" / "eval-1000-synthetic" / "ground-truth.json"

# Load existing ground truth to append
if GROUND_TRUTH_PATH.exists():
    with open(GROUND_TRUTH_PATH) as f:
        GROUND_TRUTH = json.load(f)
    START_ID = max(s["id"] for s in GROUND_TRUTH) + 1
else:
    GROUND_TRUTH = []
    START_ID = 1001

SAMPLE_ID = START_ID - 1

def next_id():
    global SAMPLE_ID
    SAMPLE_ID += 1
    return SAMPLE_ID

def rand_hex(n):
    return ''.join(random.choices('0123456789abcdef', k=n))

def rand_b64(n):
    chars = string.ascii_letters + string.digits + '+/'
    return ''.join(random.choices(chars, k=n))

def rand_aws_key():
    return 'AKIA' + ''.join(random.choices(string.ascii_uppercase + string.digits, k=16))

def rand_aws_secret():
    return ''.join(random.choices(string.ascii_letters + string.digits + '+/', k=40))

def rand_password():
    return ''.join(random.choices(string.ascii_letters, k=8)) + \
           ''.join(random.choices(string.digits, k=3)) + random.choice('!@#$%')

def rand_ssn():
    return f"{random.randint(100,999)}-{random.randint(10,99)}-{random.randint(1000,9999)}"

def rand_cc():
    prefix = random.choice(['4532','5412','3782','6011'])
    rest = ''.join([str(random.randint(0,9)) for _ in range(12)])
    return f"{prefix[:4]} {prefix[3]}{rest[:3]} {rest[3:7]} {rest[7:11]}"

def save_sample(category, subcategory, severity, filename, note):
    sid = next_id()
    GROUND_TRUTH.append({
        "id": sid,
        "file": f"images/{filename}",
        "category": category,
        "subcategory": subcategory,
        "severity": severity,
        "bucket": "images",
        "note": note,
    })
    return sid

# ============================================================
# HTML TEMPLATES FOR PLAYWRIGHT RENDERING
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
.titlebar-text { color: #8b949e; font-size: 12px; margin-left: 8px; font-family: sans-serif; }
.prompt { color: #58a6ff; }
.comment { color: #6e7681; }
.key { color: #ff7b72; }
.value { color: #a5d6ff; }
.string { color: #a5d6ff; }
.warn { color: #d29922; }
.error { color: #f85149; }
"""

VSCODE_CSS = """
body { margin: 0; padding: 0; background: #1e1e1e; font-family: 'Menlo', monospace; font-size: 13px; }
.editor { display: flex; height: 600px; }
.sidebar { width: 48px; background: #252526; display: flex; flex-direction: column; align-items: center; padding-top: 10px; gap: 20px; }
.sidebar-icon { width: 24px; height: 24px; background: #858585; border-radius: 4px; opacity: 0.6; }
.explorer { width: 220px; background: #252526; border-right: 1px solid #3c3c3c; padding: 10px; color: #cccccc; font-size: 11px; }
.explorer-title { text-transform: uppercase; font-size: 10px; color: #bbbbbb; letter-spacing: 1px; margin-bottom: 8px; }
.file-item { padding: 2px 8px; cursor: pointer; border-radius: 3px; }
.file-item.active { background: #37373d; color: #ffffff; }
.file-item:hover { background: #2a2d2e; }
.code-area { flex: 1; background: #1e1e1e; padding: 0; }
.tab-bar { background: #252526; display: flex; height: 35px; border-bottom: 1px solid #3c3c3c; }
.tab { padding: 8px 16px; color: #969696; font-size: 12px; border-right: 1px solid #3c3c3c; display: flex; align-items: center; gap: 6px; }
.tab.active { background: #1e1e1e; color: #ffffff; border-top: 1px solid #007acc; }
.code { padding: 10px 0; overflow: hidden; }
.line { display: flex; height: 20px; }
.line-num { width: 50px; text-align: right; padding-right: 15px; color: #858585; user-select: none; }
.line-content { color: #d4d4d4; white-space: pre; }
.env-key { color: #9cdcfe; }
.env-eq { color: #d4d4d4; }
.env-val { color: #ce9178; }
.env-comment { color: #6a9955; }
.status-bar { position: fixed; bottom: 0; left: 0; right: 0; height: 22px; background: #007acc; display: flex; align-items: center; padding: 0 10px; color: #ffffff; font-size: 11px; gap: 15px; }
"""

SLACK_CSS = """
body { margin: 0; background: #1a1d21; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; }
.slack { max-width: 800px; margin: 20px auto; }
.channel-header { padding: 12px 20px; border-bottom: 1px solid #35373b; color: #d1d2d3; font-size: 15px; font-weight: 700; }
.messages { padding: 20px; }
.message { display: flex; gap: 12px; margin-bottom: 16px; }
.avatar { width: 36px; height: 36px; border-radius: 4px; flex-shrink: 0; }
.msg-content { flex: 1; }
.msg-header { display: flex; gap: 8px; align-items: baseline; margin-bottom: 4px; }
.msg-name { color: #d1d2d3; font-weight: 700; font-size: 14px; }
.msg-time { color: #616061; font-size: 11px; }
.msg-text { color: #d1d2d3; font-size: 14px; line-height: 1.5; }
.msg-code { background: #1d2025; border: 1px solid #35373b; border-radius: 4px; padding: 8px 12px; font-family: monospace; font-size: 12px; color: #e8912d; margin: 4px 0; white-space: pre; }
"""

EMAIL_CSS = """
body { margin: 0; background: #f5f5f5; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; }
.email { max-width: 700px; margin: 20px auto; background: white; border-radius: 8px; box-shadow: 0 2px 8px rgba(0,0,0,0.1); overflow: hidden; }
.email-header { padding: 20px 24px; border-bottom: 1px solid #eee; }
.email-subject { font-size: 18px; font-weight: 600; color: #1a1a1a; margin-bottom: 12px; }
.email-meta { font-size: 13px; color: #666; line-height: 1.8; }
.email-meta b { color: #333; }
.email-body { padding: 24px; font-size: 14px; line-height: 1.7; color: #333; }
.email-body a { color: #1a73e8; }
.btn-danger { display: inline-block; padding: 12px 32px; background: #d93025; color: white !important; text-decoration: none; border-radius: 4px; font-weight: 600; margin: 16px 0; }
.warning-box { background: #fef7e0; border: 1px solid #f9e6a5; border-radius: 4px; padding: 12px 16px; margin: 12px 0; font-size: 13px; color: #856404; }
"""

FORM_CSS = """
body { margin: 0; background: #f0f0f0; font-family: 'Courier New', monospace; }
.form { max-width: 650px; margin: 20px auto; background: white; padding: 40px; box-shadow: 0 2px 8px rgba(0,0,0,0.15); }
.form-title { text-align: center; font-size: 16px; font-weight: bold; margin-bottom: 4px; }
.form-subtitle { text-align: center; font-size: 11px; color: #666; margin-bottom: 20px; }
.form-row { display: flex; gap: 20px; margin-bottom: 8px; }
.form-field { flex: 1; }
.form-label { font-size: 8px; color: #666; text-transform: uppercase; }
.form-value { font-size: 13px; border-bottom: 1px solid #999; padding: 4px 0; min-height: 18px; }
.form-box { border: 1px solid #999; padding: 4px 8px; font-size: 13px; text-align: right; }
.section { margin-top: 16px; padding-top: 8px; border-top: 1px solid #ccc; }
.section-title { font-size: 10px; font-weight: bold; color: #333; margin-bottom: 8px; }
"""


def render_html(page, html, filename, width=900, height=600):
    """Render HTML content to a PNG screenshot."""
    page.set_viewport_size({"width": width, "height": height})
    page.set_content(html)
    page.wait_for_timeout(300)
    filepath = OUT_DIR / filename
    page.screenshot(path=str(filepath), full_page=False)
    return filename


def gen_terminal_screenshots(page):
    """Terminal screenshots showing credentials, commands, etc."""
    samples = []

    # 1. AWS credentials in terminal env output
    key = rand_aws_key()
    secret = rand_aws_secret()
    html = f"""<style>{TERMINAL_CSS}</style>
<div class="titlebar"><div class="dot dot-red"></div><div class="dot dot-yellow"></div><div class="dot dot-green"></div><span class="titlebar-text">Terminal — bash — 120×40</span></div>
<div class="terminal">
<span class="prompt">admin@prod-server:~$</span> env | grep AWS<br>
<span class="key">AWS_ACCESS_KEY_ID</span>=<span class="value">{key}</span><br>
<span class="key">AWS_SECRET_ACCESS_KEY</span>=<span class="value">{secret}</span><br>
<span class="key">AWS_DEFAULT_REGION</span>=<span class="value">us-east-1</span><br>
<span class="key">AWS_SESSION_TOKEN</span>=<span class="value">{rand_b64(120)}</span><br>
<br>
<span class="prompt">admin@prod-server:~$</span> aws s3 ls<br>
<span class="value">2025-09-14 08:21:33 company-backups-prod</span><br>
<span class="value">2025-11-02 14:55:01 customer-data-encrypted</span><br>
<span class="value">2025-12-18 09:12:44 ml-training-datasets</span><br>
<br>
<span class="prompt">admin@prod-server:~$</span> <span style="opacity:0.7">█</span>
</div>"""
    fname = render_html(page, html, "img-terminal-aws-keys.png")
    samples.append(("credentials", "credentials.api_key", "critical", fname, "Terminal screenshot showing AWS credentials via env command"))

    # 2. Database connection with password visible
    pwd = rand_password()
    html = f"""<style>{TERMINAL_CSS}</style>
<div class="titlebar"><div class="dot dot-red"></div><div class="dot dot-yellow"></div><div class="dot dot-green"></div><span class="titlebar-text">Terminal — psql — prod-db</span></div>
<div class="terminal">
<span class="prompt">devops@bastion:~$</span> cat /opt/app/config/database.yml<br>
<span class="comment"># Production database configuration</span><br>
production:<br>
&nbsp;&nbsp;adapter: postgresql<br>
&nbsp;&nbsp;host: <span class="value">db-primary.internal.company.com</span><br>
&nbsp;&nbsp;port: <span class="value">5432</span><br>
&nbsp;&nbsp;database: <span class="value">app_production</span><br>
&nbsp;&nbsp;username: <span class="value">app_admin</span><br>
&nbsp;&nbsp;password: <span class="error">{pwd}</span><br>
&nbsp;&nbsp;pool: <span class="value">25</span><br>
&nbsp;&nbsp;timeout: <span class="value">5000</span><br>
<br>
<span class="prompt">devops@bastion:~$</span> psql "postgresql://app_admin:{pwd}@db-primary.internal.company.com:5432/app_production"<br>
<span class="value">psql (15.4)</span><br>
<span class="value">SSL connection (protocol: TLSv1.3, cipher: TLS_AES_256_GCM_SHA384)</span><br>
<span class="value">Type "help" for help.</span><br>
<br>
<span class="prompt">app_production=#</span> <span style="opacity:0.7">█</span>
</div>"""
    fname = render_html(page, html, "img-terminal-db-password.png")
    samples.append(("credentials", "credentials.password", "critical", fname, "Terminal showing database config with password and active psql connection"))

    # 3. Git log showing accidentally committed secrets
    token = f"ghp_{rand_b64(36)}"
    html = f"""<style>{TERMINAL_CSS}</style>
<div class="titlebar"><div class="dot dot-red"></div><div class="dot dot-yellow"></div><div class="dot dot-green"></div><span class="titlebar-text">Terminal — git log</span></div>
<div class="terminal">
<span class="prompt">dev@laptop:~/project$</span> git log --oneline -5<br>
<span class="warn">a3f8c21</span> fix: remove hardcoded token<br>
<span class="warn">b7d2e45</span> feat: add API integration<br>
<span class="warn">c1a9f67</span> chore: update dependencies<br>
<br>
<span class="prompt">dev@laptop:~/project$</span> git show b7d2e45<br>
<span class="comment">commit b7d2e45a8c3f1d9e6b2a4c7f0e8d3b5a1c9f7e2d</span><br>
<span class="comment">Author: {fake.name()} &lt;{fake.email()}&gt;</span><br>
<br>
<span class="error">+GITHUB_TOKEN="{token}"</span><br>
<span class="error">+OPENAI_API_KEY="sk-proj-{rand_b64(48)}"</span><br>
<span class="string">+API_BASE_URL="https://api.company.com/v2"</span><br>
</div>"""
    fname = render_html(page, html, "img-terminal-git-secrets.png")
    samples.append(("credentials", "credentials.token", "critical", fname, "Git log showing accidentally committed API tokens"))

    # 4. SSH session showing private key
    key_lines = '<br>'.join([rand_b64(64) for _ in range(8)])
    html = f"""<style>{TERMINAL_CSS}</style>
<div class="titlebar"><div class="dot dot-red"></div><div class="dot dot-yellow"></div><div class="dot dot-green"></div><span class="titlebar-text">Terminal — ssh key exposure</span></div>
<div class="terminal">
<span class="prompt">user@workstation:~$</span> cat ~/.ssh/id_rsa<br>
<span class="error">-----BEGIN RSA PRIVATE KEY-----</span><br>
<span class="value">{key_lines}</span><br>
<span class="error">-----END RSA PRIVATE KEY-----</span><br>
<br>
<span class="prompt">user@workstation:~$</span> ssh-keygen -l -f ~/.ssh/id_rsa<br>
<span class="value">4096 SHA256:{rand_b64(43)} user@workstation (RSA)</span><br>
</div>"""
    fname = render_html(page, html, "img-terminal-ssh-key.png")
    samples.append(("credentials", "credentials.private_key", "critical", fname, "Terminal showing SSH private key contents"))

    # 5. kubectl showing secrets
    html = f"""<style>{TERMINAL_CSS}</style>
<div class="titlebar"><div class="dot dot-red"></div><div class="dot dot-yellow"></div><div class="dot dot-green"></div><span class="titlebar-text">Terminal — kubectl</span></div>
<div class="terminal">
<span class="prompt">admin@k8s-master:~$</span> kubectl get secret app-secrets -o json | jq '.data | map_values(@base64d)'<br>
{{<br>
&nbsp;&nbsp;<span class="key">"DATABASE_PASSWORD"</span>: <span class="string">"{rand_password()}"</span>,<br>
&nbsp;&nbsp;<span class="key">"STRIPE_SECRET_KEY"</span>: <span class="string">"sk_live_{rand_b64(48)}"</span>,<br>
&nbsp;&nbsp;<span class="key">"JWT_SECRET"</span>: <span class="string">"{rand_hex(64)}"</span>,<br>
&nbsp;&nbsp;<span class="key">"SENDGRID_API_KEY"</span>: <span class="string">"SG.{rand_b64(22)}.{rand_b64(43)}"</span>,<br>
&nbsp;&nbsp;<span class="key">"REDIS_PASSWORD"</span>: <span class="string">"{rand_password()}"</span><br>
}}<br>
<span class="prompt">admin@k8s-master:~$</span> <span style="opacity:0.7">█</span>
</div>"""
    fname = render_html(page, html, "img-terminal-k8s-secrets.png")
    samples.append(("credentials", "credentials.cloud_config", "critical", fname, "kubectl showing decoded Kubernetes secrets"))

    return samples


def gen_vscode_screenshots(page):
    """VS Code editor screenshots."""
    samples = []

    # 1. .env file open in VS Code
    env_lines = [
        ("# Production environment config", "env-comment"),
        ("NODE_ENV=production", "env-key", "env-eq", "env-val"),
        ("PORT=3000", "env-key", "env-eq", "env-val"),
        ("", ""),
        ("# Database", "env-comment"),
        (f"DATABASE_URL=postgres://admin:{rand_password()}@db.internal:5432/prod", "env-key", "env-eq", "env-val"),
        (f"REDIS_URL=redis://:{rand_password()}@cache.internal:6379", "env-key", "env-eq", "env-val"),
        ("", ""),
        ("# API Keys", "env-comment"),
        (f"STRIPE_SECRET_KEY=sk_live_{rand_b64(48)}", "env-key", "env-eq", "env-val"),
        (f"OPENAI_API_KEY=sk-proj-{rand_b64(48)}", "env-key", "env-eq", "env-val"),
        (f"SENDGRID_API_KEY=SG.{rand_b64(22)}.{rand_b64(43)}", "env-key", "env-eq", "env-val"),
        ("", ""),
        ("# Auth", "env-comment"),
        (f"JWT_SECRET={rand_hex(64)}", "env-key", "env-eq", "env-val"),
        (f"SESSION_SECRET={rand_hex(48)}", "env-key", "env-eq", "env-val"),
    ]

    lines_html = ""
    for i, parts in enumerate(env_lines, 1):
        text = parts[0]
        if text.startswith("#"):
            content = f'<span class="env-comment">{text}</span>'
        elif "=" in text:
            k, v = text.split("=", 1)
            content = f'<span class="env-key">{k}</span><span class="env-eq">=</span><span class="env-val">{v}</span>'
        else:
            content = text
        lines_html += f'<div class="line"><span class="line-num">{i}</span><span class="line-content">{content}</span></div>\n'

    html = f"""<style>{VSCODE_CSS}</style>
<div class="editor">
    <div class="sidebar">{''.join(['<div class="sidebar-icon"></div>' for _ in range(5)])}</div>
    <div class="explorer">
        <div class="explorer-title">Explorer</div>
        <div class="file-item">📁 src</div>
        <div class="file-item">&nbsp;&nbsp;📄 index.js</div>
        <div class="file-item">&nbsp;&nbsp;📄 server.js</div>
        <div class="file-item active">📄 .env</div>
        <div class="file-item">📄 .env.example</div>
        <div class="file-item">📄 package.json</div>
        <div class="file-item">📄 docker-compose.yml</div>
    </div>
    <div class="code-area">
        <div class="tab-bar">
            <div class="tab active">📄 .env</div>
            <div class="tab">📄 server.js</div>
        </div>
        <div class="code">{lines_html}</div>
    </div>
</div>
<div class="status-bar"><span>UTF-8</span><span>LF</span><span>ENV</span><span>Ln 1, Col 1</span></div>"""
    fname = render_html(page, html, "img-vscode-env-file.png", width=1100, height=600)
    samples.append(("credentials", "credentials.api_key", "critical", fname, "VS Code editor with .env file containing API keys"))

    # 2. Python file with hardcoded credentials
    py_lines = [
        ('# config.py — DO NOT COMMIT', 'env-comment'),
        ('import os', ''),
        ('', ''),
        ('class Config:', ''),
        (f'    DB_HOST = "db-prod.internal.company.com"', ''),
        (f'    DB_USER = "admin"', ''),
        (f'    DB_PASS = "{rand_password()}"', ''),
        (f'    SECRET_KEY = "{rand_hex(48)}"', ''),
        (f'    AWS_KEY = "{rand_aws_key()}"', ''),
        (f'    AWS_SECRET = "{rand_aws_secret()}"', ''),
        ('', ''),
        ('class ProdConfig(Config):', ''),
        ('    DEBUG = False', ''),
        (f'    REDIS_URL = "redis://:{rand_password()}@cache:6379"', ''),
    ]
    lines_html = ""
    for i, (text, cls) in enumerate(py_lines, 1):
        if text.startswith('#'):
            content = f'<span class="env-comment">{text}</span>'
        elif '=' in text and ('"' in text or "'" in text):
            eq_pos = text.index('=')
            k = text[:eq_pos+1]
            v = text[eq_pos+1:]
            content = f'<span class="env-key">{k}</span><span class="env-val">{v}</span>'
        else:
            content = f'<span style="color:#d4d4d4">{text}</span>'
        lines_html += f'<div class="line"><span class="line-num">{i}</span><span class="line-content">{content}</span></div>\n'

    html = f"""<style>{VSCODE_CSS}</style>
<div class="editor">
    <div class="sidebar">{''.join(['<div class="sidebar-icon"></div>' for _ in range(5)])}</div>
    <div class="explorer">
        <div class="explorer-title">Explorer</div>
        <div class="file-item">📁 app</div>
        <div class="file-item active">&nbsp;&nbsp;📄 config.py</div>
        <div class="file-item">&nbsp;&nbsp;📄 models.py</div>
        <div class="file-item">&nbsp;&nbsp;📄 views.py</div>
        <div class="file-item">📄 requirements.txt</div>
    </div>
    <div class="code-area">
        <div class="tab-bar"><div class="tab active">🐍 config.py</div></div>
        <div class="code">{lines_html}</div>
    </div>
</div>
<div class="status-bar"><span>UTF-8</span><span>LF</span><span>Python</span><span>Ln 1, Col 1</span></div>"""
    fname = render_html(page, html, "img-vscode-python-secrets.png", width=1100, height=600)
    samples.append(("credentials", "credentials.password", "critical", fname, "VS Code showing Python config with hardcoded credentials"))

    return samples


def gen_slack_screenshots(page):
    """Slack chat screenshots with leaked credentials."""
    samples = []

    colors = ['#e03e3e','#36a64f','#2eb886','#e67e22','#9b59b6','#3498db']

    # 1. API key shared in Slack
    html = f"""<style>{SLACK_CSS}</style>
<div class="slack">
    <div class="channel-header"># eng-backend</div>
    <div class="messages">
        <div class="message">
            <div class="avatar" style="background:{random.choice(colors)}"></div>
            <div class="msg-content">
                <div class="msg-header"><span class="msg-name">{fake.first_name()} {fake.last_name()[0]}.</span><span class="msg-time">11:34 AM</span></div>
                <div class="msg-text">Hey can someone share the production Stripe key? I need to debug a webhook issue</div>
            </div>
        </div>
        <div class="message">
            <div class="avatar" style="background:{random.choice(colors)}"></div>
            <div class="msg-content">
                <div class="msg-header"><span class="msg-name">{fake.first_name()} {fake.last_name()[0]}.</span><span class="msg-time">11:36 AM</span></div>
                <div class="msg-text">Sure, here you go:
                <div class="msg-code">STRIPE_SECRET_KEY=sk_live_{rand_b64(48)}
STRIPE_WEBHOOK_SECRET=whsec_{rand_b64(32)}</div>
                Don't forget to rotate it when you're done 👍</div>
            </div>
        </div>
        <div class="message">
            <div class="avatar" style="background:{random.choice(colors)}"></div>
            <div class="msg-content">
                <div class="msg-header"><span class="msg-name">{fake.first_name()} {fake.last_name()[0]}.</span><span class="msg-time">11:37 AM</span></div>
                <div class="msg-text">Thanks! Also need the OpenAI key for the embeddings service</div>
            </div>
        </div>
        <div class="message">
            <div class="avatar" style="background:{random.choice(colors)}"></div>
            <div class="msg-content">
                <div class="msg-header"><span class="msg-name">{fake.first_name()} {fake.last_name()[0]}.</span><span class="msg-time">11:38 AM</span></div>
                <div class="msg-text"><div class="msg-code">OPENAI_API_KEY=sk-proj-{rand_b64(48)}</div></div>
            </div>
        </div>
    </div>
</div>"""
    fname = render_html(page, html, "img-slack-api-keys.png", width=850, height=500)
    samples.append(("credentials", "credentials.api_key", "critical", fname, "Slack conversation sharing API keys in chat"))

    # 2. PII shared in Slack
    html = f"""<style>{SLACK_CSS}</style>
<div class="slack">
    <div class="channel-header"># hr-operations</div>
    <div class="messages">
        <div class="message">
            <div class="avatar" style="background:{random.choice(colors)}"></div>
            <div class="msg-content">
                <div class="msg-header"><span class="msg-name">{fake.first_name()} {fake.last_name()[0]}.</span><span class="msg-time">2:14 PM</span></div>
                <div class="msg-text">Need to verify the new hire's info for payroll setup. @{fake.first_name()} can you confirm?</div>
            </div>
        </div>
        <div class="message">
            <div class="avatar" style="background:{random.choice(colors)}"></div>
            <div class="msg-content">
                <div class="msg-header"><span class="msg-name">{fake.first_name()} {fake.last_name()[0]}.</span><span class="msg-time">2:18 PM</span></div>
                <div class="msg-text">Here's the info from the onboarding form:
                <div class="msg-code">Name: {fake.name()}
SSN: {rand_ssn()}
DOB: {fake.date_of_birth(minimum_age=22,maximum_age=45).strftime("%m/%d/%Y")}
Address: {fake.address().replace(chr(10), ", ")}
Bank Routing: {random.randint(100000000,999999999)}
Bank Account: {random.randint(10000000,9999999999)}</div>
                Let me know if you need anything else</div>
            </div>
        </div>
    </div>
</div>"""
    fname = render_html(page, html, "img-slack-pii-shared.png", width=850, height=450)
    samples.append(("pii", "pii.identity", "critical", fname, "Slack conversation sharing employee PII including SSN"))

    return samples


def gen_email_screenshots(page):
    """Email screenshots — phishing and legitimate."""
    samples = []

    # 1. Phishing email
    company = fake.company()
    html = f"""<style>{EMAIL_CSS}</style>
<div class="email">
    <div class="email-header">
        <div class="email-subject">⚠️ Urgent: Unusual sign-in activity on your account</div>
        <div class="email-meta">
            <b>From:</b> security@{company.lower().replace(' ','-')}-alerts.com<br>
            <b>To:</b> {fake.email()}<br>
            <b>Date:</b> {fake.date_time_this_year().strftime("%b %d, %Y %I:%M %p")}
        </div>
    </div>
    <div class="email-body">
        <p>Dear Customer,</p>
        <p>We detected a sign-in attempt from an unrecognized device:</p>
        <div class="warning-box">
            <strong>Location:</strong> {fake.city()}, {fake.country()}<br>
            <strong>IP Address:</strong> {random.randint(10,200)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}<br>
            <strong>Device:</strong> Unknown Linux Device<br>
            <strong>Time:</strong> {fake.date_time_this_year().strftime("%B %d, %Y at %I:%M %p")} UTC
        </div>
        <p>If this wasn't you, your account may be compromised. Please verify your identity immediately:</p>
        <a href="#" class="btn-danger">Verify My Account</a>
        <p style="font-size:12px;color:#999;margin-top:20px;">If you don't take action within 24 hours, your account will be temporarily suspended for your protection.</p>
        <p>Sincerely,<br>{company} Security Team</p>
    </div>
</div>"""
    fname = render_html(page, html, "img-email-phishing.png", width=750, height=650)
    samples.append(("malicious", "malicious.phishing", "high", fname, "Phishing email impersonating security alert"))

    # 2. Another phishing — password reset
    html = f"""<style>{EMAIL_CSS}</style>
<div class="email">
    <div class="email-header">
        <div class="email-subject">Password Reset Request — Action Required</div>
        <div class="email-meta">
            <b>From:</b> noreply@{fake.domain_name()}-support.net<br>
            <b>To:</b> {fake.email()}<br>
            <b>Date:</b> {fake.date_time_this_year().strftime("%b %d, %Y %I:%M %p")}
        </div>
    </div>
    <div class="email-body">
        <p>Hi {fake.first_name()},</p>
        <p>We received a request to reset the password for your account. Use the link below to set a new password:</p>
        <a href="#" class="btn-danger" style="background:#1a73e8;">Reset Password</a>
        <p>This link expires in 15 minutes.</p>
        <p style="font-size:12px;color:#999;">If you didn't request this, someone may have entered your email address by mistake. You can safely ignore this email.</p>
        <p>— The Support Team</p>
    </div>
</div>"""
    fname = render_html(page, html, "img-email-phishing-reset.png", width=750, height=550)
    samples.append(("malicious", "malicious.phishing", "high", fname, "Phishing email disguised as password reset"))

    return samples


def gen_form_screenshots(page):
    """Scanned forms — W-2, medical, etc."""
    samples = []

    # 1. W-2 Tax Form
    name = fake.name()
    ssn = rand_ssn()
    html = f"""<style>{FORM_CSS}</style>
<div class="form">
    <div class="form-title">Form W-2 Wage and Tax Statement</div>
    <div class="form-subtitle">Department of the Treasury — Internal Revenue Service — {random.randint(2023,2025)}</div>
    <div class="form-row">
        <div class="form-field"><div class="form-label">a Employee's SSN</div><div class="form-value" style="font-weight:bold;color:#c00">{ssn}</div></div>
        <div class="form-field"><div class="form-label">b Employer ID (EIN)</div><div class="form-value">{random.randint(10,99)}-{random.randint(1000000,9999999)}</div></div>
    </div>
    <div class="form-row">
        <div class="form-field" style="flex:2"><div class="form-label">c Employer's name, address</div><div class="form-value">{fake.company()}<br>{fake.address().replace(chr(10),'<br>')}</div></div>
    </div>
    <div class="form-row">
        <div class="form-field" style="flex:2"><div class="form-label">e Employee's name</div><div class="form-value" style="font-size:16px;font-weight:bold">{name}</div></div>
    </div>
    <div class="form-row">
        <div class="form-field" style="flex:2"><div class="form-label">f Employee's address</div><div class="form-value">{fake.address().replace(chr(10),', ')}</div></div>
    </div>
    <div class="section"><div class="section-title">Wages and Taxes</div></div>
    <div class="form-row">
        <div class="form-field"><div class="form-label">1 Wages, tips, other</div><div class="form-box">${random.randint(50000,200000):,}.00</div></div>
        <div class="form-field"><div class="form-label">2 Federal income tax</div><div class="form-box">${random.randint(8000,50000):,}.00</div></div>
    </div>
    <div class="form-row">
        <div class="form-field"><div class="form-label">3 Social security wages</div><div class="form-box">${random.randint(50000,160000):,}.00</div></div>
        <div class="form-field"><div class="form-label">4 Social security tax</div><div class="form-box">${random.randint(3000,10000):,}.00</div></div>
    </div>
    <div class="form-row">
        <div class="form-field"><div class="form-label">5 Medicare wages</div><div class="form-box">${random.randint(50000,200000):,}.00</div></div>
        <div class="form-field"><div class="form-label">6 Medicare tax</div><div class="form-box">${random.randint(700,3000):,}.00</div></div>
    </div>
</div>"""
    fname = render_html(page, html, "img-form-w2-tax.png", width=700, height=650)
    samples.append(("financial", "financial.tax", "critical", fname, "W-2 tax form with SSN and salary"))

    # 2. Medical form
    patient = fake.name()
    html = f"""<style>{FORM_CSS}</style>
<div class="form">
    <div class="form-title">{fake.company()} Medical Center</div>
    <div class="form-subtitle">Patient Intake Form — CONFIDENTIAL</div>
    <div class="section"><div class="section-title">Patient Information</div></div>
    <div class="form-row">
        <div class="form-field"><div class="form-label">Full Name</div><div class="form-value">{patient}</div></div>
        <div class="form-field"><div class="form-label">Date of Birth</div><div class="form-value">{fake.date_of_birth(minimum_age=18,maximum_age=80).strftime("%m/%d/%Y")}</div></div>
    </div>
    <div class="form-row">
        <div class="form-field"><div class="form-label">SSN</div><div class="form-value" style="color:#c00">{rand_ssn()}</div></div>
        <div class="form-field"><div class="form-label">Insurance ID</div><div class="form-value">{random.choice(['W','H','U'])}{random.randint(100000000,999999999)}</div></div>
    </div>
    <div class="form-row">
        <div class="form-field" style="flex:2"><div class="form-label">Address</div><div class="form-value">{fake.address().replace(chr(10),', ')}</div></div>
    </div>
    <div class="section"><div class="section-title">Medical History</div></div>
    <div class="form-row">
        <div class="form-field" style="flex:2"><div class="form-label">Current Medications</div><div class="form-value">Metformin 500mg BID, Lisinopril 10mg QD, Atorvastatin 20mg QHS</div></div>
    </div>
    <div class="form-row">
        <div class="form-field" style="flex:2"><div class="form-label">Allergies</div><div class="form-value">{random.choice(['Penicillin (anaphylaxis)','Sulfa drugs (rash)','NKDA','Codeine (nausea)'])}</div></div>
    </div>
    <div class="form-row">
        <div class="form-field" style="flex:2"><div class="form-label">Diagnoses</div><div class="form-value">Type 2 Diabetes (E11.65), Hypertension (I10), Hyperlipidemia (E78.5)</div></div>
    </div>
</div>"""
    fname = render_html(page, html, "img-form-medical-intake.png", width=700, height=600)
    samples.append(("medical", "medical.diagnosis", "high", fname, "Medical intake form with patient PII and diagnoses"))

    # 3. Credit card / payment form
    html = f"""<style>{FORM_CSS}</style>
<div class="form" style="max-width:500px">
    <div class="form-title">Payment Receipt</div>
    <div class="form-subtitle">{fake.company()} — Order #{random.randint(10000,99999)}</div>
    <div class="section"><div class="section-title">Card Details</div></div>
    <div class="form-row">
        <div class="form-field"><div class="form-label">Cardholder</div><div class="form-value">{fake.name()}</div></div>
    </div>
    <div class="form-row">
        <div class="form-field"><div class="form-label">Card Number</div><div class="form-value" style="font-weight:bold;color:#c00">{rand_cc()}</div></div>
    </div>
    <div class="form-row">
        <div class="form-field"><div class="form-label">Expiry</div><div class="form-value">{random.randint(1,12):02d}/{random.randint(26,30)}</div></div>
        <div class="form-field"><div class="form-label">CVV</div><div class="form-value" style="color:#c00">{random.randint(100,999)}</div></div>
    </div>
    <div class="section"><div class="section-title">Transaction</div></div>
    <div class="form-row">
        <div class="form-field"><div class="form-label">Amount</div><div class="form-box">${random.randint(50,5000):,}.{random.randint(10,99)}</div></div>
        <div class="form-field"><div class="form-label">Status</div><div class="form-value" style="color:green">Approved</div></div>
    </div>
</div>"""
    fname = render_html(page, html, "img-form-credit-card.png", width=550, height=500)
    samples.append(("financial", "financial.credit_card", "critical", fname, "Payment receipt showing full credit card number and CVV"))

    return samples


def gen_dashboard_screenshots(page):
    """Dashboard/admin panel screenshots."""
    samples = []

    # 1. Database admin showing user records
    rows = ''.join([f"""<tr>
        <td>{i}</td><td>{fake.name()}</td><td>{fake.email()}</td>
        <td style="color:#c00">{rand_ssn()}</td>
        <td>{fake.date_of_birth(minimum_age=18,maximum_age=70).strftime("%Y-%m-%d")}</td>
        <td>{fake.phone_number()}</td>
    </tr>""" for i in range(1,9)])

    html = f"""<style>
body {{ margin:0; background:#1e1e2e; font-family: -apple-system, sans-serif; color:#cdd6f4; }}
.panel {{ margin:20px; }}
.header {{ background:#181825; padding:12px 20px; border-bottom:1px solid #313244; display:flex; justify-content:space-between; align-items:center; }}
.header h2 {{ margin:0; font-size:16px; }}
.badge {{ background:#f38ba8; color:#1e1e2e; padding:2px 8px; border-radius:10px; font-size:11px; }}
table {{ width:100%; border-collapse:collapse; font-size:12px; }}
th {{ text-align:left; padding:8px 12px; background:#181825; color:#a6adc8; font-weight:600; border-bottom:1px solid #313244; }}
td {{ padding:8px 12px; border-bottom:1px solid #313244; }}
tr:hover {{ background:#313244; }}
.db-info {{ font-size:11px; color:#6c7086; padding:8px 20px; background:#181825; }}
</style>
<div class="header">
    <h2>📊 users_production — 847,293 rows</h2>
    <span class="badge">LIVE DATABASE</span>
</div>
<div class="db-info">Connected to: db-primary.internal.company.com:5432 | SELECT * FROM users LIMIT 8</div>
<div class="panel">
<table>
<tr><th>id</th><th>full_name</th><th>email</th><th>ssn</th><th>dob</th><th>phone</th></tr>
{rows}
</table>
</div>"""
    fname = render_html(page, html, "img-dashboard-user-db.png", width=1000, height=450)
    samples.append(("pii", "pii.identity", "critical", fname, "Database admin panel showing user table with SSNs"))

    return samples


def gen_safe_images(page):
    """Safe images — architecture diagrams, dashboards, docs."""
    samples = []

    # 1. Clean architecture diagram
    html = """<style>
body { margin:0; background:#f8f9fa; font-family: -apple-system, sans-serif; }
.diagram { max-width:800px; margin:30px auto; text-align:center; }
.title { font-size:20px; font-weight:700; color:#1a1a1a; margin-bottom:30px; }
.row { display:flex; justify-content:center; gap:20px; margin:15px 0; }
.box { padding:16px 24px; border-radius:8px; font-size:13px; font-weight:600; color:white; min-width:120px; }
.blue { background:#2196F3; }
.green { background:#4CAF50; }
.orange { background:#FF9800; }
.purple { background:#9C27B0; }
.gray { background:#607D8B; }
.arrow { font-size:24px; color:#999; margin:5px 0; }
</style>
<div class="diagram">
    <div class="title">System Architecture — Microservices</div>
    <div class="row"><div class="box blue">Load Balancer<br><small>nginx</small></div></div>
    <div class="arrow">↓</div>
    <div class="row">
        <div class="box green">API Gateway<br><small>Kong</small></div>
        <div class="box green">Auth Service<br><small>OAuth 2.0</small></div>
    </div>
    <div class="arrow">↓</div>
    <div class="row">
        <div class="box orange">User Service</div>
        <div class="box orange">Order Service</div>
        <div class="box orange">Payment Service</div>
    </div>
    <div class="arrow">↓</div>
    <div class="row">
        <div class="box purple">PostgreSQL</div>
        <div class="box purple">Redis Cache</div>
        <div class="box gray">S3 Storage</div>
    </div>
</div>"""
    fname = render_html(page, html, "img-safe-architecture.png", width=850, height=500)
    samples.append(("safe", "safe.documentation", "info", fname, "Architecture diagram — no sensitive data"))

    # 2. Monitoring dashboard — clean metrics
    html = """<style>
body { margin:0; background:#0d1117; font-family:-apple-system,sans-serif; color:#c9d1d9; }
.dash { padding:20px; }
.dash-title { font-size:18px; font-weight:700; margin-bottom:20px; }
.cards { display:flex; gap:16px; margin-bottom:20px; }
.card { flex:1; background:#161b22; border:1px solid #30363d; border-radius:8px; padding:16px; }
.card-label { font-size:11px; color:#8b949e; text-transform:uppercase; }
.card-value { font-size:28px; font-weight:700; margin:8px 0; }
.card-value.green { color:#3fb950; }
.card-value.blue { color:#58a6ff; }
.card-value.yellow { color:#d29922; }
.card-change { font-size:12px; color:#3fb950; }
</style>
<div class="dash">
    <div class="dash-title">📊 Production Dashboard — Last 24h</div>
    <div class="cards">
        <div class="card"><div class="card-label">Uptime</div><div class="card-value green">99.97%</div><div class="card-change">↑ 0.02%</div></div>
        <div class="card"><div class="card-label">Requests/min</div><div class="card-value blue">12,847</div><div class="card-change">↑ 8.3%</div></div>
        <div class="card"><div class="card-label">P99 Latency</div><div class="card-value yellow">142ms</div><div class="card-change">↓ 12ms</div></div>
        <div class="card"><div class="card-label">Error Rate</div><div class="card-value green">0.03%</div><div class="card-change">↓ 0.01%</div></div>
    </div>
    <div class="cards">
        <div class="card"><div class="card-label">Active Users</div><div class="card-value blue">34,521</div><div class="card-change">↑ 12%</div></div>
        <div class="card"><div class="card-label">CPU Usage</div><div class="card-value yellow">47%</div><div class="card-change">↓ 3%</div></div>
        <div class="card"><div class="card-label">Memory</div><div class="card-value green">62%</div><div class="card-change">→ stable</div></div>
        <div class="card"><div class="card-label">Disk I/O</div><div class="card-value green">23 MB/s</div><div class="card-change">→ stable</div></div>
    </div>
</div>"""
    fname = render_html(page, html, "img-safe-dashboard.png", width=900, height=400)
    samples.append(("safe", "safe.documentation", "info", fname, "Monitoring dashboard with clean metrics only"))

    # 3. API documentation page
    html = """<style>
body { margin:0; background:#fff; font-family:-apple-system,sans-serif; color:#333; }
.docs { max-width:750px; margin:30px auto; padding:0 20px; }
h1 { font-size:24px; border-bottom:1px solid #eee; padding-bottom:12px; }
h2 { font-size:18px; color:#0366d6; margin-top:24px; }
code { background:#f6f8fa; padding:2px 6px; border-radius:3px; font-size:13px; }
pre { background:#f6f8fa; padding:16px; border-radius:6px; overflow:auto; font-size:13px; line-height:1.5; }
.method { display:inline-block; padding:2px 8px; border-radius:3px; font-size:12px; font-weight:700; color:white; }
.get { background:#28a745; }
.post { background:#0366d6; }
table { width:100%; border-collapse:collapse; margin:12px 0; font-size:13px; }
th, td { text-align:left; padding:8px; border-bottom:1px solid #eee; }
th { font-weight:600; }
</style>
<div class="docs">
    <h1>API Reference</h1>
    <h2><span class="method get">GET</span> /api/v1/products</h2>
    <p>Returns a paginated list of products.</p>
    <p><strong>Headers:</strong> <code>Authorization: Bearer &lt;token&gt;</code></p>
    <table><tr><th>Parameter</th><th>Type</th><th>Required</th><th>Description</th></tr>
    <tr><td>page</td><td>integer</td><td>No</td><td>Page number (default: 1)</td></tr>
    <tr><td>limit</td><td>integer</td><td>No</td><td>Items per page (default: 20)</td></tr>
    <tr><td>category</td><td>string</td><td>No</td><td>Filter by category</td></tr></table>
    <p><strong>Response:</strong></p>
    <pre>{"data": [{"id": 1, "name": "Widget", "price": 29.99}], "total": 142, "page": 1}</pre>
</div>"""
    fname = render_html(page, html, "img-safe-api-docs.png", width=800, height=550)
    samples.append(("safe", "safe.documentation", "info", fname, "API documentation page — no sensitive data"))

    # 4. Clean code review
    html = """<style>
body { margin:0; background:#0d1117; font-family:monospace; font-size:13px; color:#c9d1d9; }
.pr { margin:20px; }
.pr-title { font-size:18px; font-weight:700; margin-bottom:4px; }
.pr-meta { font-size:12px; color:#8b949e; margin-bottom:16px; }
.diff { background:#161b22; border:1px solid #30363d; border-radius:6px; overflow:hidden; }
.diff-header { background:#161b22; padding:8px 16px; border-bottom:1px solid #30363d; font-size:12px; color:#8b949e; }
.diff-line { padding:2px 16px; font-size:12px; line-height:1.6; }
.add { background:#12261e; color:#aff5b4; }
.del { background:#2d1214; color:#ffa198; }
.ctx { color:#8b949e; }
</style>
<div class="pr">
    <div class="pr-title">feat: add request validation middleware</div>
    <div class="pr-meta">Opened by dev-team • 3 files changed, +45 −12</div>
    <div class="diff">
        <div class="diff-header">src/middleware/validate.ts</div>
        <div class="diff-line add">+import { z } from 'zod';</div>
        <div class="diff-line add">+import { Request, Response, NextFunction } from 'express';</div>
        <div class="diff-line ctx"> </div>
        <div class="diff-line add">+export const validate = (schema: z.ZodSchema) =&gt; {</div>
        <div class="diff-line add">+  return (req: Request, res: Response, next: NextFunction) =&gt; {</div>
        <div class="diff-line add">+    const result = schema.safeParse(req.body);</div>
        <div class="diff-line add">+    if (!result.success) {</div>
        <div class="diff-line add">+      return res.status(400).json({ errors: result.error.issues });</div>
        <div class="diff-line add">+    }</div>
        <div class="diff-line add">+    req.body = result.data;</div>
        <div class="diff-line add">+    next();</div>
        <div class="diff-line add">+  };</div>
        <div class="diff-line add">+};</div>
    </div>
</div>"""
    fname = render_html(page, html, "img-safe-code-review.png", width=850, height=450)
    samples.append(("safe", "safe.code", "info", fname, "GitHub PR diff — clean code, no secrets"))

    # 5. Blank Kanban board
    html = """<style>
body { margin:0; background:#f4f5f7; font-family:-apple-system,sans-serif; }
.board { display:flex; gap:12px; padding:20px; overflow:hidden; }
.col { background:#ebecf0; border-radius:8px; width:250px; padding:12px; }
.col-title { font-size:13px; font-weight:700; color:#5e6c84; margin-bottom:12px; }
.card { background:white; border-radius:4px; padding:10px; margin-bottom:8px; box-shadow:0 1px 2px rgba(0,0,0,0.1); font-size:13px; color:#172b4d; }
.tag { display:inline-block; padding:1px 6px; border-radius:3px; font-size:10px; font-weight:600; margin-top:6px; }
.tag-blue { background:#deebff; color:#0052cc; }
.tag-green { background:#e3fcef; color:#006644; }
.tag-orange { background:#fff3e0; color:#e65100; }
h2 { text-align:center; font-size:18px; color:#172b4d; padding:16px; margin:0; border-bottom:1px solid #dfe1e6; }
</style>
<h2>Sprint 42 — Team Board</h2>
<div class="board">
    <div class="col"><div class="col-title">TO DO (3)</div>
        <div class="card">Add pagination to /api/products<div class="tag tag-blue">Backend</div></div>
        <div class="card">Update onboarding flow copy<div class="tag tag-green">Frontend</div></div>
        <div class="card">Write integration tests for auth<div class="tag tag-orange">Testing</div></div>
    </div>
    <div class="col"><div class="col-title">IN PROGRESS (2)</div>
        <div class="card">Migrate database to PostgreSQL 16<div class="tag tag-blue">Backend</div></div>
        <div class="card">Redesign settings page<div class="tag tag-green">Frontend</div></div>
    </div>
    <div class="col"><div class="col-title">DONE (4)</div>
        <div class="card">Fix N+1 query on orders list<div class="tag tag-blue">Backend</div></div>
        <div class="card">Add dark mode toggle<div class="tag tag-green">Frontend</div></div>
        <div class="card">Set up CI pipeline<div class="tag tag-orange">DevOps</div></div>
        <div class="card">Update README<div class="tag tag-green">Docs</div></div>
    </div>
</div>"""
    fname = render_html(page, html, "img-safe-kanban.png", width=850, height=480)
    samples.append(("safe", "safe.documentation", "info", fname, "Kanban board — project tasks, no sensitive data"))

    return samples


def gen_classified_screenshots(page):
    """Screenshots of classified/confidential documents."""
    samples = []

    # 1. TOP SECRET document
    html = f"""<style>
body {{ margin:0; background:#f5f0e8; font-family:'Courier New',monospace; }}
.doc {{ max-width:650px; margin:20px auto; padding:40px; background:white; box-shadow:0 2px 10px rgba(0,0,0,0.2); }}
.stamp {{ text-align:center; font-size:24px; font-weight:bold; color:#c00; border:3px solid #c00; display:inline-block; padding:4px 20px; margin:0 auto 20px; transform:rotate(-3deg); }}
.stamp-container {{ text-align:center; }}
.header {{ text-align:center; margin-bottom:20px; }}
.doc-id {{ font-size:11px; color:#666; }}
.doc-title {{ font-size:16px; font-weight:bold; margin:12px 0; }}
.content {{ font-size:13px; line-height:1.8; }}
.footer {{ margin-top:30px; font-size:10px; color:#666; border-top:1px solid #ccc; padding-top:10px; }}
</style>
<div class="doc">
    <div class="stamp-container"><div class="stamp">TOP SECRET // SCI // NOFORN</div></div>
    <div class="header">
        <div class="doc-id">DOC-{random.randint(2024,2026)}-{random.randint(10000,99999)} | {random.choice(['CIA','NSA','DIA'])}</div>
        <div class="doc-title">INTELLIGENCE ASSESSMENT: {random.choice(['Regional Threat Analysis','Signals Intelligence Summary','Counter-Proliferation Brief'])}</div>
        <div class="doc-id">Date: {fake.date_this_year().strftime("%d %B %Y").upper()}</div>
    </div>
    <div class="content">
        <p><strong>EXECUTIVE SUMMARY:</strong> {fake.paragraph(nb_sentences=3)}</p>
        <p><strong>KEY JUDGMENTS:</strong></p>
        <p>1. {fake.sentence()} (High confidence)</p>
        <p>2. {fake.sentence()} (Moderate confidence)</p>
        <p><strong>SOURCES:</strong> {random.choice(['HUMINT','SIGINT','GEOINT'])} collection indicates {fake.sentence().lower()}</p>
    </div>
    <div class="footer">
        CLASSIFICATION: TOP SECRET // SCI // NOFORN<br>
        DISTRIBUTION: Limited to cleared personnel with SCI access<br>
        DECLASSIFY ON: {random.randint(2050,2060)}-01-01
    </div>
</div>"""
    fname = render_html(page, html, "img-classified-top-secret.png", width=750, height=700)
    samples.append(("confidential", "confidential.classified", "critical", fname, "TOP SECRET intelligence assessment document"))

    return samples


# ============================================================
# MAIN
# ============================================================
if __name__ == "__main__":
    print("Generating image eval samples...\n")

    all_samples = []

    with sync_playwright() as p:
        browser = p.chromium.launch()
        page = browser.new_page()

        print("  Generating terminal screenshots...")
        all_samples.extend(gen_terminal_screenshots(page))

        print("  Generating VS Code screenshots...")
        all_samples.extend(gen_vscode_screenshots(page))

        print("  Generating Slack screenshots...")
        all_samples.extend(gen_slack_screenshots(page))

        print("  Generating email screenshots...")
        all_samples.extend(gen_email_screenshots(page))

        print("  Generating form screenshots...")
        all_samples.extend(gen_form_screenshots(page))

        print("  Generating dashboard screenshots...")
        all_samples.extend(gen_dashboard_screenshots(page))

        print("  Generating safe screenshots...")
        all_samples.extend(gen_safe_images(page))

        print("  Generating classified screenshots...")
        all_samples.extend(gen_classified_screenshots(page))

        browser.close()

    # Save updated ground truth
    for cat, subcat, sev, fname, note in all_samples:
        save_sample(cat, subcat, sev, fname, note)

    with open(GROUND_TRUTH_PATH, "w") as f:
        json.dump(GROUND_TRUTH, f, indent=2)

    # Stats
    from collections import Counter
    img_cats = Counter(cat for cat, *_ in all_samples)

    print(f"\nGenerated {len(all_samples)} images:")
    for c, n in sorted(img_cats.items(), key=lambda x: -x[1]):
        print(f"  {c:<15s} {n:>3d}")
    print(f"\nTotal eval samples: {len(GROUND_TRUTH)} ({len(GROUND_TRUTH) - len(all_samples)} text + {len(all_samples)} images)")
    print(f"Saved to: {OUT_DIR}/")
    print("Done!")
