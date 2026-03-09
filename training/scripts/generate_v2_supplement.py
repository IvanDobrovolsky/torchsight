#!/usr/bin/env python3
"""
Generate supplemental training data to fix v2 model weaknesses:
1. Safe content with credential-like patterns (reduce false positives)
2. Multi-finding documents (teach model to output multiple findings)
3. Richer explanations across all categories
"""

import json
import random
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
OUTPUT = SCRIPT_DIR.parent / "data" / "processed" / "v2_supplement.jsonl"

random.seed(42)

samples = []

# =============================================================================
# 1. SAFE CONTENT WITH CREDENTIAL-LIKE PATTERNS (~2000 samples)
# =============================================================================

# --- .env.example / placeholder files ---
PLACEHOLDER_KEYS = [
    "your-api-key-here", "YOUR_KEY_HERE", "sk-your-key-here", "sk_test_xxxxxxxxxxxx",
    "replace-with-your-key", "INSERT_API_KEY", "changeme", "password123",
    "your-secret-here", "xxxxxxxxxxxxxxxx", "TODO_REPLACE", "<your-token>",
    "example-key-do-not-use", "PASTE_YOUR_KEY", "pk_test_xxxxxxxx",
    "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx", "npm_xxxxxxxxxxxxxxxx",
    "test-key-not-real", "dummy-secret-for-dev", "placeholder",
]

PLACEHOLDER_VARS = [
    "API_KEY", "SECRET_KEY", "DATABASE_URL", "OPENAI_API_KEY", "STRIPE_SECRET_KEY",
    "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "GITHUB_TOKEN", "NPM_TOKEN",
    "REDIS_URL", "MONGO_URI", "JWT_SECRET", "SESSION_SECRET", "SMTP_PASSWORD",
    "SLACK_WEBHOOK_URL", "SENTRY_DSN", "POSTGRES_PASSWORD", "MYSQL_ROOT_PASSWORD",
    "FIREBASE_API_KEY", "TWILIO_AUTH_TOKEN", "SENDGRID_API_KEY", "DATADOG_API_KEY",
]

DB_URLS_PLACEHOLDER = [
    "postgres://user:password@localhost:5432/myapp",
    "mysql://root:password@localhost:3306/dev_db",
    "mongodb://localhost:27017/test",
    "redis://localhost:6379/0",
    "postgres://user:changeme@localhost/app",
]

for i in range(400):
    num_vars = random.randint(3, 8)
    vars_chosen = random.sample(PLACEHOLDER_VARS, min(num_vars, len(PLACEHOLDER_VARS)))
    lines = ["# Environment Configuration", f"# Copy this file to .env and fill in your values", ""]
    for var in vars_chosen:
        key = random.choice(PLACEHOLDER_KEYS)
        if "URL" in var or "URI" in var:
            key = random.choice(DB_URLS_PLACEHOLDER)
        lines.append(f"# {var.replace('_', ' ').title()}")
        lines.append(f"{var}={key}")
        lines.append("")

    samples.append({
        "id": f"safe_placeholder_{i:04d}",
        "source": "v2_supplement",
        "source_license": "generated",
        "text": "\n".join(lines),
        "findings": [{"category": "safe", "subcategory": "safe.config", "severity": "info",
                       "explanation": "Configuration template with placeholder values. No real credentials — all values are examples meant to be replaced by the user."}]
    })

# --- Tutorials / documentation with example credentials ---
TUTORIAL_TEMPLATES = [
    ("Setting Up AWS CLI", "To configure your AWS credentials, run:\n\n```bash\nexport AWS_ACCESS_KEY_ID={key}\nexport AWS_SECRET_ACCESS_KEY={secret}\n```\n\nReplace the placeholder values with your actual AWS credentials from the IAM console.\n\n**Never commit real credentials to version control.**"),
    ("Getting Started with Stripe", "First, get your API keys from the Stripe Dashboard.\n\n```python\nimport stripe\nstripe.api_key = '{key}'\n```\n\nUse `sk_test_` keys for development. Never use `sk_live_` keys in client-side code.\n\n```bash\nexport STRIPE_KEY={key}\n```"),
    ("Docker Compose for Local Development", "Create a `docker-compose.yml` for your local environment:\n\n```yaml\nservices:\n  db:\n    image: postgres:15\n    environment:\n      POSTGRES_PASSWORD: {secret}\n      POSTGRES_DB: myapp\n  redis:\n    image: redis:7\n    command: redis-server --requirepass {secret}\n```\n\nThese passwords are for local development only."),
    ("JWT Authentication Tutorial", "Generate a JWT token for testing:\n\n```javascript\nconst jwt = require('jsonwebtoken');\nconst token = jwt.sign({{ user: 'test' }}, '{secret}');\nconsole.log(token);\n// Output: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...\n```\n\nIn production, store your secret in environment variables."),
    ("Database Connection Guide", "Configure your database connection:\n\n```python\nDATABASE_URL = '{db_url}'\n# Replace with your actual database URL\n```\n\nFor local development, you can use the default PostgreSQL settings."),
    ("GitHub Actions CI/CD Setup", "Create `.github/workflows/deploy.yml`:\n\n```yaml\nname: Deploy\non: push\njobs:\n  deploy:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n      - run: npm install && npm run build\n        env:\n          API_KEY: ${{{{ secrets.API_KEY }}}}\n          DATABASE_URL: ${{{{ secrets.DATABASE_URL }}}}\n```\n\nAdd your secrets in GitHub Settings > Secrets."),
    ("Configuring OAuth2", "Set up OAuth2 credentials:\n\n```env\nOAUTH_CLIENT_ID={key}\nOAUTH_CLIENT_SECRET={secret}\nOAUTH_REDIRECT_URI=http://localhost:3000/callback\n```\n\nGet these values from your OAuth provider's developer console."),
    ("Redis Configuration", "Connect to Redis:\n\n```python\nimport redis\nr = redis.Redis(\n    host='localhost',\n    port=6379,\n    password='{secret}',  # Set in .env\n    db=0\n)\n```"),
    ("Terraform Provider Setup", "Configure the AWS provider:\n\n```hcl\nprovider \"aws\" {{\n  region     = \"us-east-1\"\n  access_key = \"{key}\"  # Use env vars in production\n  secret_key = \"{secret}\"\n}}\n```\n\n**Better approach:** Use `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY` environment variables."),
    ("Kubernetes Secrets", "Create a secret from a file:\n\n```yaml\napiVersion: v1\nkind: Secret\nmetadata:\n  name: app-secrets\ntype: Opaque\ndata:\n  # base64 encoded values — replace with your own\n  db-password: Y2hhbmdlbWU=  # 'changeme'\n  api-key: eW91ci1rZXktaGVyZQ==  # 'your-key-here'\n```"),
]

EXAMPLE_KEYS = ["your-api-key-here", "sk-example-key-12345", "AKIAIOSFODNN7EXAMPLE",
                "sk_test_xxxxxxxxxxxxxxxx", "ghp_xxxxxxxxxxxxxxxxxxxx", "your-key-here",
                "replace-me", "INSERT_KEY_HERE", "pk_test_example"]
EXAMPLE_SECRETS = ["your-secret-here", "wJalrXUtnFEMI/K7MDENG/EXAMPLE", "changeme",
                   "replace-with-your-secret", "dummy-secret-123", "your-password-here",
                   "password", "secret123", "test-secret"]
EXAMPLE_DB_URLS = ["postgres://user:password@localhost:5432/myapp",
                   "mysql://root:changeme@localhost:3306/app",
                   "mongodb://localhost:27017/mydb"]

for i in range(500):
    title, template = random.choice(TUTORIAL_TEMPLATES)
    key = random.choice(EXAMPLE_KEYS)
    secret = random.choice(EXAMPLE_SECRETS)
    db_url = random.choice(EXAMPLE_DB_URLS)
    text = f"# {title}\n\n" + template.format(key=key, secret=secret, db_url=db_url)

    samples.append({
        "id": f"safe_tutorial_{i:04d}",
        "source": "v2_supplement",
        "source_license": "generated",
        "text": text,
        "findings": [{"category": "safe", "subcategory": "safe.documentation", "severity": "info",
                       "explanation": f"Tutorial/documentation: {title}. Contains example credentials and placeholder values for instructional purposes. No real secrets exposed."}]
    })

# --- Unit tests / test fixtures with fake credentials ---
TEST_TEMPLATES = [
    'import unittest\nfrom unittest.mock import patch\n\nclass TestAPIClient(unittest.TestCase):\n    @patch(\'app.config.API_KEY\', \'{key}\')\n    @patch(\'app.config.DB_PASSWORD\', \'{secret}\')\n    def test_authentication(self):\n        client = APIClient()\n        response = client.authenticate()\n        self.assertEqual(response.status_code, 200)\n\n    def test_invalid_key(self):\n        with patch(\'app.config.API_KEY\', \'invalid-key\'):\n            client = APIClient()\n            with self.assertRaises(AuthError):\n                client.authenticate()',
    'const {{ describe, it, expect }} = require(\'jest\');\n\ndescribe(\'Payment Service\', () => {{\n  const MOCK_STRIPE_KEY = \'{key}\';\n  const MOCK_DB_URL = \'postgres://test:test@localhost/test_db\';\n\n  it(\'should process payment\', async () => {{\n    const service = new PaymentService(MOCK_STRIPE_KEY);\n    const result = await service.charge(1000);\n    expect(result.success).toBe(true);\n  }});\n\n  it(\'should handle invalid key\', async () => {{\n    const service = new PaymentService(\'invalid\');\n    await expect(service.charge(1000)).rejects.toThrow();\n  }});\n}});',
    '# conftest.py\nimport pytest\n\n@pytest.fixture\ndef mock_credentials():\n    return {{\n        "aws_access_key_id": "AKIAIOSFODNN7EXAMPLE",\n        "aws_secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",\n        "region": "us-east-1"\n    }}\n\n@pytest.fixture\ndef mock_db_url():\n    return "postgres://test:test@localhost:5432/test_db"\n\ndef test_aws_client(mock_credentials):\n    client = AWSClient(**mock_credentials)\n    assert client.region == "us-east-1"',
    'package auth_test\n\nimport (\n    "testing"\n)\n\nconst (\n    testAPIKey    = "{key}"\n    testDBPass    = "{secret}"\n    testJWTSecret = "test-jwt-secret-do-not-use"\n)\n\nfunc TestAuthenticate(t *testing.T) {{\n    client := NewClient(testAPIKey)\n    token, err := client.Authenticate()\n    if err != nil {{\n        t.Fatalf("auth failed: %v", err)\n    }}\n    if token == "" {{\n        t.Fatal("expected non-empty token")\n    }}\n}}',
]

for i in range(400):
    template = random.choice(TEST_TEMPLATES)
    key = random.choice(EXAMPLE_KEYS)
    secret = random.choice(EXAMPLE_SECRETS)
    text = template.format(key=key, secret=secret)

    samples.append({
        "id": f"safe_test_{i:04d}",
        "source": "v2_supplement",
        "source_license": "generated",
        "text": text,
        "findings": [{"category": "safe", "subcategory": "safe.code", "severity": "info",
                       "explanation": "Test file with mock/fake credentials used for unit testing. No real secrets — values are test fixtures that do not grant access to any system."}]
    })

# --- Docker compose with default passwords ---
for i in range(200):
    services = random.sample(["postgres", "mysql", "redis", "mongo", "rabbitmq", "elasticsearch"], random.randint(2, 4))
    lines = ["version: '3.8'", "services:"]
    for svc in services:
        pw = random.choice(["changeme", "password", "dev-password", "local-only", "test123"])
        if svc == "postgres":
            lines.extend([f"  db:", f"    image: postgres:15", f"    environment:", f"      POSTGRES_PASSWORD: {pw}", f"      POSTGRES_DB: app_dev", f"    ports:", f'      - "5432:5432"'])
        elif svc == "mysql":
            lines.extend([f"  mysql:", f"    image: mysql:8", f"    environment:", f"      MYSQL_ROOT_PASSWORD: {pw}", f"      MYSQL_DATABASE: app_dev"])
        elif svc == "redis":
            lines.extend([f"  redis:", f"    image: redis:7", f"    command: redis-server --requirepass {pw}"])
        elif svc == "mongo":
            lines.extend([f"  mongo:", f"    image: mongo:7", f"    environment:", f"      MONGO_INITDB_ROOT_USERNAME: root", f"      MONGO_INITDB_ROOT_PASSWORD: {pw}"])
        elif svc == "rabbitmq":
            lines.extend([f"  rabbitmq:", f"    image: rabbitmq:3-management", f"    environment:", f"      RABBITMQ_DEFAULT_PASS: {pw}"])
        elif svc == "elasticsearch":
            lines.extend([f"  elasticsearch:", f"    image: elasticsearch:8.11.0", f"    environment:", f"      ELASTIC_PASSWORD: {pw}"])

    samples.append({
        "id": f"safe_docker_{i:04d}",
        "source": "v2_supplement",
        "source_license": "generated",
        "text": "\n".join(lines),
        "findings": [{"category": "safe", "subcategory": "safe.config", "severity": "info",
                       "explanation": f"Docker Compose for local development with default passwords ({', '.join(services)}). These are standard development defaults, not production credentials."}]
    })

# --- GitHub Actions / CI with secret references ---
for i in range(200):
    secrets = random.sample(["API_KEY", "DEPLOY_TOKEN", "NPM_TOKEN", "DOCKER_PASSWORD",
                              "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "CODECOV_TOKEN",
                              "SENTRY_AUTH_TOKEN", "VERCEL_TOKEN", "DATABASE_URL"], random.randint(2, 5))
    refs = "\n".join([f'          {s}: ${{{{ secrets.{s} }}}}' for s in secrets])
    text = f"""name: CI/CD Pipeline
on:
  push:
    branches: [main]
  pull_request:

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: '20'
      - run: npm ci
      - run: npm test
      - run: npm run build
        env:
{refs}
      - run: npm run deploy
        if: github.ref == 'refs/heads/main'
"""
    samples.append({
        "id": f"safe_ci_{i:04d}",
        "source": "v2_supplement",
        "source_license": "generated",
        "text": text,
        "findings": [{"category": "safe", "subcategory": "safe.config", "severity": "info",
                       "explanation": f"CI/CD configuration using secret variable references (${{{{ secrets.* }}}}). No actual credentials — values are injected at runtime from the secrets store."}]
    })

# --- Hashed passwords / bcrypt / encrypted content ---
HASHES = [
    "$2b$12$LJ3m4ysNCFGqPz1N.Pu8aObK3F7GYl5K2M3xL9fR8dQ6wC4tE7nJi",
    "$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy",
    "$argon2id$v=19$m=65536,t=3,p=4$c2FsdHNhbHQ$Jqzv0OPOlEq",
    "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "pbkdf2:sha256:260000$7d4e7f8a$a1b2c3d4e5f6g7h8i9j0",
]

for i in range(200):
    hash_val = random.choice(HASHES)
    text = f"""-- User migration
CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(255) NOT NULL UNIQUE,
    email VARCHAR(255) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    created_at TIMESTAMP DEFAULT NOW()
);

-- Seed admin user (password hash - not plaintext)
INSERT INTO users (username, email, password_hash) VALUES
    ('admin', 'admin@example.com', '{hash_val}'),
    ('testuser', 'test@example.com', '{random.choice(HASHES)}');
"""
    samples.append({
        "id": f"safe_hash_{i:04d}",
        "source": "v2_supplement",
        "source_license": "generated",
        "text": text,
        "findings": [{"category": "safe", "subcategory": "safe.code", "severity": "info",
                       "explanation": "Database migration with hashed passwords (bcrypt/argon2/sha256). Password hashes are one-way and do not expose plaintext credentials."}]
    })


# =============================================================================
# 2. MULTI-FINDING DOCUMENTS (~2000 samples)
# =============================================================================

REAL_API_KEYS = ["sk_live_51HG4kLInR9t3eM7vK8bN2pQ", "AKIA3EXAMPLE7REALKEY",
                 "ghp_R4nD0mT0k3nV4lu3H3r3ABC", "xoxb-1234-5678-abcdef",
                 "SG.xxxxxxx.yyyyyyyy", "rk_live_xxxxxxxxx"]
REAL_PASSWORDS = ["Pr0d_s3cret!", "Admin@2026", "r3alP@ssw0rd", "Sup3rS3cureDB#1",
                  "W1nt3r2026!", "p@$$w0rd!DB"]
REAL_DB_URLS = [
    "postgres://admin:{pw}@prod-db-01.us-east-1.rds.amazonaws.com:5432/production",
    "mysql://root:{pw}@db.internal.company.com:3306/main",
    "mongodb://admin:{pw}@cluster0.abc123.mongodb.net/prod",
]

NAMES = ["John Smith", "Sarah Johnson", "Michael Chen", "Maria Rodriguez", "David Park",
         "Emily Davis", "Robert Wilson", "Jennifer Lee", "James Brown", "Amanda Taylor"]
SSNS = ["412-55-7890", "287-43-8891", "553-21-6743", "198-76-5432", "321-87-6540"]
EMAILS = ["john.smith@company.com", "sarah.j@gmail.com", "m.chen@corp.io",
           "maria.r@enterprise.com", "d.park@tech.co"]
PHONES = ["(503) 555-0142", "(212) 555-0198", "(415) 555-0167", "(312) 555-0134"]

# --- .env files with multiple credential types ---
for i in range(400):
    pw = random.choice(REAL_PASSWORDS)
    db_url = random.choice(REAL_DB_URLS).format(pw=pw)
    api_key = random.choice(REAL_API_KEYS)

    extra_creds = random.sample([
        (f"REDIS_URL=redis://:{random.choice(REAL_PASSWORDS)}@cache.internal:6379/0", "credentials.connection_string", "Redis connection string with embedded password"),
        (f"SLACK_WEBHOOK=https://hooks.slack.com/services/T024F{random.randint(1000,9999)}/B048{random.randint(1000,9999)}/{''.join(random.choices('abcdefghijklmnop', k=24))}", "credentials.token", "Slack webhook URL that allows posting to channels"),
        (f"SENDGRID_API_KEY=SG.{''.join(random.choices('abcdefghijklmnopqrstuvwxyz', k=22))}.{''.join(random.choices('ABCDEFGHIJKLMNOP', k=22))}", "credentials.api_key", "SendGrid API key for email service"),
        (f"JWT_SECRET={''.join(random.choices('abcdef0123456789', k=64))}", "credentials.token", "JWT signing secret — allows forging authentication tokens"),
        (f"GITHUB_TOKEN=ghp_{''.join(random.choices('abcdefghijklmnopABCDEFGH0123456789', k=36))}", "credentials.token", "GitHub personal access token with repository access"),
    ], random.randint(1, 3))

    lines = [f"# Production Environment", f"DATABASE_URL={db_url}", f"API_KEY={api_key}"]
    findings = [
        {"category": "credentials", "subcategory": "credentials.connection_string", "severity": "critical",
         "explanation": f"Production database connection string with plaintext password for RDS/MongoDB instance"},
        {"category": "credentials", "subcategory": "credentials.api_key", "severity": "critical",
         "explanation": f"API key exposed: {api_key[:15]}... — grants access to external service"},
    ]

    for cred_line, subcat, expl in extra_creds:
        lines.append(cred_line)
        findings.append({"category": "credentials", "subcategory": subcat, "severity": "critical", "explanation": expl})

    samples.append({
        "id": f"multi_creds_{i:04d}",
        "source": "v2_supplement",
        "source_license": "generated",
        "text": "\n".join(lines),
        "findings": findings
    })

# --- HR files with PII + financial + medical ---
for i in range(400):
    name = random.choice(NAMES)
    ssn = random.choice(SSNS)
    email = random.choice(EMAILS)
    phone = random.choice(PHONES)
    salary = random.randint(75, 250) * 1000

    text = f"""EMPLOYEE PERSONNEL FILE — CONFIDENTIAL

Name: {name}
SSN: {ssn}
Date of Birth: {random.randint(1, 12):02d}/{random.randint(1, 28):02d}/{random.randint(1970, 1995)}
Email: {email}
Phone: {phone}
Address: {random.randint(100, 9999)} {random.choice(['Oak', 'Maple', 'Pine', 'Cedar', 'Elm'])} {random.choice(['Street', 'Avenue', 'Drive', 'Lane'])}, {random.choice(['Arlington', 'Portland', 'Austin', 'Denver'])}, {random.choice(['VA', 'OR', 'TX', 'CO'])} {random.randint(10000, 99999)}

Position: {random.choice(['Senior Engineer', 'Product Manager', 'Director of Sales', 'VP of Engineering', 'Data Analyst'])}
Department: {random.choice(['Engineering', 'Product', 'Sales', 'Marketing', 'Finance'])}
Salary: ${salary:,}
Stock Options: {random.randint(1000, 50000):,} shares vesting over 4 years

Emergency Contact: {random.choice(NAMES)}, {random.choice(PHONES)}, {random.choice(['spouse', 'parent', 'sibling'])}
"""

    findings = [
        {"category": "pii", "subcategory": "pii.identity", "severity": "critical",
         "explanation": f"Personal identity information for {name} including SSN ({ssn[:3]}-XX-XXXX), date of birth, and home address"},
        {"category": "pii", "subcategory": "pii.contact", "severity": "warning",
         "explanation": f"Contact information: email address, phone number, and physical address for {name.split()[0]}"},
        {"category": "financial", "subcategory": "financial.tax", "severity": "warning",
         "explanation": f"Compensation data: salary (${salary:,}) and stock option details — sensitive financial information"},
        {"category": "confidential", "subcategory": "confidential.internal", "severity": "warning",
         "explanation": "Internal HR document marked CONFIDENTIAL with employment details and emergency contact information"},
    ]

    samples.append({
        "id": f"multi_hr_{i:04d}",
        "source": "v2_supplement",
        "source_license": "generated",
        "text": text,
        "findings": findings
    })

# --- Log files with injection + PII ---
for i in range(300):
    normal_paths = ["/api/health", "/api/users", "/static/app.js", "/login", "/dashboard",
                    "/api/products", "/search", "/api/orders"]

    lines = []
    attack_types = []

    for _ in range(random.randint(15, 30)):
        ip = f"10.0.{random.randint(1,10)}.{random.randint(1,254)}"
        path = random.choice(normal_paths)
        user = random.choice(["jsmith", "admin", "mchen", "sjohnson", "-"])

        if random.random() < 0.2:  # 20% attack traffic
            attack = random.choice([
                ("sqli", f"/login?user=admin'%20OR%201=1;--", "malicious.injection", "SQL injection attempt in login parameter"),
                ("xss", f"/search?q=<script>alert(document.cookie)</script>", "malicious.injection", "Cross-site scripting attempt in search parameter"),
                ("sqli", f"/api/users?id=1%20UNION%20SELECT%20*%20FROM%20passwords--", "malicious.injection", "UNION-based SQL injection targeting passwords table"),
                ("path", f"/api/../../../etc/passwd", "malicious.injection", "Path traversal attempt to read system files"),
            ])
            attack_types.append(attack)
            path = attack[1]
            status = random.choice(["400", "403", "500"])
        else:
            status = "200"

        session = f"sess_{''.join(random.choices('abcdef0123456789', k=16))}" if user != "-" else "-"
        lines.append(f"{ip} user={user} session={session} [{random.randint(1,28):02d}/Mar/2026:{random.randint(0,23):02d}:{random.randint(0,59):02d}:{random.randint(0,59):02d}] \"GET {path} HTTP/1.1\" {status}")

    findings = []
    seen_types = set()
    for attack in attack_types:
        if attack[2] not in seen_types:
            seen_types.add(attack[2])
            findings.append({"category": "malicious", "subcategory": attack[2], "severity": "critical",
                             "explanation": attack[3]})

    findings.append({"category": "pii", "subcategory": "pii.metadata", "severity": "warning",
                     "explanation": "Server logs contain usernames and session tokens that can be used to track user activity and potentially hijack sessions"})

    samples.append({
        "id": f"multi_logs_{i:04d}",
        "source": "v2_supplement",
        "source_license": "generated",
        "text": "\n".join(lines),
        "findings": findings
    })

# --- Documents with mixed medical + PII ---
for i in range(300):
    name = random.choice(NAMES)
    ssn = random.choice(SSNS)

    diagnoses = ["Type 2 Diabetes Mellitus", "Essential Hypertension", "Major Depressive Disorder",
                 "Stage IIB non-Hodgkin Lymphoma", "Chronic Kidney Disease Stage 3", "Rheumatoid Arthritis"]
    meds = ["Metformin 500mg BID", "Lisinopril 10mg QD", "Sertraline 100mg QD",
            "Atorvastatin 20mg QHS", "Amlodipine 5mg QD", "Metoprolol 25mg BID"]

    dx = random.choice(diagnoses)
    med_list = random.sample(meds, random.randint(2, 4))

    text = f"""PATIENT MEDICAL RECORD — HIPAA PROTECTED

Patient: {name}
MRN: {random.randint(100000, 999999)}
DOB: {random.randint(1, 12):02d}/{random.randint(1, 28):02d}/{random.randint(1960, 1990)}
SSN: {ssn}
Insurance: {random.choice(['Blue Cross', 'Aetna', 'UnitedHealth', 'Cigna'])} #{random.randint(100000, 999999)}

DIAGNOSIS: {dx}

MEDICATIONS:
{chr(10).join(f'  - {m}' for m in med_list)}

NOTES: Patient reports {random.choice(['improvement', 'no change', 'worsening symptoms'])} since last visit.
Follow-up in {random.choice(['2 weeks', '1 month', '3 months'])}.
"""

    samples.append({
        "id": f"multi_medical_{i:04d}",
        "source": "v2_supplement",
        "source_license": "generated",
        "text": text,
        "findings": [
            {"category": "medical", "subcategory": "medical.diagnosis", "severity": "critical",
             "explanation": f"Protected health information: {dx} diagnosis with treatment plan and medication list"},
            {"category": "pii", "subcategory": "pii.identity", "severity": "critical",
             "explanation": f"Patient identity: {name} with SSN, date of birth, and medical record number"},
            {"category": "medical", "subcategory": "medical.insurance", "severity": "warning",
             "explanation": "Health insurance policy details including carrier name and member ID"},
        ]
    })

# --- Code files with multiple vulnerability types ---
for i in range(200):
    lang = random.choice(["python", "javascript", "java"])

    if lang == "python":
        text = f"""from flask import Flask, request
import os
import subprocess

app = Flask(__name__)

DB_PASSWORD = "{random.choice(REAL_PASSWORDS)}"
API_KEY = "{random.choice(REAL_API_KEYS)}"

@app.route('/search')
def search():
    query = request.args.get('q')
    # Vulnerable to SQL injection
    result = db.execute(f"SELECT * FROM products WHERE name LIKE '%{{query}}%'")
    return render_template('results.html', results=result, query=query)  # XSS via query

@app.route('/run')
def run_command():
    cmd = request.args.get('cmd')
    output = subprocess.check_output(cmd, shell=True)  # Command injection
    return output
"""
    elif lang == "javascript":
        text = f"""const express = require('express');
const app = express();

const STRIPE_KEY = "{random.choice(REAL_API_KEYS)}";
const DB_PASS = "{random.choice(REAL_PASSWORDS)}";

app.get('/user/:id', (req, res) => {{
    // SQL injection
    db.query(`SELECT * FROM users WHERE id = ${{req.params.id}}`);
}});

app.get('/page', (req, res) => {{
    // Reflected XSS
    res.send(`<h1>Search: ${{req.query.q}}</h1>`);
}});

app.post('/eval', (req, res) => {{
    // Remote code execution
    const result = eval(req.body.code);
    res.json({{ result }});
}});
"""
    else:
        text = f"""import java.io.*;
import java.sql.*;

public class UserService {{
    private static final String DB_PASSWORD = "{random.choice(REAL_PASSWORDS)}";
    private static final String API_KEY = "{random.choice(REAL_API_KEYS)}";

    public User getUser(String id) throws SQLException {{
        // SQL injection
        Statement stmt = conn.createStatement();
        ResultSet rs = stmt.executeQuery("SELECT * FROM users WHERE id = '" + id + "'");
        return mapUser(rs);
    }}

    public void processData(InputStream input) throws Exception {{
        // Insecure deserialization
        ObjectInputStream ois = new ObjectInputStream(input);
        Object obj = ois.readObject();
    }}
}}
"""

    samples.append({
        "id": f"multi_vuln_code_{i:04d}",
        "source": "v2_supplement",
        "source_license": "generated",
        "text": text,
        "findings": [
            {"category": "credentials", "subcategory": "credentials.password" if "PASSWORD" in text else "credentials.api_key", "severity": "critical",
             "explanation": "Hardcoded credentials in source code — password and API key stored as string literals instead of environment variables"},
            {"category": "malicious", "subcategory": "malicious.injection", "severity": "critical",
             "explanation": "SQL injection vulnerability: user input directly interpolated into SQL query without parameterization"},
            {"category": "malicious", "subcategory": "malicious.injection", "severity": "critical",
             "explanation": "Additional injection vulnerability: command injection, XSS, or insecure deserialization allowing arbitrary code execution"},
        ]
    })

# --- Financial documents with multiple finding types ---
for i in range(200):
    name = random.choice(NAMES)
    ssn = random.choice(SSNS)

    text = f"""TAX RETURN SUMMARY — {random.randint(2024, 2026)}
Prepared by: Anderson & Associates CPA

Taxpayer: {name}
SSN: {ssn}
Filing Status: {random.choice(['Single', 'Married Filing Jointly', 'Head of Household'])}

INCOME:
  Wages (W-2): ${random.randint(80, 350)},{random.randint(100,999)}
  Interest Income: ${random.randint(500, 15000):,}
  Dividend Income: ${random.randint(1000, 25000):,}
  Capital Gains: ${random.randint(5000, 100000):,}

DEDUCTIONS:
  Mortgage Interest: ${random.randint(8000, 35000):,}
  State Taxes: ${random.randint(5000, 25000):,}
  Charitable: ${random.randint(1000, 15000):,}

Bank Account for Refund:
  Routing: {random.choice(['021000021', '067014822', '121000248'])}
  Account: {''.join(random.choices('0123456789', k=10))}
"""

    samples.append({
        "id": f"multi_tax_{i:04d}",
        "source": "v2_supplement",
        "source_license": "generated",
        "text": text,
        "findings": [
            {"category": "financial", "subcategory": "financial.tax", "severity": "critical",
             "explanation": f"Individual tax return with detailed income, deductions, and filing information for tax year"},
            {"category": "pii", "subcategory": "pii.identity", "severity": "critical",
             "explanation": f"Taxpayer identity: {name} with Social Security Number"},
            {"category": "financial", "subcategory": "financial.bank_account", "severity": "critical",
             "explanation": "Bank routing and account numbers for direct deposit — enables unauthorized transfers"},
        ]
    })


# =============================================================================
# WRITE OUTPUT
# =============================================================================

random.shuffle(samples)

OUTPUT.parent.mkdir(parents=True, exist_ok=True)
with open(OUTPUT, "w") as f:
    for s in samples:
        f.write(json.dumps(s) + "\n")

print(f"Generated {len(samples):,} supplemental samples")
print(f"  Safe with credential patterns: {sum(1 for s in samples if s['id'].startswith('safe_')):,}")
print(f"  Multi-finding documents: {sum(1 for s in samples if s['id'].startswith('multi_')):,}")
print(f"Output: {OUTPUT}")

# Stats
from collections import Counter
finding_counts = Counter()
for s in samples:
    finding_counts[len(s["findings"])] += 1
print(f"\nFindings per document:")
for k, v in sorted(finding_counts.items()):
    print(f"  {k} findings: {v} samples")
