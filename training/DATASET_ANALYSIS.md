# TorchSight Dataset Analysis & Processing Plan

## Executive Summary

**Total taxonomy subcategories:** 50
**Target dataset size:** ~13,550 samples
**Real data available:** ~5,200 samples (38%)
**Synthetic data needed:** ~8,350 samples (62%)
**Fully synthetic categories:** 22 (no real data source at all)

---

## 1. Dataset Inventory

### Downloaded & Ready

| Dataset | Records | License | Status |
|---------|---------|---------|--------|
| Enron Emails | 517,401 emails / 150 mailboxes | Public (FERC release) | Raw, unlabeled |
| SecLists | ~48,600 payloads + 56M passwords | MIT | Implicit labels by directory |
| MITRE ATT&CK | 835 techniques, 696 malware, 187 groups | Apache 2.0 | STIX labeled |
| NVD | 10,000 CVEs (1988-2004) | Public domain | CVSS/CWE labeled |
| MTSamples | 4,999 medical transcriptions | CC0 | Specialty labels |
| OWASP WSTG | 126 test case guides | CC BY-SA 4.0 | Methodology docs |
| CRS Reports | 200 reports (metadata only) | Public domain (17 USC §105) | Need PDF download |
| Army Doctrine | 1 PDF + index | Public domain (17 USC §105) | Need more downloads |

### Excluded (License Issues)

| Dataset | Reason | Replacement |
|---------|--------|-------------|
| MIMIC-III | PhysioNet DUA prohibits LLM use | MTSamples + synthetic |
| Exploit-DB | GPL v2, derivative work ambiguity | NVD metadata + synthetic |

---

## 2. Per-Dataset Deep Analysis

### 2.1 Enron Emails (517K emails)

**Taxonomy Mapping:**

| Subcategory | Volume | Quality | Notes |
|-------------|--------|---------|-------|
| pii.identity | ~517K (names in every email) | HIGH | Full names in headers + signatures |
| pii.contact | ~50K+ (phones, addresses) | HIGH | Signature blocks, meeting invites |
| pii.identity (SSN) | ~5-10 | RARE | Real SSN found (522-94-9373) |
| credentials.password | ~20-30 | LOW | Plaintext passwords (megan1, WELCOME, 3fqsh7) |
| confidential.internal | ~hundreds | MODERATE | Exec committee meetings, trade secrets |
| confidential.legal | ~hundreds | MODERATE | Litigation holds, privilege claims |
| financial.transaction | ~thousands | HIGH | Energy trading, dollar amounts, contracts |

**Processing Strategy:**
- Sample ~2,000 emails with richest PII (those with signature blocks)
- Extract structured fields: full_name, email, phone, address
- Flag emails with passwords, financial data, legal content
- Use as base for synthetic PII augmentation

### 2.2 SecLists (~48K attack payloads)

**Taxonomy Mapping:**

| Subcategory | Payload Count | Source Files |
|-------------|---------------|--------------|
| malicious.injection (XSS) | 30,816 | Fuzzing/XSS/**/*.txt |
| malicious.injection (Cmd) | 8,774 | command-injection-commix.txt, UnixAttacks.fuzzdb.txt |
| malicious.injection (SQLi) | 594 | Fuzzing/Databases/SQLi/*.txt |
| malicious.injection (LDAP) | 26 | LDAP.Fuzzing.txt |
| malicious.shell | 61 files / 7,047 lines | Web-Shells/**/* |
| malicious.obfuscated | 8,300+ | URL-encoded cmd injection |
| malicious.xxe | 51 | XXE-Fuzzing.txt |
| malicious.ssti | 89 | template-engines-*.txt |
| malicious.ssrf | ~80 | Embedded in XXE/LFI files |
| malicious.prototype_pollution | ~0 | Not covered |
| credentials.password | ~56M lines | Passwords/**/*.txt |

**Processing Strategy:**
- XSS/SQLi/CmdInj: Sample 500 per type, wrap in realistic file contexts (HTML forms, log entries, config files)
- Web shells: All 61 files usable as-is (real PHP/JSP/ASP shells)
- Passwords: Sample 500 unique, embed in .env files, config files, credential dumps
- XXE/SSTI/SSRF: Too few — use as seeds for synthetic generation

### 2.3 MITRE ATT&CK (835 techniques + 696 malware)

**Taxonomy Mapping:**

| Subcategory | Count | Content |
|-------------|-------|---------|
| malicious.malware | 787 | Malware descriptions + tool profiles |
| malicious.exploit | 835 | Attack technique descriptions |

**Tactics Distribution:** defense-evasion (262), persistence (181), privilege-escalation (140), credential-access (80), execution (70), C2 (55), discovery (50)

**Processing Strategy:**
- Extract technique name + description as training context
- Map tactics to our severity levels
- Use malware descriptions for malicious.malware samples
- Pair with NVD CVE data where external references overlap

### 2.4 NVD (10,000 CVEs)

**CRITICAL ISSUE:** Date range is 1988-2004 only. Missing 20+ years of modern CVEs.

**CWE Distribution:**
- Buffer Overflow (CWE-119/120): 154
- Input Validation (CWE-20): 82
- XSS (CWE-79): 79
- Path Traversal (CWE-22): 45
- Code Injection (CWE-94): 39
- SQLi (CWE-89): 24
- Command Injection (CWE-78): 7
- SSRF (CWE-918): 2
- XXE (CWE-611): 0
- SSTI: 0
- 8,920 entries classified "NVD-CWE-Other" (unclassified)

**Severity:** HIGH: 4,565 | MEDIUM: 4,448 | LOW: 842 | CRITICAL: 48

**Processing Strategy:**
- Extract CVE ID + description + CVSS + CWE as structured training samples
- Map CWE IDs to our taxonomy subcategories
- **ACTION NEEDED:** Download additional NVD pages (2005-2026) for modern vulnerability coverage
- Use descriptions as context for malicious.exploit training

### 2.5 MTSamples (4,999 records)

**Taxonomy Mapping:**

| Subcategory | Count | Notes |
|-------------|-------|-------|
| medical.diagnosis | ~4,086 (82%) | Assessment/impression sections |
| medical.prescription | ~2,149 (43%) | Medication lists, dosages |
| medical.lab_result | ~1,461 (29%) | Blood work, cholesterol, etc. |
| pii (any) | ~263 (5%) | Templated/anonymized — NOT real PII |

**Top Specialties:** Surgery (1,103), Consult (516), Cardiovascular (372), Orthopedic (355), Radiology (273)

**Processing Strategy:**
- Inject synthetic PII (names, DOB, SSN, addresses) into transcriptions
- Split into diagnosis/prescription/lab_result based on content analysis
- Generate structured lab report formats (the originals are narrative only)

### 2.6 OWASP WSTG (126 test guides)

**Category Distribution:** Input Validation (31), Client-side (16), Config (14), Auth (11), Session (11), Business Logic (11), Info Gathering (10), Authorization (7), Identity (5), Crypto (4), API (4), Error Handling (2)

**Processing Strategy:**
- NOT direct training samples — these are testing methodology docs
- Use as seed templates for synthetic payload generation
- Extract inline example payloads where present
- Reference for ensuring our taxonomy covers all OWASP categories

### 2.7 CRS Reports (200 metadata files)

**KEY LIMITATION:** Only JSON metadata downloaded. PDFs/HTML not fetched yet.

**Topic Coverage:**

| Subcategory | Reports | Examples |
|-------------|---------|---------|
| confidential.weapons_systems | 48 | ICBM/Sentinel, Hypersonic, THAAD, Columbia SSBN, DDG(X), NGAD |
| confidential.military | 87 | Force structure, combatant commands, SOF, NDAA, acquisition |
| confidential.nuclear | 12 | North Korea/Iran/Russia nukes, NC3, arms control |
| confidential.intelligence | ~16 | DNI, IC leadership, FISA 702, USCYBERCOM, declassification |

**Rich military terminology:** SSBN, DDG, CVN, ICBM, THAAD, PATRIOT, LRHW, NGAD, CCA, A2/AD, SOF, USSOCOM, MDTF, BMD, AUKUS, NC3

**Processing Strategy:**
- **ACTION NEEDED:** Download PDFs via `formats[].url` links in JSON
- Extract text from PDFs with OCR/text extraction
- These are UNCLASSIFIED public reports — perfect for teaching the model what defense topics look like
- Only 22/200 have summary text in the JSON; rest need PDF content

---

## 3. Master Gap Analysis

### Coverage Matrix

| Subcategory | Target | Real Data | Synth Needed | Gap Level |
|-------------|--------|-----------|--------------|-----------|
| **PII** | | | | |
| pii.identity | 800 | 800 (Enron) | 0 | COVERED |
| pii.contact | 600 | 600 (Enron) | 0 | COVERED |
| pii.government_id | 400 | 0 | 400 | FULL GAP |
| pii.biometric | 200 | 0 | 200 | FULL GAP |
| pii.metadata | 300 | 0 | 300 | FULL GAP |
| pii.behavioral | 200 | 0 | 200 | FULL GAP |
| **CREDENTIALS** | | | | |
| credentials.password | 400 | 400 (SecLists) | 0 | COVERED |
| credentials.api_key | 300 | 0 | 300 | FULL GAP |
| credentials.token | 200 | 0 | 200 | FULL GAP |
| credentials.private_key | 200 | 0 | 200 | FULL GAP |
| credentials.connection_string | 200 | 0 | 200 | FULL GAP |
| credentials.cloud_config | 300 | 0 | 300 | FULL GAP |
| credentials.cicd | 200 | 0 | 200 | FULL GAP |
| credentials.container | 200 | 0 | 200 | FULL GAP |
| **FINANCIAL** | | | | |
| financial.credit_card | 300 | 0 | 300 | FULL GAP |
| financial.bank_account | 200 | 0 | 200 | FULL GAP |
| financial.tax | 200 | 0 | 200 | FULL GAP |
| financial.transaction | 300 | 100 (Enron) | 200 | PARTIAL |
| **MEDICAL** | | | | |
| medical.diagnosis | 400 | 400 (MTSamples) | 0 | COVERED |
| medical.prescription | 300 | 300 (MTSamples) | 0 | COVERED |
| medical.lab_result | 300 | 150 (MTSamples) | 150 | PARTIAL |
| medical.insurance | 200 | 0 | 200 | FULL GAP |
| **CONFIDENTIAL** | | | | |
| confidential.classified | 300 | 0 | 300 | FULL GAP |
| confidential.internal | 300 | 200 (Enron) | 100 | PARTIAL |
| confidential.legal | 300 | 100 (Enron) | 200 | PARTIAL |
| confidential.military | 300 | 87 (CRS*) | 213 | PARTIAL |
| confidential.military_comms | 250 | 0 | 250 | FULL GAP |
| confidential.weapons_systems | 200 | 48 (CRS*) | 152 | PARTIAL |
| confidential.intelligence | 300 | 16 (CRS*) | 284 | PARTIAL |
| confidential.geospatial | 200 | 0 | 200 | FULL GAP |
| confidential.nuclear | 150 | 12 (CRS*) | 138 | PARTIAL |
| confidential.education | 300 | 0 | 300 | FULL GAP |
| **MALICIOUS** | | | | |
| malicious.injection | 400 | 400 (SecLists) | 0 | COVERED |
| malicious.exploit | 300 | 300 (NVD+MITRE) | 0 | COVERED |
| malicious.shell | 200 | 61 (SecLists) | 139 | PARTIAL |
| malicious.obfuscated | 200 | 200 (SecLists) | 0 | COVERED |
| malicious.phishing | 200 | 0 | 200 | FULL GAP |
| malicious.malware | 200 | 200 (MITRE) | 0 | COVERED |
| malicious.prompt_injection | 300 | 0 | 300 | FULL GAP |
| malicious.supply_chain | 200 | 0 | 200 | FULL GAP |
| malicious.deserialization | 200 | 0 | 200 | FULL GAP |
| malicious.ssrf | 200 | 80 (SecLists) | 120 | PARTIAL |
| malicious.redos | 150 | 0 | 150 | FULL GAP |
| malicious.steganography | 150 | 0 | 150 | FULL GAP |
| malicious.prototype_pollution | 150 | 0 | 150 | FULL GAP |
| malicious.xxe | 200 | 51 (SecLists) | 149 | PARTIAL |
| malicious.ssti | 200 | 89 (SecLists) | 111 | PARTIAL |
| **SAFE** | | | | |
| safe.documentation | 300 | 0 | 300 | FULL GAP |
| safe.code | 300 | 0 | 300 | FULL GAP |
| safe.config | 200 | 0 | 200 | FULL GAP |
| safe.media | 200 | 0 | 200 | FULL GAP |

*CRS = metadata only; need PDF downloads for actual content

### Summary

- **Covered (real data sufficient):** 9 subcategories
- **Partial (real + synthetic mix):** 13 subcategories
- **Full gap (100% synthetic):** 28 subcategories
- **Total synthetic samples needed:** ~8,350

---

## 4. Action Items

### Phase 1: Process Existing Data

1. **enron_processor.py** — Extract PII-rich emails, structure fields, label pii.*/confidential.internal/credentials.*
2. **seclists_processor.py** — Categorize payloads by type, wrap in file contexts, label malicious.*
3. **mitre_processor.py** — Extract technique/malware descriptions, map to malicious.malware/exploit
4. **nvd_processor.py** — Extract CVE descriptions + CWE mapping, label malicious.exploit/injection
5. **mtsamples_processor.py** — Split by content type, inject synthetic PII, label medical.*
6. **crs_processor.py** — Download PDFs, extract text, label confidential.military/weapons/nuclear/intel

### Phase 2: Fill Data Gaps

7. **Download more NVD data** — Fetch 2005-2026 CVEs (currently only have 1988-2004)
8. **Download CRS PDFs** — Fetch actual report content from `formats[].url`
9. **Download more Army doctrine** — FAS mirror has 538+ PDFs available

### Phase 3: Synthetic Data Generation

10. **synth_pii.py** — Government IDs, biometrics, metadata, behavioral tracking
11. **synth_credentials.py** — API keys, tokens, private keys, cloud configs, CI/CD, containers
12. **synth_financial.py** — Credit cards, bank accounts, tax docs
13. **synth_medical.py** — Insurance records, structured lab reports
14. **synth_confidential.py** — Classification markings, military comms (OPORD/FRAGO/SITREP), geospatial, nuclear, education
15. **synth_malicious.py** — Prompt injection, supply chain, deserialization, SSRF, ReDoS, steganography, prototype pollution, phishing
16. **synth_safe.py** — Clean docs, code, configs, media descriptions

---

## 5. Output Format

Every processor outputs JSONL with this schema:

```json
{
  "id": "enron_00001",
  "source": "enron",
  "source_license": "public_ferc",
  "text": "...",
  "findings": [
    {
      "category": "pii",
      "subcategory": "pii.contact",
      "severity": "warning",
      "compliance": ["GDPR", "CCPA"],
      "fields": {
        "email": "john.smith@enron.com",
        "phone": "713-853-5984"
      }
    }
  ]
}
```
