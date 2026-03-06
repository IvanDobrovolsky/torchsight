# TorchSight Label Reference

## Overview

Every training sample produces one or more **findings**. Each finding has 4 label levels:

```
L1  Category      — what type of security concern
L2  Subcategory   — specific variant within category
L3  Severity      — risk level (critical / warning / info)
L4  Compliance    — applicable regulations (multi-label)
```

---

## L1: Category

| ID | Category | Description | Example |
|----|----------|-------------|---------|
| `pii` | Personal Identifiable Information | Data that identifies a specific individual | SSN, name + DOB, passport number |
| `credentials` | Credentials & Secrets | Authentication material or cryptographic keys | API keys, passwords, tokens, private keys |
| `financial` | Financial Data | Payment instruments and financial records | Credit card numbers, bank statements |
| `medical` | Medical / PHI | Protected health information | Diagnoses, prescriptions, lab results |
| `confidential` | Confidential Documents | Restricted-access or classified material | NDAs, classified memos, internal-only docs |
| `malicious` | Security Threats | Code or payloads designed to attack systems | SQL injection, reverse shells, exploits |
| `safe` | Safe / Clean | No security concerns detected | Documentation, clean code, photos |

---

## L2: Subcategory

### pii.*
| Subcategory | Description | Key Fields | Source Datasets |
|-------------|-------------|------------|-----------------|
| `pii.identity` | Core identity data | full_name, date_of_birth, ssn, gender, nationality | Enron, Synthetic |
| `pii.contact` | Contact information | phone, email, address, city, state, zip_code | Enron, Synthetic |
| `pii.government_id` | Government-issued identification | driver_license, passport_number, id_number, visa_number | MIDV-500, Synthetic |
| `pii.biometric` | Biometric identifiers | fingerprint_hash, face_photo_ref, iris_scan_ref | Synthetic only |

### credentials.*
| Subcategory | Description | Key Fields | Source Datasets |
|-------------|-------------|------------|-----------------|
| `credentials.password` | Plaintext or hashed passwords | password, hash, salt | SecLists, Synthetic |
| `credentials.api_key` | API keys for cloud/SaaS services | api_key, provider, scope | Synthetic |
| `credentials.token` | Authentication tokens | token, token_type (OAuth/JWT/session) | Synthetic |
| `credentials.private_key` | Cryptographic private keys | key_type (SSH/PGP/TLS), key_content | Synthetic |
| `credentials.connection_string` | Database/service URIs with auth | connection_string, db_type, host | Synthetic |

### financial.*
| Subcategory | Description | Key Fields | Source Datasets |
|-------------|-------------|------------|-----------------|
| `financial.credit_card` | Payment card data | credit_card, cvv, expiry, cardholder | Synthetic |
| `financial.bank_account` | Bank account details | bank_account, routing_number, iban | Synthetic |
| `financial.tax` | Tax documents | document_type, tax_id, income, employer | Synthetic |
| `financial.transaction` | Invoices, payments, transfers | amount, sender, recipient, reference | EDGAR, Synthetic |

### medical.*
| Subcategory | Description | Key Fields | Source Datasets |
|-------------|-------------|------------|-----------------|
| `medical.diagnosis` | Conditions and diseases | diagnosis, icd_code, severity | MTSamples, MIMIC-III, Synthetic |
| `medical.prescription` | Medications and dosages | medication, dosage, frequency, prescriber | MTSamples, Synthetic |
| `medical.lab_result` | Laboratory and imaging results | test_name, result, reference_range, flags | MIMIC-III, Synthetic |
| `medical.insurance` | Health insurance information | insurance_provider, policy_number, group_number | Synthetic |

### confidential.*
| Subcategory | Description | Key Fields | Source Datasets |
|-------------|-------------|------------|-----------------|
| `confidential.classified` | Government/military classifications | classification_level, codeword, handling_instructions | CIA FOIA, Synthetic |
| `confidential.internal` | Corporate internal-only documents | classification, department, distribution_list | Enron, Synthetic |
| `confidential.legal` | Legal privilege or restricted docs | document_type, parties, effective_date, jurisdiction | CourtListener, EDGAR, Synthetic |
| `confidential.military` | Military/defense content | operation_name, unit, coordinates, classification | Synthetic only |
| `confidential.education` | FERPA-protected student records | student_id, gpa, enrollment_status, disciplinary | Synthetic only |

### malicious.*
| Subcategory | Description | Key Fields | Source Datasets |
|-------------|-------------|------------|-----------------|
| `malicious.injection` | Injection attack payloads | payload, injection_type (SQL/XSS/cmd/LDAP/template) | SecLists, OWASP |
| `malicious.exploit` | Exploit code and PoCs | cve_id, target, payload, exploit_type | Exploit-DB, NVD |
| `malicious.shell` | Reverse/web shells and backdoors | shell_type, target_host, target_port, payload | SecLists, Exploit-DB, Synthetic |
| `malicious.obfuscated` | Encoded/obfuscated payloads | encoding (base64/hex/rot13), decoded_payload | SecLists, Synthetic |
| `malicious.phishing` | Phishing pages and social engineering | target_brand, harvested_fields, redirect_url | Synthetic |
| `malicious.malware` | Malware signatures and C2 patterns | malware_family, c2_server, behavior | MITRE ATT&CK, Synthetic |
| `malicious.prompt_injection` | LLM prompt injection and jailbreaks | injection_type (direct/indirect/jailbreak), target_model, payload | Synthetic, Garak |
| `malicious.supply_chain` | Dependency confusion, typosquatting, lockfile poisoning | attack_type, package_name, target_registry, malicious_payload | Synthetic, Backstabber's Knife |
| `malicious.deserialization` | Unsafe deserialization payloads | format (pickle/yaml/java/php), payload, gadget_chain | Exploit-DB, Synthetic |
| `malicious.ssrf` | Server-side request forgery payloads | target_url, protocol, cloud_metadata_endpoint | SecLists, Synthetic |
| `malicious.redos` | Regular expression denial of service | regex_pattern, complexity_class, estimated_impact | Synthetic |
| `malicious.steganography` | Hidden data embedded in files | carrier_type (image/audio/video), encoding_method, hidden_data_type | Synthetic |
| `malicious.prototype_pollution` | JavaScript prototype pollution | payload, target_property, attack_vector | SecLists, Synthetic |
| `malicious.xxe` | XML External Entity injection | payload, target_resource, exfiltration_method | SecLists, OWASP |
| `malicious.ssti` | Server-side template injection | template_engine, payload, target_language | SecLists, Synthetic |

### credentials.*  (additional)
| Subcategory | Description | Key Fields | Source Datasets |
|-------------|-------------|------------|-----------------|
| `credentials.cloud_config` | AWS/GCP/Azure config with secrets | provider, config_type (IAM/terraform/env), exposed_resource | Synthetic |
| `credentials.cicd` | CI/CD pipeline secrets | platform (GitHub Actions/Jenkins/GitLab CI), secret_type, pipeline_file | Synthetic |
| `credentials.container` | Container/orchestration secrets | platform (Docker/K8s/Helm), secret_location (ENV/configmap/values), exposed_secret | Synthetic |

### pii.*  (additional)
| Subcategory | Description | Key Fields | Source Datasets |
|-------------|-------------|------------|-----------------|
| `pii.metadata` | File metadata leaking identity | metadata_type (EXIF/PDF properties/Office), gps_coordinates, device_info, author | Synthetic |
| `pii.behavioral` | Behavioral/tracking data | data_type (browsing_history/search_queries/location_traces), user_identifier | Synthetic |

### safe.*
| Subcategory | Description | Source Datasets |
|-------------|-------------|-----------------|
| `safe.documentation` | README, docs, manuals | Synthetic |
| `safe.code` | Clean source code | Synthetic |
| `safe.config` | Non-sensitive configuration | Synthetic |
| `safe.media` | Photos, artwork, diagrams | Synthetic |

---

## L3: Severity

| Level | Criteria | Examples |
|-------|----------|---------|
| `critical` | Immediate, exploitable risk. Direct exposure of sensitive data or active threat. | Plaintext SSN, active API key, reverse shell, full credit card |
| `warning` | Moderate risk requiring review. Partial exposure or potential threat. | Partial PII (name without SSN), internal document without markings, suspicious pattern |
| `info` | Low or no risk. Informational classification. | Clean file, safe content, metadata-only |

### Severity Assignment Rules
- Any **full SSN, credit card, or active credential** → `critical`
- Any **malicious payload or exploit** → `critical`
- Any **prompt injection or supply chain attack** → `critical`
- Any **reverse shell, C2 beacon, or steganographic payload** → `critical`
- **Cloud config with IAM keys or terraform state secrets** → `critical`
- **CI/CD secrets or container secrets in plaintext** → `critical`
- **Name + DOB** or **name + address** (but no SSN/ID) → `warning`
- **Email address alone** → `warning`
- **EXIF GPS coordinates or file metadata with author** → `warning`
- **Behavioral tracking data** → `warning`
- **ReDoS pattern or prototype pollution vector** → `warning`
- **Internal/confidential marking** without sensitive data → `warning`
- **Safe/clean files** → `info`

---

## L4: Compliance Tags (multi-label)

| Tag | Full Name | Triggered By |
|-----|-----------|-------------|
| `GDPR` | EU General Data Protection Regulation | Any PII (name, email, address, DOB, biometric) |
| `HIPAA` | Health Insurance Portability & Accountability Act | Any PHI (diagnosis, prescription, lab result, insurance) |
| `PCI-DSS` | Payment Card Industry Data Security Standard | Credit card numbers, CVVs, cardholder data |
| `SOX` | Sarbanes-Oxley Act | Financial records of public companies |
| `FERPA` | Family Educational Rights & Privacy Act | Student records, grades, enrollment data |
| `CCPA` | California Consumer Privacy Act | PII of California residents |
| `ITAR` | International Traffic in Arms Regulations | Military/defense technical data |
| `EAR` | Export Administration Regulations | Dual-use technology |

### Compliance Assignment Rules
- PII of any kind → `GDPR` (unless clearly non-EU)
- PII with US context → add `CCPA`
- Medical data → `HIPAA`
- Credit card / payment → `PCI-DSS`
- Financial records of corporations → `SOX`
- Student data → `FERPA`
- Military/defense → `ITAR`
- Dual-use tech → `EAR`

---

## Extracted Data Fields (complete reference)

### Identity
`full_name` `first_name` `last_name` `date_of_birth` `gender` `nationality` `ssn` `tax_id`

### Contact
`email` `phone` `address` `city` `state` `zip_code` `country`

### Government IDs
`driver_license` `passport_number` `id_number` `visa_number` `issue_date` `expiration_date` `issuing_authority`

### Credentials
`username` `password` `api_key` `token` `secret` `private_key` `connection_string` `certificate`

### Financial
`credit_card` `cvv` `bank_account` `routing_number` `iban` `swift_code` `amount` `currency`

### Medical
`medical_record_number` `diagnosis` `icd_code` `medication` `dosage` `prescriber` `insurance_provider` `policy_number` `group_number`

### Threat
`threat_type` `payload` `attack_vector` `risk_level` `cve_id` `target` `c2_server` `injection_type` `target_model` `package_name` `target_registry` `gadget_chain` `regex_pattern` `template_engine` `encoding_method` `carrier_type`

### File Metadata
`metadata_type` `gps_coordinates` `device_info` `author` `software` `creation_date` `modification_date`

### Behavioral
`data_type` `user_identifier` `tracking_domain` `collection_method`

### Cloud / Infrastructure
`provider` `config_type` `exposed_resource` `platform` `secret_location` `pipeline_file`

### Document
`document_type` `classification` `organization` `department` `effective_date` `expiration_date` `parties`

### Meta
`compliance` `summary` `content_type` `subject` `record_count`
