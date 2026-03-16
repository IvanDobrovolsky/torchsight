# Beam v1.1 Roadmap

## v1.0 Known Limitations

Beam v1.0 is a **document classifier** — it identifies *what kind* of sensitive content a file contains. It is not a field-level extraction model. The regex safety net (52 patterns) compensates for structured values the model misses, but v1.1 should handle these natively.

### What the model should catch but currently relies on regex for

| Pattern | v1.0 | v1.1 Target |
|---------|------|-------------|
| Full SSNs (123-45-6789) | Regex catches, Beam inconsistent | Beam + regex |
| Partial/redacted SSNs (***-**-5043) | Regex catches, Beam misses | Beam + regex |
| Email addresses | Beam catches on short docs, misses on long | Beam consistent |
| Masked bank accounts (****1515) | Regex catches | Beam + regex |
| Credit card numbers | Regex catches | Beam + regex |
| API keys (AKIA..., sk_live_...) | Regex catches | Beam + regex |

### Classification gaps

| Issue | Description | v1.1 Fix |
|-------|-------------|----------|
| Tabular financial data | Multi-page pay stubs/statements classified as `confidential.internal` instead of `financial` | Add pay stub, bank statement, tax return examples to training data |
| Employer/business names | Not flagged as PII even alongside employee SSN | Add employer-in-context training examples |
| Granular financial fields | Salary, tax withholdings, 401K amounts not individually identified | Train on field-level extraction from payroll/tax documents |
| Large document chunking | Individual chunks lose document-level context | Add chunk-aware prompt that includes document metadata |

### Accuracy

| Dataset | v1.0 Accuracy | v1.1 Target |
|---------|---------------|-------------|
| Eval-1000 (synthetic) | 95.1% category | 97%+ |
| Real-world financial docs | ~85% | 93%+ |
| Full pipeline (Beam + regex + OCR) | ~97.6% (eval), ~92% (real-world) | 98%+ |

---

## v1.1 Training Plan

### New training data sources

| Source | Samples | Purpose |
|--------|---------|---------|
| Synthetic pay stubs | 2,000 | Multi-format payroll records with SSN, salary, tax fields |
| Synthetic bank statements | 2,000 | Account numbers, transactions, balances in tabular layout |
| Synthetic tax returns (1040/W2/K-1) | 1,500 | Full SSNs, income, deductions, employer EIN |
| Synthetic credit card statements | 1,000 | Card numbers, transactions, balances |
| Synthetic mortgage/loan docs | 1,000 | Loan numbers, property addresses, payment schedules |
| Synthetic legal/court docs | 1,000 | Case numbers, party names, custody terms |
| Real-world financial document patterns | 500 | Anonymized structural patterns from real document layouts |

### Training changes

- Increase field-level extraction examples in training data (model should output specific values, not just categories)
- Add chunked document examples where the model sees partial context and must still classify correctly
- Increase `num_predict` ceiling for extraction-heavy responses
- Add employer/business-in-context examples so model recognizes employer names as PII-adjacent

### Regex improvements (independent of retrain)

Additional patterns for v1.1:
- EIN (Employer Identification Number): `\d{2}-\d{7}`
- Routing numbers: `\b\d{9}\b` (with ABA validation)
- Loan/account numbers with common prefixes
- Date patterns in financial context (pay period, statement date)
- Dollar amounts in sensitive context (`\$[\d,]+\.\d{2}` near PII)
