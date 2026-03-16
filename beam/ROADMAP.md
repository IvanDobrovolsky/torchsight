# Beam v1.1 Roadmap

## v1.0 Known Limitations

Beam v1.0 is a **document classifier** — it identifies *what kind* of sensitive content a file contains. It is not a field-level extraction model. TorchSight's regex safety net (separate from Beam) compensates for structured patterns the model misses.

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

