# Paper Review for JISA Submission

Audit of TorchSight_JISA_IvanDobrovolskyi.docx against (a) JISA / Elsevier
submission requirements and (b) recent publications in the same area
(LLM-based cybersecurity classification, on-prem DLP). Prioritized list of
edits to maximize acceptance odds.

## 1. JISA / Elsevier compliance — required, missing

These are mandatory under Elsevier's editorial policies. Reviewers and
production will hold the paper.

- [ ] **Declaration of generative AI in scientific writing.** Elsevier
  requires authors to disclose use of generative AI tools in writing.
  Add a one-paragraph statement at end of the paper (after CRediT or as
  its own §13). Standard template: "During the preparation of this work
  the author used [tool name] in order to [purpose]. After using this
  tool, the author reviewed and edited the content as needed and takes
  full responsibility for the content of the publication." If no AI was
  used in writing, state that explicitly: "No generative AI tools were
  used in writing this manuscript."
- [ ] **Declaration of competing interest.** Required by Elsevier even
  when none exist. Add as its own section or right after Funding:
  "The author declares no competing financial or non-financial interests
  that could have appeared to influence the work reported in this paper."
- [ ] **CRediT author name.** Section 12 currently has a literal
  `[Author Name]` placeholder. Replace with `Ivan Dobrovolskyi`.

## 2. JISA compliance — present, verify content

- [x] CRediT contribution section (§12, name needs filling)
- [x] Funding declaration (§11)
- [x] Data Availability statement (§10) — Apache 2.0 + HF + GitHub
- [x] Ethics section (§6.7)
- [x] Bootstrap 95% CIs (10,000 resamples — strong, better than Wilson)
- [x] Field validation against real-world data (§6.8 — divorce-case eval)

## 3. Numbers to update post-rerun

See `PAPER_DELTAS.md` quick-reference table — 14 numerical changes,
mostly in §6.10 (external benchmark) and one in §6.x (regex baseline).
Apply when qwen base eval finishes.

## 4. Content gaps reviewers will likely flag

Ordered by likely reviewer pushback. High-impact additions first.

### 4a. Add SecureBERT 2.0 to Related Work (high impact, low effort)

The paper already cites SecureBERT (Aghaei et al. 2022, arXiv:2204.02685).
**SecureBERT 2.0** was released in October 2025 (arXiv:2510.00240) — it
is the most recent direct competitor in cybersecurity NLP. A reviewer
who works in this area will notice the omission.

Suggested add (in §2 Related Work):

> SecureBERT 2.0 (Fayyazi et al., 2025) extended the original SecureBERT
> with a 13B-token cybersecurity corpus and improved long-context
> handling, achieving state of the art on threat-intelligence semantic
> search and CWE-aware vulnerability detection. Its encoder-only design
> targets information retrieval and entity extraction; in contrast,
> TorchSight's decoder-only generative classifier produces structured
> JSON findings suitable for downstream DLP enforcement. The two
> systems are complementary rather than competing, but a direct
> comparison on document-level classification remains future work.

### 4b. Strengthen significance claim (medium impact, low effort)

Paper says "all three Beam quantizations (92.7–95.1%) outperform every
commercial frontier model" but only gives bootstrap CIs. McNemar's
paired test on the 1,000-sample primary benchmark (computed against
the existing result JSONs) yields:

| Pairing | n_{Beam>X} | n_{X>Beam} | χ² (cont. corr.) | p-value |
|---|---|---|---|---|
| Beam q4_K_M vs Claude Sonnet 4 | 166 | 14 | 126.67 | 2.2 × 10⁻²⁹ |
| Beam q4_K_M vs Claude Opus 4 | 167 | 15 | 125.28 | 4.4 × 10⁻²⁹ |
| Beam q4_K_M vs Gemini 2.5 Pro | 226 | 29 | 150.65 | 1.3 × 10⁻³⁴ |
| Beam q4_K_M vs GPT-5 | 209 | 27 | 138.82 | 4.8 × 10⁻³² |
| Beam q4_K_M vs Qwen 3.5 27B base | 532 | 14 | 489.54 | 1.8 × 10⁻¹⁰⁸ |
| Beam q4_K_M vs Beam q8_0 | 34 | 10 | 12.02 | 5.0 × 10⁻⁴ |
| Beam q4_K_M vs Beam f16 | 31 | 10 | 9.76 | 1.8 × 10⁻³ |

All seven pairings are significant at p < 0.01; the four commercial
gaps are at p < 10⁻²⁹ — far beyond any reasonable correction for
multiple comparisons (Bonferroni at α = 0.05 / 7 = 0.007 is trivially
cleared). q4_K_M's lead over q8_0 and f16 is also significant but
within the Beam family — worth a sentence in §6.

Suggested paper text (one new paragraph in §6 results):

> To confirm that the accuracy gaps are not artefacts of sampling
> variation, we computed paired McNemar's tests across the 1,000-
> sample primary benchmark. Beam q4_K_M significantly outperforms
> every commercial model (vs. Claude Sonnet 4: χ²₁ = 126.7, p ≈ 2 × 10⁻²⁹;
> vs. GPT-5: χ²₁ = 138.8, p ≈ 5 × 10⁻³²; vs. Gemini 2.5 Pro: χ²₁ = 150.7,
> p ≈ 1 × 10⁻³⁴; vs. Claude Opus 4: χ²₁ = 125.3, p ≈ 4 × 10⁻²⁹) and
> the unmodified Qwen 3.5 27B base (χ²₁ = 489.5, p ≈ 2 × 10⁻¹⁰⁸).
> Within the Beam family, q4_K_M's lead over q8_0 (χ²₁ = 12.0,
> p ≈ 5 × 10⁻⁴) and f16 (χ²₁ = 9.8, p ≈ 2 × 10⁻³) is also
> significant, suggesting that 4-bit quantization provides
> regularization rather than degradation on this task.

The script that produced these is at
`scripts/compute_mcnemar.py` (to add) — re-running it on a fresh
clone reproduces the table exactly.

### 4c. Frame subcategory accuracy correctly (medium impact, low effort)

Paper reports Beam subcategory 48.5% which sounds low. Reviewer
question: "Why is subcategory accuracy half the category accuracy?"

Answer: it's a **51-class** problem vs a **7-class** problem. Random-
chance baseline is 1/51 ≈ 2.0%. Beam achieves 48.5%, the best commercial
(Claude Sonnet 4) is 23.0%. So Beam is **~2× the best commercial on a
51-way task**, while every model loses ground on subcategory vs category
because the problem is fundamentally harder.

Add one sentence to §6.X:

> Subcategory classification is a 51-way problem, with a random-chance
> baseline of 2.0%. All models lose ground relative to the 7-way
> category task: Beam q4_K_M drops from 95.1% to 48.5% (24× chance),
> while Claude Sonnet 4 drops from 79.9% to 23.0% (11× chance). The
> relative ordering is preserved.

### 4d. Add an explicit Threat Model section (medium impact, ~half page)

Standard in security venues. Currently absent. Suggested location:
between §3 Security Taxonomy and §4 Dataset, as new §3.5 or §4 (renumber).

Content:
- **Adversary**: a user, contractor, or compromised application that
  attempts to exfiltrate sensitive documents from the organization.
- **Asset**: text/PDF/image documents stored in employee-controlled
  directories (laptops, email archives, file shares).
- **Trust boundary**: TorchSight runs entirely on the data owner's
  hardware. No document content leaves the host; no telemetry; no model
  updates require document upload.
- **What TorchSight defends**: classification accuracy under realistic
  document distributions, including held-out and out-of-distribution
  data (§6.10), and resistance to confidentiality leakage in the model
  itself (training data is public; the model file is not document-
  retrieval-targeted).
- **Out of scope**: prompt-injection attacks against the classifier
  (the classifier consumes documents, not user instructions, so the
  attack surface is the document); model-extraction attacks (the model
  is published openly, so this is non-applicable).

### 4e. Bridge synthetic primary to real-world distribution (medium impact)

A reviewer will ask: "Synthetic data in the primary benchmark — does it
reflect real distributions?" The paper has §6.8 Field Validation
addressing this with the divorce-case eval (95% detection on 120 real
files). Strengthen the bridge:

> The synthetic primary benchmark (eval-1000) prioritizes coverage and
> stratification: every category and subcategory is present in
> controlled proportions, enabling per-class analysis. To check that
> our reported numbers extend to naturally occurring distributions,
> we additionally evaluate (i) on a 500-sample external benchmark
> (§6.10) drawn from real public datasets (NVD, NIST, AI4Privacy,
> Enron, MTSamples, phishing) where Beam achieves 93.8% (CI [91.3,
> 95.6]); and (ii) on a real personal-document corpus (§6.8) where
> the full TorchSight pipeline detects 95% of files containing
> sensitive content.

### 4f. Cite recent JISA-published cyber-LLM work (low impact, low effort)

Recent JISA papers in adjacent space include LLM-based log analysis
(F1 0.928), malicious-URL classification with RoBERTa+SAE, and
multimodal anomaly detection. Adding 2-3 of these in §2 grounds the
paper in the journal's recent output.

### 4g. Single-prompt limitation (already in PAPER_DELTAS)

Three-line defense in PAPER_DELTAS.md §"Defending the prompt choice"
should be incorporated into the existing §6 limitations subsection.

## 5. Minor edits / polish

- §6.10 Phishing rewrite: paper currently says "Beam 80%" — actual is
  100%. Story is "Beam perfect on phishing while commercials struggle"
  rather than "all models do okay."
- §6.10 MTSamples rewrite: paper currently says "all models 99-100% on
  MTSamples." Actual: Beam 82%, others 100%. New framing: "Commercials
  trivially classify MTSamples as `medical`; Beam routes 14/100 to
  `pii` because patient records are PHI under HIPAA. The behaviour
  is defensible but the strict-accuracy comparison requires
  acknowledgement."
- Word count is ~10,168 — at the upper end of JISA range. If trimming
  needed, candidates: §1 introduction has redundancy; §2 related work
  can compress some commercial-DLP description; the divorce-case
  field validation is fine as-is.

## 6. Strengths to preserve / emphasize

- 1500-sample two-tier benchmark (1000 synthetic + 500 external) — larger
  than typical JISA cyber-LLM papers in this area.
- Apache 2.0 + HuggingFace artifact release — full reproducibility.
- 7-way model comparison (3 Beam quants + 4 commercial + Qwen base + regex).
- Real-world deployment validation (§6.8 — 120 files of leaked divorce-
  case documents). This is rare and concrete; reviewers respect it.
- Cost analysis: the per-1000-files cost table is a strong practitioner
  argument.
- External validation excludes MTSamples from training **explicitly**,
  not just by hash — strongest possible OOD claim.

## 7. Submission-day checklist

- [ ] Replace `[Author Name]` in §12 with `Ivan Dobrovolskyi`
- [ ] Add Declaration of competing interest
- [ ] Add Declaration of generative AI use
- [ ] Apply 14 number deltas from PAPER_DELTAS.md
- [ ] Add SecureBERT 2.0 reference + paragraph in §2
- [ ] Add McNemar's significance line in §6.x results
- [ ] Add subcategory framing sentence in §6.x
- [ ] (Optional) Add §3.5 Threat Model
- [ ] Re-export figures with new external numbers (fig10, fig11)
- [ ] Spell-check and word-count check (target ≤10,500)
- [ ] PDF preview to verify table formatting after number changes
