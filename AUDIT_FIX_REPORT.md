# Aegis Forensics integration audit — 16 November 2026

## A. Issue status

| Issue | Root cause / finding | Files changed | Validation | Status |
|---|---|---|---|---|
| Network CSV semantic search | Event-content allowlist excluded `proto`, `service`, `state`, `attack_cat`. The dashboard receives original parsed evidence, not an encoded ML feature frame. | `modules/semantic_search.py`, `tests/test_semantic_search.py` | Demo CSV: zero searchable records before fix; all 40 Generic rows retrieved with forced lexical fallback afterward. Empty/missing values, duplicate text, case changes and multiline source spans tested. | Fixed |
| Search relevance | Lexical character resemblance returned every record, even without a shared query token. | Same | `unauthorized access` has no lexical matches in the synthetic network fixture; no matches invented. | Fixed for lexical mode; embedding output remains ranked similarity |
| Search reruns | Results already had sound case/evidence/query/content cache keys. Tabs lacked persistent selection. Search exceptions lacked a local error state. | `dashboard/app.py`, `requirements.txt`, both changed test files | Existing cache tests; real Streamlit widget test; explicit exception regression. | Fixed; Streamlit 1.66+ required |
| Saved Network CSV scan | Navigation saved an evidence link with `scan_record=None`; no scan snapshot was persisted. | `dashboard/app.py`, `tests/test_audit_fix_regressions.py` | Execute actual handoff branch against temporary case/evidence storage, verify saved SHA, checkpoint identity, split, case and exact scan selection. | Fixed for future handoffs; existing histories unchanged |
| Saved vs derived predictions | Investigation intentionally runs current inference from verified source; it is distinct from saved results. | `dashboard/app.py` | Existing historical selection/report tests plus new handoff regression. | Separate captions and historical ML panel |
| Evaluation | Existing upload evaluation used DataFrame index membership and omitted confusion counts; it ran automatically when labels existed. | `modules/ml_evaluation.py`, dashboard, evaluation CLI, new regressions | Verified CSV record identities; reordered rows, duplicate content, mismatched evidence and invalid labels. Actual demo inference for both models. | Explicit opt-in evaluation with full binary metrics |
| Flag for review | Audit notes survived restart, but displayed state and deduplication were session-only. Identity was just case + finding ID. | `modules/finding_reviews.py`, `modules/integrity.py`, dashboard, new regressions | Reload without session memory, duplicate action, different case/evidence/scan/record, broken-chain refusal. | Fixed; pending review only; predictions unchanged |
| Audit integrity | FINAL-TEST-001 verifies. CASE-2026-001 and TEST-003 fail with “Entry 1 was modified.” | Dashboard adds workspace verification; integrity adds optional atomic duplicate suppression only | Existing 20 audit tests; read-only verification of all 11 local cases. | Nine internally consistent, two preserved failures |
| Missing timeline timestamps | Expected: no recognized absolute event-time field. `dur` is numeric duration and cannot become an absolute timestamp, including explicit selection. | No timeline implementation change | Existing timestamp tests cover timezone-aware formats, explicit selection, ordering, numeric rejection and source references. Demo: 0 resolved / 200 unresolved. | Correct behavior preserved |
| Finding traceability | Existing independently parsed CSV locations and model provenance are retained. | No locator/model implementation change | Existing CSV, model provenance, report, and historical selection suites; new multiline-search test. | Automated regressions pass |
| Reports, exports, YARA, hashing, case storage | Existing behavior retained. | No changes to report/export/YARA/hash implementation | Complete available suite includes Markdown validation, PDF extraction, saved reports, scanner handoff, and YARA tests. | See test results |

## B. Test results

- Baseline, before modifications: **322 tests, 320 passed, 2 failed**, 81.652 seconds. Failures: `test_python_candidate_is_read_as_data_and_never_executed` and `test_real_windows_sharing_lock_can_be_retried_after_release`, both returning `retry` where `scanned` was expected.
- Filesystem-monitor suite repeated unchanged in isolation: **27/27 passed**, 15.230 seconds. A direct harmless Python-file inspection also returned `scanned`. The baseline failure cause remains unconfirmed; no filesystem implementation or timeout was changed.
- Focused semantic search: **16/16 passed** after the search/UI changes.
- Focused audit integrity: **20/20 passed** after the optional duplicate suppression change.
- Focused new regressions: **5/5 passed**, including real Streamlit widgets, persistent review notes, verified evaluation alignment and actual dashboard handoff execution.
- First complete post-fix run: **331/331 passed**, 54.529 seconds, before the final widget regression and final isolation guard were included.
- Final complete run: **332/332 passed**, **58.747 seconds**, including the real Streamlit widget regression and final case-isolation guard. Full output: `audit_artifacts/audit_fix_full_tests.txt`.

### Actual evaluation of the 200-row demo file

Random-split checkpoints, default detector threshold. Ground truth: 100 normal, 100 attack. These are metrics on this file only; its relationship to checkpoint training data was not established. This is **not independent holdout performance** or a full-dataset claim.

| Model | Flagged | TP | TN | FP | FN | Accuracy | Precision | Recall | F1 |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| XGBoost | 105 | 99 | 94 | 6 | 1 | 0.9650 | 0.9429 | 0.9900 | 0.9659 |
| Isolation Forest | 69 | 53 | 84 | 16 | 47 | 0.6850 | 0.7681 | 0.5300 | 0.6272 |

Confusion matrices `[TN, FP; FN, TP]`: XGBoost `[[94,6],[1,99]]`; Isolation Forest `[[84,16],[47,53]]`. Exact metrics and checkpoint provenance: `audit_artifacts/demo_evaluation_random.json`.

Neither `label` nor `attack_cat` is used as a prediction feature. The existing strict checkpoint schema, category domains, artifact hashes and no-silent-model-fallback behavior were retained and tested. Search indexing `attack_cat` does not feed it into inference.

## C. Files changed / added

Existing files backed up before modification under `backups/audit_fix_20261116_154302/`:

- `dashboard/app.py`: saved network-scan handoff, persistent tabs, explicit search errors, durable pending-review display, audit verification access, historical/derived labeling and opt-in evaluation.
- `modules/semantic_search.py`: network category fallback fields, cache version bump, lexical relevance guard.
- `modules/integrity.py`: optional exact action/details duplicate suppression under the existing interprocess lock; historical entries remain untouched.
- `tests/test_semantic_search.py`: network evidence, multiline locators, actual demo data, error display and tab configuration regressions; update an old lexical test to query the content it expects to retrieve.
- `requirements.txt`: minimum Streamlit 1.66 for the state-tracked tab API used by the installed environment.

New source/test files:

- `modules/finding_reviews.py`: stable full-finding identity including case and scan/analysis context; verified audit reload; append-only review persistence.
- `modules/ml_evaluation.py`: binary metrics aligned through verified source record identities; reject ambiguous or foreign evidence.
- `tools/evaluate_labeled_csv.py`: explicit read-only labeled evaluation CLI; prints JSON, never trains or replaces models.
- `tests/test_audit_fix_regressions.py`: review, evaluation, network handoff and real Streamlit rerun regressions using temporary/synthetic evidence.
- `AUDIT_FIX_REPORT.md`: this report.

Generated verification artifacts:

- `audit_artifacts/demo_evaluation_random.json`: exact demo metrics and model provenance, UTF-8 JSON.
- `audit_artifacts/audit_fix_case_verification.json`: read-only per-case verification and current log SHA-256 values.
- `audit_artifacts/audit_fix_integrity_tests.txt`: focused audit test output.
- `audit_artifacts/audit_fix_filesystem_tests.txt`: unchanged filesystem suite rerun output.
- `audit_artifacts/audit_fix_full_tests.txt`: final complete test output.

No training/testing dataset, checkpoint, historical evidence file or historical audit entry was edited. Temporary regression cases are separate from the user's cases. Verification can create the existing architecture's lock sidecars; it does not rewrite audit logs.

## D. Remaining limitations

- Broken historical chains remain broken and blocked. A hash mismatch establishes a verification failure, not who changed the entry or why. Do not claim those cases have valid chains. Unanchored chains establish internal consistency and cannot prove authenticity or detect every tail truncation.
- Old free-text review notes are preserved. They lack enough scan/evidence identity to safely assign a modern review badge; the code does not guess or backfill them. New structured notes survive session restart.
- Lexical fallback matches shared query tokens; it cannot infer the concept “unauthorized access” from protocol/category values alone. Sentence-transformer availability still depends on the existing reviewed local artifact manifest. No model download was performed.
- Network scan snapshots are saved when **Open in Investigations** is clicked. Previously unsaved scans are not reconstructed or represented as historical facts. The current handoff saves the currently selected model; it does not claim both checkpoints ran in a single scan.
- Search prioritizes existing event-content fields. For CSVs without event-content fields it indexes the explicit network category allowlist, including `attack_cat` if present. It does not index arbitrary numeric measurements, identifiers or every string column.
- Automated tests exercise Streamlit widgets and extracted dashboard branches, not a complete human-driven browser session. End-to-end visual layout, a real Ollama-generated response and privileged Windows/Defender operations were not manually exercised.
- Git is unavailable on this shell's PATH, so change review used pre-edit backups and direct source inspection.

## E. Instructor demo readiness

Automated verification supports demonstrating: network CSV upload/inference, checkpoint provenance and schema refusal, individual CSV evidence references, Generic lexical search, search persistence, timeline's honest unresolved state, pending review persistence, future saved-scan handoff/version selection, per-case audit verification, and existing validated report/Markdown/PDF paths.

Use **FINAL-TEST-001** and explicitly select its case history scope when opening existing evidence. The default all-case history view correctly refuses to trust a collection containing broken chains. Keep saved historical findings and current derived predictions clearly identified.

Do not demonstrate broken case histories as valid, review flags as confirmed false positives, model scores as correctness, the demo sample as independent holdout performance, duration as an event timestamp, or unavailable embeddings/Ollama as verified working services. Do one visual rehearsal before presenting; the baseline filesystem timing failures warrant observing monitoring behavior on the demonstration laptop.

## F. Exact PowerShell commands

Run from the project directory:

```powershell
Set-Location 'C:\Users\umair\Documents\ML_Project\ai-forensics-platform'
.\.venv\Scripts\python.exe -m streamlit run dashboard/app.py
```

Complete available test suite:

```powershell
.\.venv\Scripts\python.exe -m unittest discover -s tests -v
```

Focused regressions:

```powershell
.\.venv\Scripts\python.exe -m unittest discover -s tests -p test_semantic_search.py -v
.\.venv\Scripts\python.exe -m unittest discover -s tests -p test_audit_fix_regressions.py -v
.\.venv\Scripts\python.exe -m unittest discover -s tests -p test_audit_integrity.py -v
```

Explicit demo evaluation without training or artifact mutation:

```powershell
.\.venv\Scripts\python.exe tools/evaluate_labeled_csv.py data/training/UNSW_NB15_demo_balanced.csv --split random
```

Read-only active case verification:

```powershell
.\.venv\Scripts\python.exe -c "from modules.integrity import EvidenceIntegrity; print(EvidenceIntegrity.verify_audit_trail('FINAL-TEST-001'))"
```
