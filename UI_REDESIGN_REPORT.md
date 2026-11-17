# Threat Rules and Model Evaluation redesign

Implemented in the existing React frontend. No forensic backend, API contract, checkpoint, original rule file, evidence, audit record, or Streamlit source was modified. The original frontend was backed up under `backups/ui_rules_evaluation/` before edits.

## Threat Rules

- Cards show individual rule declarations rather than a large source-code dump: actual name, description, severity, YARA type, source filename, and recorded MITRE/tag metadata.
- Search covers each rule's own declaration and metadata. Severity, type, source-file filters and nine-card pagination use returned data only.
- “View Rule Details” opens the existing accessible Radix drawer. All readable metadata stays available; missing information is labeled as unavailable.
- “View Source Code” is collapsed initially. Safe React text-token highlighting preserves the exact API-provided file, including imports and other declarations. A browser test compares displayed source to the actual API response. No HTML injection or rule execution is used.
- The current six files contain 16 readable declarations. Counts describe definitions and metadata, not enabled status, detection counts, or security coverage.

## Model Evaluation

- A deliberate empty state contains no prefilled performance values. The existing labeled-data confirmation and real evaluation endpoint are retained.
- Checkpoint model, split, and XGBoost classification threshold live in a labeled configuration panel. Existing queued-job cancellation remains available when the API reports it is supported.
- Completed evaluations show Accuracy, Precision, Recall and F1 KPI cards with definitions; dataset name/hash, model/split, sample count and label distribution; a keyboard-operable confusion matrix; and interactive decision-outcome charts.
- Selecting a matrix cell explains the corresponding TP/TN/FP/FN count and percentage. Charts use returned counts or metrics; no ROC curve, score or match is inferred.
- Up to eight completed runs can be inspected within the current case/evidence workspace. Model comparison requires different models with matching case, evidence ID, SHA-256, sample count, class-label distribution and split. Comparison concerns labeled binary decisions, not equivalence of learning methods or raw scores. The XGBoost threshold remains visible in the comparison table.
- Changing configuration does not relabel old results. A new attempt is distinguished from the last completed run; evidence/case changes clear the local run workspace. Invalid or context-mismatched results do not populate the dashboard.
- Demonstration-file and selected-file limitations are prominent. Raw request/provenance JSON is available only in a collapsed expert section.

## Files changed

Existing files modified:

| File | Reason |
|---|---|
| `frontend/src/pages/Rules.tsx` | Metadata catalog, search/filters, pagination and details/source drawer |
| `frontend/src/pages/Evaluation.tsx` | Evaluation dashboard, job states, KPI/matrix display, configuration and guarded comparison |
| `frontend/e2e/workflows.spec.ts` | Preserve regression coverage on alternate ports; explicitly select its case; compare the dashboard evidence count with the real case-scoped API count rather than assuming globally fresh storage |

New frontend files:

- `frontend/src/lib/ruleCatalog.ts`: display-only source tokenizer and metadata extraction.
- `frontend/src/components/common/SourceCode.tsx`: lossless, escaped syntax highlighting.
- `frontend/src/lib/evaluation.ts`: typed display data, result validation and comparability guards.
- `frontend/src/components/charts/EvaluationCharts.tsx`: lazy-loaded real-data outcome/comparison charts.
- `frontend/src/styles/analytics-pages.css`: scoped dark/light, responsive and accessible page styling.
- `frontend/src/lib/analytics.test.ts`: seven focused metadata/source and comparison/result-validation tests.
- `frontend/e2e/analytics.spec.ts`: two real-browser redesign acceptance workflows.
- `frontend/e2e/isolated_api.py`: temporary-storage browser-test fixture only; imports the original unchanged API.
- `frontend/playwright.analytics.config.ts`, `frontend/vite.acceptance.config.ts`: isolated loopback test ports and acceptance-only proxy configuration.

This report is also new. Exact frontend source deltas are listed in `audit_artifacts/ui_redesign_changed_files.json`. Production dependency manifests and the shared application shell remain unchanged.

## Verification

| Check | Result |
|---|---|
| Frontend unit/component tests | **12/12 passed**: seven new tests plus five existing tests |
| TypeScript + Vite production build | **Passed**; final build 9.70 seconds |
| Relevant existing API integration tests | **10/10 passed**, 26.026 seconds; original inference/report modules and temporary cases |
| Chrome acceptance | **5/5 passed**: two new page workflows plus all three existing workflows |
| Protected-file comparison | **124 files, zero changed or missing** across API, modules, Streamlit, models, data/evidence/audits, reports and rule sources |

Browser verification includes actual XGBoost and Isolation Forest evaluations, comparison, matrix selection, exact source preservation, severity/search filters, empty/error states, theme switching, mobile overflow checks, and existing evidence/review/search/report downloads. The demo runs reproduce XGBoost 96.50% and Isolation Forest 68.50% accuracy on that file only; values were returned by the backend, never embedded as application results.

The first browser pass exposed a missing explicit filter label and inherited large-number styles on matrix row labels; both were corrected. Shared acceptance fixtures also invalidated an old test's assumption that its case would always contain one evidence link: the existing store legitimately reuses same-hash evidence. The test now checks its explicitly selected case against the real API count; backend behavior was not changed.

Your existing servers on ports 5173 and 8000 were left running. Acceptance used ports 5174 and 8001, with temporary cases/evidence and an acceptance-only proxy using the API's existing permitted frontend origin. The test servers stop after acceptance. No existing history was used for test writes.

Evidence:

- `audit_artifacts/ui_redesign_browser_results.json`
- `audit_artifacts/ui_redesign_api_tests.txt`
- `audit_artifacts/ui_redesign_integrity.json`
- `audit_artifacts/rules_redesign_dark.png`
- `audit_artifacts/rule_details_redesign.png`
- `audit_artifacts/rules_redesign_mobile_light.png`
- `audit_artifacts/evaluation_redesign_xgboost.png`
- `audit_artifacts/evaluation_redesign_comparison_dark.png`
- `audit_artifacts/evaluation_redesign_comparison_light.png`
- `audit_artifacts/evaluation_redesign_mobile.png`

## Remaining limitations

- Metadata extraction is a display helper, not a YARA compiler or status verifier. Unrecognized files retain source access without invented metadata.
- The unchanged API caps each source file at 100,000 characters and its catalog at 100 files. Current files are complete and below those bounds. Potential source truncation and partial returned catalogs are disclosed; this frontend cannot recover bytes the API does not return.
- Evaluation comparisons remain local to the current mounted case/evidence workspace and reset on refresh/navigation. Independent holdout status is not established by this API. ROC-AUC cannot be derived from the returned flagged-only decisions.
- Chrome desktop and 390-pixel mobile layouts were visually inspected in dark/light themes. This was not a complete assistive-technology audit; dialogs use the existing Radix implementation, matrix cells are native buttons, and the existing reduced-motion preference remains respected.

## Reproduce checks in PowerShell

From the project root, using the existing portable Node runtime:

```powershell
$env:PATH = "$PWD\.tools\node-v24.21.0-win-x64;$env:PATH"
npm.cmd --prefix frontend run test
npm.cmd --prefix frontend run build
npm.cmd --prefix frontend run test:e2e -- --config playwright.analytics.config.ts
.\.venv\Scripts\python.exe -m unittest discover -s tests -p test_web_api.py -v
```

Refresh the running frontend and open `/rules` or `/evaluation` to use the redesigned pages.
