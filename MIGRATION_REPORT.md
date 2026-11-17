# Aegis Forensics — local React/FastAPI migration acceptance

16 November 2026. This migration adds a working local web application over the existing engine. It does **not** claim production authentication, public hosting, or verification of every live Windows control. The acceptance results below distinguish tested workflows from unavailable or environment-dependent features.

## Architecture and preservation

- New React/TypeScript/Vite frontend, Tailwind CSS, shadcn-style Button/common UI components, accessible Radix Dialog/Tabs, Lucide icons, Recharts, React Router, TanStack Query.
- New FastAPI/Pydantic API: 28 OpenAPI paths, versioned thin routers, service adapters, loopback host/origin/token checks, bounded jobs, validation, pagination and explicit error responses.
- Original `modules/`, Streamlit dashboard, existing tests, data, models and report history remain in place. No original forensic algorithm was rewritten. New cases/uploads/reviews/scans use the original case audit/evidence/scan modules.
- Backup: `backups/react_fastapi_migration/original_source.zip`; protected baseline: `protected_manifest.json`. The manifest covers **142 pre-existing files** in modules/dashboard/tests/data/models/reports. The integrity verifier found **zero changed or missing files**. New files are additive.
- Installed development dependencies into the existing venv; a checksum-verified official portable Node 24.21.0 runtime is in `.tools/`. These are development tooling changes, not checkpoint or evidence changes.

## Feature acceptance

| Feature | Frontend | API | Integration test | Status |
|---|---|---|---|---|
| Local startup / real API communication | Vite frontend builds and serves | FastAPI/Uvicorn starts | Chrome tests launch both loopback servers | Verified |
| Sidebar / routing / theme / mobile | 12 routes, collapsible desktop/sidebar drawer, dark/light preference | Actual settings/case/monitor data | Real navigation, theme persistence, 390px no-overflow check | Verified |
| Dashboard | Real KPIs, severity chart, method summary, linked audit activity | Verified histories only; fresh evidence hash checks | Chrome asserts case counts and rendered chart | Verified; saved scan versions are counted separately |
| Case creation and selection | Dialog and global selector | Existing audit append; reject duplicate/invalid IDs | Real creation, duplicate error, empty-case selection | Verified for local operator |
| Evidence upload / vault | Upload, filters, sorting, paging, details, verification, investigate action | Existing collision-safe copy, SHA, case association, source validation | Upload, collision, traversal/limit rejection, tamper rejection, cross-case 404 | Verified |
| File / image scan | Original file/static check workflow; explicit image limitations | Existing static/YARA engine; image uses same supported checks | Real harmless file scan plus existing YARA regression suite | File path verified; no AI-origin claim |
| Event-log rule findings | Saved finding review | Original RuleEngine runs only for supported CSV schema | Real timestamped failed-login fixture produces brute-force finding | Verified |
| Network CSV / XGBoost | Model/split controls, job status, saved findings/provenance | Exact trusted checkpoint, strict schema, original locators | Real 200-row upload/inference yields 105 flagged rows | Verified |
| Isolation Forest | Separate model selection/evaluation interface | Exact existing selected checkpoint | Real API and Chrome evaluation yields matrix `[[84,16],[47,53]]` | Verified |
| Random / official checkpoint contracts | Both split options exposed | Existing four pinned checkpoint loaders | Original checkpoint/schema/provenance tests retained | Engine verified; browser rehearsal uses random split |
| Scan persistence / historical versions | Saved scan selector | Existing append-only scan snapshot association | Scan → saved evidence → version → finding selection | Verified |
| Finding source review | Record, physical line span, hash/model score, safe table, technical metadata | Source locator from original evidence bytes | Real source-row preview and multiline CSV source tests | Verified; no row inferred for missing locator |
| Flag for review | Explicit pending status; button disabled after success | Existing verified audit notes, full finding/case/scan identity | Duplicate action leaves log bytes unchanged; fresh service reload retains pending status | Verified; no prediction modification |
| Existing structured review notes | Exact prior structured findings recognized | Exact old-note lookup only; no guessed associations | Existing review persistence suite plus new API flow | Retained where exact identity matches; old free-text notes are not backfilled |
| Evidence search | Method badge, loading/error/no-match states, paging, scoped query persistence | Existing lexical / optional reviewed-local-transformer search; scoped cache | Chrome retrieves 40 Generic rows and returns to the tab without losing the query | Verified lexical path; embeddings remain optional |
| Timeline | Explicit column, timezone-aware filters, unresolved view | Original TimelineConstructor | Demo remains 0 resolved / 200 unresolved; reordered multiline fixture has correct times/lines | Verified |
| Approved folder review | Approved ID selector, bounded job/result/coverage display | Existing scan_laptop, 100 files / 30 seconds / 500 findings | Real API and Chrome harmless approved-root scan; reject arbitrary path | Verified |
| Local Windows system observations | Explicit authorize/read-only action | Existing Defender status, event/startup/process review functions | Underlying Windows regression suite; new wrapper is not live-rehearsed | Implemented; live environment verification remains |
| URL analysis | Static URL form and result | Original inspect_url; never makes a network request | Real private-address URL input returns static analysis | Verified; not a reputation/network-probing service |
| Live Protection status / notifications | Actual heartbeat/errors/global recorded alerts | Existing durable background status/history | Chrome/API read actual local status; original monitor/event tests pass | Read path verified |
| Live Protection start / stop | Explicit authorization; approved-root restriction; disabled unavailable states | Existing agent and duplicate-process prevention | Root rejection + existing module tests; real agent not started/stopped by this migration | Implemented; live command rehearsal outstanding |
| YARA catalog / rule metadata | Read-only actual rule source | Existing rule files | Chrome rules page + full original YARA suite | Verified read path; editing unavailable |
| Reports / Markdown / PDF | Verified scan selection, preview, actual browser downloads | Existing grounded deterministic generator and validated exporters | Real Chrome Markdown/PDF; API rejects export after source tampering | Verified for scans with evidence-linked findings |
| LLM report generation | Honest limitation displayed | Not exposed in new API; original Streamlit still supports its existing optional path | Original reporter/LLM reliability suite | New UI deterministic only |
| Model evaluation | Explicit labeled-data opt-in, metrics/matrix/provenance | Existing CSV identity-aligned evaluation | Actual XGBoost/IForest outputs; exact IF confusion counts verified | Verified on selected file only |
| Audit Integrity | Per-case verification, error and trusted-event views | Original verification, no repair endpoint | Tamper/missing/cross-case tests and read-only local checks | FINAL-TEST-001 valid; two historical failures preserved |
| Streamlit coexistence | Original UI available as fallback | No original source modified; same audit lock/persistence modules | All pre-existing tests retained plus file-hash manifest | Source/regressions verified; not a manual dual-app visual rehearsal |

## Tests and build evidence

- Before implementation: **332/332 Python tests passed**, 63.592 seconds (`audit_artifacts/migration_baseline_tests.txt`).
- New focused API acceptance: **10/10 passed**, 14.716 seconds (`migration_api_tests.txt`). This includes original inference/report code and real temporary evidence, not simulated successful responses.
- Complete Python suite: **342/342 passed**, **93.047 seconds** (`audit_artifacts/migration_full_tests.txt`): all 332 pre-existing tests plus 10 new API acceptance tests.
- Frontend components: **5/5 passed** using Vitest/Testing Library; error/loading/empty states, pagination, escaped evidence text and displayed-page numeric sorting.
- Browser acceptance: **3/3 passed**, **39.877 seconds**, zero skipped/unexpected/flaky results. Installed Chrome, actual loopback API, existing checkpoints and temporary case/evidence storage; results in `migration_browser_results.json`. The final desktop capture waits for a rendered Recharts surface.
- Production build: TypeScript and Vite pass. Latest build has approximately **105 KiB gzipped entry**, **23 KiB UI chunk**, **108 KiB lazy chart chunk**, and **6.3 KiB CSS**; routes/charts are split. Exact output is environment-dependent.
- Integrity check: `python scripts/verify-migration-integrity.py` found **142 protected files, zero changed**.
- Historical local check: `FINAL-TEST-001` internally consistent; `CASE-2026-001` and `TEST-003`: **Entry 1 was modified**. No attempt was made to repair them. Internal consistency is not independently anchored authenticity.

Intermediate failures were resolved rather than suppressed: initial network adapter called event-log rules without checking their schema; a one-record negative fixture did not reach feature-schema validation; a short job test deadline was insufficient during concurrent installation; frontend esbuild needed execution outside this environment's restrictive file sandbox. The final tests use valid multirow negative fixtures, explicit rule-schema checks and a bounded 60-second test polling deadline. No engine guard or original test expectation was weakened.

## Created / modified files

The complete exact source list is `audit_artifacts/migration_source_files.json` (**56 new source/config/doc files**):

- API: `api/main.py`, `api/requirements.txt`; versioned routers in `api/routers/`; request/response schemas in `api/schemas/`; identifier/path policy in `api/security/`; forensic adapters and bounded worker in `api/services/`; package initializers.
- Frontend setup: `package.json`, lockfile, `tsconfig.json`, `vite.config.ts`, `index.html`, `.env.example`, `components.json`, `playwright.config.ts`.
- Frontend application: `src/main.tsx`, `src/app/App.tsx`, `context.tsx`, `services/api.ts`, `hooks/useEvidence.ts`, `types/index.ts`, `lib/utils.ts`, `styles/index.css`.
- Frontend components: `layout/Shell.tsx`, `charts/FindingsChart.tsx`, `common/index.tsx`, `ui/button.tsx`, `investigations/EvidenceSelect.tsx`, `scanner/JobPanel.tsx`.
- Pages: `Dashboard.tsx`, `Scanner.tsx`, `Investigations.tsx`, `EvidenceVault.tsx`, `Timeline.tsx`, `Reports.tsx`, `Evaluation.tsx`, `Audit.tsx`, `Monitoring.tsx`, `Rules.tsx`, `Settings.tsx`. AI Anomaly Detection reuses the investigation finding UI with server-side ML source filtering.
- Tests: `tests/test_web_api.py`, `frontend/src/test-setup.ts`, `frontend/src/components/common/common.test.tsx`, `frontend/e2e/workflows.spec.ts`.
- Scripts: `scripts/start-web.ps1`, `acceptance_server.py`, `verify-migration-integrity.py`.
- Docs/config: `README.md`, `API_DOCUMENTATION.md`, `MIGRATION_PLAN.md`, this report and `.gitignore`.

**Existing project source files modified: none.** Original `requirements.txt` is unchanged; additive `api/requirements.txt` declares API dependencies. Runtime installation changed the development venv; downloaded tooling and build outputs are ignored.

Generated artifacts include the protected source ZIP/manifest, test logs, OpenAPI JSON, exact new source list, browser result JSON and desktop/mobile screenshots. New web-generated report caches use `reports/web_exports/`; original report history is not rewritten. Acceptance case data is created in temporary directories and does not become a historical user case.

## Remaining limitations / unresolved verification

1. **Not all final acceptance claims are asserted as complete.** Core evidence/investigation/report workflows pass real browser acceptance. Live Windows monitor mutation and system-observation wrapper rehearsal remain outstanding; no production/multi-user authentication is implemented or claimed.
2. Do not expose this local application publicly. There is no user identity/authorization database. Case isolation means strict request context in a single trusted operator workspace, not multi-user tenant isolation.
3. Jobs are in-process, one running plus one waiting. They are lost on restart. Saved scans and review notes persist. Running cancellation is unavailable in the underlying bounded engine; only queued cancellation is offered. The full query/model operations are bounded by size/record/concurrency controls; a separate hard-kill worker for every operation was not introduced.
4. Folder and system reviews produce current job observations, not automatically saved forensic scan snapshots. Use evidence uploads/scans for exportable evidence-linked reports. Local monitor alerts are global agent observations and explicitly not current-case findings. The new interface does not implement monitor-alert promotion or startup-task administration; the original Streamlit workflow remains available for those operations.
5. Reports require evidence-linked findings. The original engine refuses an evidence-referenced report for an empty finding set; the new UI disables that control and explains the reason. LLM generation is not exposed in the new interface. Old Streamlit report history remains in place and is not shown as newly generated web reports.
6. Existing structured Streamlit review notes are recognized only when their complete finding identity matches; legacy free-text notes are preserved without guessing their scan identity. New web review notes include explicit scan identity. Streamlit's existing badge logic may not display newly web-scoped notes; the shared audit trail still contains them unchanged. No historical note migration was attempted.
7. Search embeddings depend on existing reviewed local artifacts. The accepted path is lexical fallback, explicitly labeled. `Generic` has 40 matches; protocol/category text alone does not establish “unauthorized access.” Search cache is scoped by original content/query/case/evidence and limited to eight preparations.
8. No image-origin AI, camera attribution, arbitrary rule editing, uploaded model loading, remote-client laptop scan, CSV export, or reputation feed is falsely exposed. Static image checks and static URL heuristics are the implemented capabilities. No ROC-AUC is fabricated from a flagged-only inference frame; current file evaluation shows the supported binary metrics. Existing stored checkpoint evaluation remains available in Streamlit.
9. Interactive upload/parsing is limited to 20 MiB/10,000 records. Generic tables show bounded fields/rows with technical details; sorting such tables affects the displayed page. Vault filters/sorting run server-side. Case/scan/report selectors are bounded to the currently implemented 100-entry view; very large case/scan/report catalogs would need additional selector pagination. The evidence vault itself is fully paged and preserves explicitly selected older evidence.
10. Desktop and mobile screenshots use an explicitly named temporary acceptance case and real test responses. Chrome UI acceptance ran; tablet widths and full keyboard/screen-reader accessibility were not manually audited. Radix handles dialog/tab semantics and the interface respects reduced-motion settings.
11. Historical broken chains remain blocked. Do not claim they verify. No Git executable was available; isolation used an additive tree, source ZIP and hash manifest instead of a branch.

## Startup and demo instructions

See `README.md` for complete PowerShell install/test commands. Start from the project root:

```powershell
powershell -ExecutionPolicy Bypass -File scripts/start-web.ps1
```

Or in separate terminals:

```powershell
.\.venv\Scripts\python.exe -m uvicorn api.main:app --reload --host 127.0.0.1 --port 8000
```

```powershell
$env:PATH = "$PWD\.tools\node-v24.21.0-win-x64;$env:PATH"
npm.cmd --prefix frontend run dev
```

Open **http://127.0.0.1:5173**. Select `FINAL-TEST-001` to inspect existing verified history, or create a new demonstration case to keep new actions separate. Upload `data/training/UNSW_NB15_demo_balanced.csv`, select Network CSV/XGBoost/random, run analysis, then open Investigations. Review a saved finding, flag it pending, search `Generic`, and show the unresolved timeline. Verify the case, generate a report with findings and download Markdown/PDF. Model Evaluation is a separate explicitly labeled-data action; Isolation Forest should reproduce the demo confusion counts, not imply deployment accuracy.

For monitoring/folder demonstrations, first configure an approved harmless local root and rehearse with the operator present. Do not present live start/stop as acceptance-verified by this report. The original Streamlit fallback remains `python -m streamlit run dashboard/app.py`.
