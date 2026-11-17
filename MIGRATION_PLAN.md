# React / FastAPI migration inventory

Baseline: 332/332 existing tests pass (63.592s), 16 November 2026. Original source backup and SHA-256 manifest are in `backups/react_fastapi_migration/`. Existing engine, Streamlit, evidence, datasets, checkpoints and histories stay in place.

| Existing capability | Reused Python implementation | API boundary | React page |
|---|---|---|---|
| Case histories and chain verification | `modules.integrity.EvidenceIntegrity` | cases, audit | Investigations, Audit Integrity |
| Collision-safe evidence storage / source SHA | `evidence_storage`, `integrity` | case-scoped evidence upload/list/verify/preview | Evidence Vault |
| Historical scan association | `scanned_evidence` | scans, scan version selection | Scanner, Investigations |
| File/image/static/YARA checks | `safety_checks.check_uploaded_file`, `yara_scanner` | bounded scan jobs | Security Scanner |
| Network checkpoint inference | `ml_detector`, `model_store`, `csv_evidence`, `ai_reporter.ml_to_report_findings` | bounded ML scan jobs | Scanner, AI Anomaly Detection |
| Rule findings | `rules.RuleEngine`, `yara_scanner` | scan adapters, read-only rule catalog | Threat Rules |
| Search | `semantic_search` | case/evidence/query-scoped search | Investigation Search |
| Timeline | `timeline.TimelineConstructor` | paged resolved/unresolved events | Timeline |
| Pending review | `finding_reviews` | saved-scan/finding review action | Finding cards |
| Deterministic report / validated export | `evidence_reports`, `report_validation`, `pdf_report` | report generation, Markdown/PDF | Forensic Reports |
| Labeled evaluation | `ml_evaluation`, `ml_detector` | explicitly requested evaluation job | Model Evaluation |
| Local Windows monitoring | `background_monitor` | status, recorded alerts, approved-root start/stop | Live Protection |
| Bounded local directory scan | `laptop_scanner.scan_laptop` | server-configured root IDs only | Folder / Local Laptop Scanner |
| URL analysis | `safety_checks.inspect_url` | static URL inspection; no network requests | URL scanner |

Stages: A inspection/baseline/backup; B secure local API + case/evidence tests; C React shell/theme/routes and build; D evidence/scans/investigations/ML/search; E timeline/monitoring/reports/evaluation/audit; F real API integration, UI checks, regression and protected-file comparison. Results will be recorded in `MIGRATION_REPORT.md`.

Trust boundary: single operator on loopback, no multi-user authentication claim. API rejects unapproved origins/hosts and cross-case identifiers; mutations require a per-process token obtained by the allowed local frontend. Server-side root approval is environment configuration, never an arbitrary browser path. No external deployment. No rule editing, uploaded model deserialization, remote laptop scanning or invented image classifier.
