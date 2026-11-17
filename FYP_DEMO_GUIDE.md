# Aegis Forensics — verified FYP demonstration route

Read [the integration audit](INTEGRATION_AUDIT_REPORT.md) before presenting. Core workflows passed; the project has important blocked capabilities. Existing data were preserved.

The [Ollama timeout follow-up](OLLAMA_TIMEOUT_FIX_REPORT.md) subsequently demonstrated bounded local report generation on harmless evidence. Its measurements supplement the original audit; they do not certify unrestricted LLM reliability.

## Startup

From the project root in PowerShell:

```powershell
.\.venv\Scripts\python.exe -m streamlit run dashboard/app.py
```

Use the URL printed by Streamlit. `main.py` is an empty placeholder. Restart Streamlit after code changes so imported modules are refreshed. Keep the tested venv; do not upgrade packages immediately before the demonstration.

For the isolated audit workspace, with fixture evidence and separate histories:

```powershell
.\.venv\Scripts\python.exe -m streamlit run audit_artifacts/integration_20261116_063044/project/dashboard/app.py --server.port=8502
```

The isolated workspace uses its own data/reports directories. It contains a deliberately invalid unrelated case fixture: saved evidence opened in global history scope should block. Explicitly select `CASE-DEMO-VALID` for the positive demonstration. Original `CASE-2026-001` and `TEST-003` fail audit verification and must not be presented as trusted.

## Rehearsed route

1. Open Dashboard and explain that historical alerts are review signals, not active-threat or clean-system verdicts.
2. Security Scanner → File Scan: upload `audit_artifacts/integration_20261116_063044/project/fixtures/harmless_marker.txt`. Scan it. Show the Low harmless YARA marker match and SHA-256. Add to Investigation, explicitly choose a verified case, then confirm. Never use real malware.
3. Investigations → Evidence: open the saved file. Choose an explicit verified case history. In the isolated audit workspace, `CASE-DEMO-VALID` contains two synthetic versions of identical marker bytes: latest is Medium; historical `2026-11-16T01:00:00Z` is Low. Identify these as version-selection test fixtures, not severity measurements of a real attack.
4. Generate the saved-evidence forensic report. Show the same selected scan's findings, timestamp and SHA-256. Download Markdown/PDF. Change the selected scan and demonstrate that the current cached report disappears while archived history remains.
5. Security Scanner → Network CSV: choose a verified case and upload the prepared `network_flows.csv`. Click Analyze network CSV, then Open in Investigations. The random XGBoost checkpoint flagged 15 of these 40 rows in the audit. Show supervised model/checkpoint provenance and source locators. Predictions are not confirmed incidents or calibrated malware confidence.
6. In Investigation choose a different evidence file and upload prepared `events.csv`. Its first column is a numeric record ID, not a timestamp. Timeline orders two UTC-resolved events and separates one unresolved timezone-missing event. The generic event CSV is incompatible with the trained network schema; the visible inference rejection is intentional.
7. Search for `audit event fixture`. Show logical record 2 at physical line 4 and record 1 spanning lines 2–3. Expand Technical Details: this deployment uses explicitly labeled `lexical_heuristic` search. Do not call it verified embedding similarity.
8. Live Protection → Overview: enter a dedicated temporary directory. Start monitoring, create a harmless marker file there, review its saved alert, stop, restart and stop again. Allow a heartbeat interval for counts to update. Do not install a startup task or monitor user directories without an explicit scope.
9. Windows Events: load the read-only preview. Explain available System records and the Security log permission gap. Do not change Windows permissions or Defender settings during the presentation.
10. Optional bounded Laptop Scan: select only a prepared fixture directory, 100 maximum files and a one-minute filesystem limit; confirm that directory before starting. Reports & History → Build local report from scan evidence. Available Windows queries add observations beyond the selected files and can make the report very large. The actual audited export contained 55 findings and 189 PDF pages. Allow substantial rendering time.

## Capabilities to describe accurately

- Deterministic reports and validated Markdown/PDF export: demonstrated.
- Trained XGBoost and Isolation Forest checkpoint inference: demonstrated; only XGBoost was selected interactively, both models/splits ran in backend probes.
- Live local LLM generation: the original browser audit timed out. The follow-up backend tests, using the same `llama3.2` model with 2,048 context tokens and a 320-token output ceiling, produced validated full reports in 35.86, 46.41 and 36.05 seconds. A new interactive browser generation walkthrough was not performed for that follow-up. Treat this as an optional rehearsed step; allow the bounded wait, inspect the actual mode, and do not call hybrid/template fallback a full LLM report. Large prompts deliberately use deterministic reporting rather than silently increasing memory use.
- Sentence Transformer embeddings: **blocked** pending reviewed local checkpoint metadata. No model was downloaded or enabled.
- Full Security log coverage and full endpoint protection: **not demonstrated**. Read-only System polling works; Security log access was denied.
- Original invalid/legacy history: keep visibly untrusted. Never bypass integrity or citation validation to make a demo pass.

Run the full suite before presentation if code changes:

```powershell
.\.venv\Scripts\python.exe -m unittest discover -s tests -v
```

The original integration audit passed 309 tests; the Ollama follow-up suite passed **322 tests**. Do not represent untested elevated, full-disk, remediation or destructive workflows as validated.
