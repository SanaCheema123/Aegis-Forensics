# Aegis Forensics

AI-powered digital forensics and cybercrime investigation console. The React/TypeScript website calls a local FastAPI adapter over the original Python forensic engine. The original Streamlit application remains available and unchanged.

This is a **single-operator local application**, not an authenticated multi-user service. Run both servers on loopback. Do not expose them publicly or use multiple API workers. Evidence, checkpoints and historical audit records are preserved.

## Start on Windows

From the project root:

```powershell
.\.venv\Scripts\python.exe -m pip install -r api/requirements.txt
```

Use an installed Node.js 22.12+ runtime, or enable the portable runtime downloaded and checksum-verified for this workspace:

```powershell
$env:PATH = "$PWD\.tools\node-v24.21.0-win-x64;$env:PATH"
npm.cmd --prefix frontend ci
```

Start the API and frontend in two PowerShell terminals:

```powershell
.\.venv\Scripts\python.exe -m uvicorn api.main:app --reload --host 127.0.0.1 --port 8000
```

```powershell
$env:PATH = "$PWD\.tools\node-v24.21.0-win-x64;$env:PATH"
npm.cmd --prefix frontend run dev
```

- Website: **http://127.0.0.1:5173**
- API documentation: **http://127.0.0.1:8000/docs**
- Health: **http://127.0.0.1:8000/api/v1/health**

Alternatively, `powershell -ExecutionPolicy Bypass -File scripts/start-web.ps1` starts both servers; Ctrl+C stops its API process. Add `-Install` to install declared dependencies first. The script uses a hidden backend process and an interactive frontend terminal. The original Streamlit fallback starts with:

```powershell
.\.venv\Scripts\python.exe -m streamlit run dashboard/app.py
```

## Configure approved local folders

Folder scanning and monitoring accept operator-configured root **IDs**, not arbitrary browser filesystem paths. In the backend terminal, before starting Uvicorn:

```powershell
$env:AEGIS_APPROVED_ROOTS = '{"demo-folder":"C:\\Users\\umair\\Documents\\AegisDemo"}'
```

Create/select the intended harmless local folder yourself. The frontend displays only `demo-folder`. Symlinks and Windows reparse points are rejected. Local folder scans are bounded to 100 files / 30 seconds / 500 findings. Running engine operations cannot be cancelled; queued jobs can. Windows monitoring uses the existing durable agent and its duplicate-process prevention. Start/stop requires an explicit interface action; installation of startup tasks is not exposed.

`frontend/.env.example` documents `VITE_API_BASE_URL`. Default `/api/v1` uses the Vite loopback proxy. `AEGIS_API_PROXY` can change the development proxy target. Do not put credentials or machine-specific paths in frontend source.

## Workflow

1. Select a verified case, or create one in Investigations.
2. Upload original evidence in Security Scanner or Evidence Vault. The existing collision-safe store saves a copy and appends its SHA-256 to the selected case.
3. Select Network CSV for UNSW-NB15 flows; choose XGBoost or Isolation Forest and random/official checkpoint. Only that checkpoint runs. File/Image scan uses existing static checks and YARA; File scan also applies existing event-log rules when the CSV schema supports them.
4. Open Investigations and choose a saved scan version. Review original records, flag a finding for **pending** review, search evidence, or inspect chronology.
5. Generate a deterministic evidence-grounded report and export Markdown/PDF. Export revalidates the evidence, audit chain, scan snapshot and report binding.

The balanced demo CSV should retrieve **40 Generic** lexical search matches. Its duration column is not an absolute timestamp: all **200 event times remain unresolved**. Do not interpret model scores as accuracy or a review flag as a confirmed false positive.

`FINAL-TEST-001` previously verifies; check current status on Audit Integrity. `CASE-2026-001` and `TEST-003` have preserved historical verification failures. Broken histories are blocked, never repaired.

## Test and build

```powershell
.\.venv\Scripts\python.exe -m unittest discover -s tests -v
.\.venv\Scripts\python.exe scripts/verify-migration-integrity.py
$env:PATH = "$PWD\.tools\node-v24.21.0-win-x64;$env:PATH"
npm.cmd --prefix frontend run test
npm.cmd --prefix frontend run build
npm.cmd --prefix frontend run test:e2e
```

Browser tests use installed Google Chrome and automatically start temporary-storage API/Vite servers on ports 8000/5173. Stop development servers first. They use real backend inference and reporting, never the user's historical cases. They do not start the real Windows monitor or a Defender scan.

## Architecture and limits

- `frontend/`: React, TypeScript, Vite, Tailwind, shadcn-style components with Radix primitives, Lucide, Recharts, React Router and TanStack Query. Dark/light themes, responsive navigation, bounded tables, explicit loading/error/empty states.
- `api/`: Pydantic schemas, thin routers, service orchestration, existing forensic module calls, one analysis worker and one waiting slot. Jobs are process-local; completed scan snapshots and review flags persist in the existing audit architecture.
- `modules/`, `dashboard/`: original implementation, unchanged.
- `models/`: original hash-pinned XGBoost/Isolation Forest artifacts; no retraining, replacement or user-uploaded model loading.
- `reports/web_exports/`: new validated web report cache. Old Streamlit report history is retained in place; the web report archive lists reports generated through the web interface.
- Upload/interactive parsing limits: 20 MiB and 10,000 source records. API collections use bounded pages. The evidence selector shows the first 100 items plus an explicitly selected older item. The vault can page through the whole collection. Most generic preview tables display the source locator plus the first 11 data fields; finding technical details retain complete references.
- URL inspection is static and makes no network requests. Image-origin AI, camera attribution, rule editing, remote-device scanning and production authentication are unavailable. LLM generation is not exposed in the new interface; deterministic reports remain available. The existing reporting engine refuses evidence-referenced reports when a scan has no linked findings.

Read [API documentation](API_DOCUMENTATION.md), [migration inventory](MIGRATION_PLAN.md), and [migration acceptance report](MIGRATION_REPORT.md) for boundaries, exact results and remaining verification limits. Screenshots and test logs are in `audit_artifacts/`.
