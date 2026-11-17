# Local API contract

Base URL: `http://127.0.0.1:8000/api/v1`. Interactive OpenAPI: `/docs`; schema: `/openapi.json`.

## Boundary and errors

One local operator, loopback clients only; allowed hosts `127.0.0.1` and `localhost`. CORS permits only the fixed loopback frontend/API origins. This is not user authentication. Every mutation requires `X-Aegis-Token`, obtained from the allowed local `/health` endpoint. Restarting the API rotates the token. The frontend clears its token after HTTP 403; retry the action after restart. Browser-origin checks and a required custom header prevent ordinary cross-site form submissions from starting operations. Do not expose the API or Vite to a LAN/public address.

Validation errors use HTTP 422; unknown/cross-case identifiers use 404; failed integrity/unsupported state use 409; unapproved origins/roots or missing session token use 403; uploads above bounds use 413; a full analysis worker uses 429. Unexpected failures return a generic message, never a stack trace. Structured logs record operation types and job IDs rather than evidence bytes. API JSON redacts the workspace/user/approved-root path prefixes; underlying records and export validation retain original references.

Uploads: multipart field `file`, plain safe basename, nonempty, at most 20 MiB; total request stream is limited to 21 MiB. Filenames with traversal, control characters or Windows device names are rejected. Existing evidence is never overwritten. Uploaded content is never imported or executed. Archives use existing bounded static inspection, without arbitrary extraction. There is no CSV export; Markdown/PDF use existing validated exporters.

## Endpoints

| Method | Path | Behavior |
|---|---|---|
| GET | `/health` | Local API identity, limits, session token |
| GET / POST | `/cases` | List verification status / create case via existing audit append |
| GET | `/dashboard?case_id=…` | Verified-history counts, fresh source hash checks, severity/method/type summaries and recorded activity |
| GET | `/cases/{case}/audit` | Verify selected chain; return paged trusted events only when internally consistent |
| GET / POST | `/cases/{case}/evidence` | Paged filename/type filters and sorting / multipart upload |
| GET | `/cases/{case}/evidence/{id}` | Case-scoped, currently verified evidence identity |
| POST | `/cases/{case}/evidence/{id}/verify` | Verify current bytes against the recorded SHA |
| GET | `/cases/{case}/evidence/{id}/preview` | Bounded escaped source records with independently established CSV locators |
| POST | `/cases/{case}/scans` | Queue file or network analysis; persist new snapshot through `add_scanned_evidence` |
| GET | `/cases/{case}/jobs/{job}` | Status, available progress, result, explicit errors |
| POST | `/cases/{case}/jobs/{job}/cancel` | Cancel only a queued operation |
| GET | `/cases/{case}/evidence/{id}/scans` | Saved scan versions for this source and case |
| GET | `/cases/{case}/evidence/{id}/scans/{scan}/findings` | Paged findings; query/severity/source filters |
| POST | `/cases/{case}/evidence/{id}/scans/{scan}/findings/{finding}/review` | Idempotent pending review in the existing verified audit chain |
| POST | `/cases/{case}/evidence/{id}/search` | Existing lexical/optional reviewed-transformer search, scoped cache and paged matches |
| GET | `/cases/{case}/evidence/{id}/timeline` | Resolved chronology or unresolved source records; explicit timestamp column and timezone-aware start/end filters |
| POST | `/cases/{case}/evaluation` | Explicit labeled evaluation job using original checkpoint and source-aligned metrics |
| GET / POST | `/cases/{case}/reports` | List generated web reports / generate deterministic verified report |
| GET | `/cases/{case}/reports/{report}` | Report preview, validation and limitations |
| GET | `/cases/{case}/reports/{report}/download?format=pdf` | Revalidate and export; `format=md` also supported |
| POST | `/scans/url` | Static URL formatting/host heuristics; no network access or probing |
| POST | `/cases/{case}/scans/folder` | Bounded local file review of an operator-approved root ID |
| POST | `/cases/{case}/scans/system` | Explicit read-only local Windows status/event/startup/process review job; observations are not saved forensic snapshots |
| GET | `/monitoring` | Actual durable-agent status and recorded global alerts, explicitly not case-attributed |
| POST | `/monitoring/start` | Existing Windows agent, approved root IDs only, existing duplicate-process guard |
| POST | `/monitoring/stop` | Existing local agent stop operation |
| GET | `/rules` | Read-only existing local YARA catalog; actual rule content/metadata |
| GET | `/settings` | Real limits, OS support, approved root IDs and unavailable capabilities |

Collections have `{items,total,page,page_size}`. Paginated evidence/findings/preview/timeline/audit routes accept `page_number>=1`, `1<=page_size<=100` (default 25). Evidence filters: `q`, `file_type`, `sort=filename|acquired_at_utc|scan_count`, `descending=true|false`. Timeline accepts `column`, `unresolved`, `start`, `end`. Search accepts `{"query":"Generic"}`; empty or missing text does not invent matches. Returned search `mode` and score meanings distinguish lexical heuristics from embeddings.

Scan/evaluation body:

```json
{"evidence_id":"case-scoped-opaque-id","kind":"network","model":"xgboost","split":"random","threshold":0.5}
```

Models are exactly `xgboost` or `iforest`; splits exactly `random` or `official`. Pydantic rejects unknown fields/nonfinite thresholds. A schema mismatch blocks inference rather than selecting another model. The only checkpoints are the four files pinned by `modules/model_store.py`: `models/xgboost.joblib`, `models/iforest.joblib`, `models/official/xgboost.joblib`, `models/official/iforest.joblib`.

Jobs return HTTP 202 and `{id,case_id,status,phase,progress,result,error,cancellable}`. At most one runs and one waits. Completed scan results contain the saved `scan_id`, canonical `evidence_id`, counts and original provenance. Jobs are lost on API restart; saved audit-bound scans are not. The application must run as one API worker; the original engine's audit lock serializes appends with Streamlit.

Report body: `{"evidence_id":"…","scan_id":"…"}`. Reports require existing evidence-linked findings. Download always rechecks source bytes, snapshot and audit binding; a stale preview cannot authorize export. No arbitrary local file download endpoint exists. Report PDF/Markdown filenames are server-generated UUID-based basenames.

Folder body: `{"root_id":"operator-configured-id"}`. Monitoring body: `{"root_ids":["operator-configured-id"]}`. Server environment `AEGIS_APPROVED_ROOTS` maps IDs to real local directories. The browser cannot establish new roots. Startup-task installation, arbitrary shell commands, model uploads and rule editing are not exposed.
