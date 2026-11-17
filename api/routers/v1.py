from fastapi import APIRouter, Request, Query, UploadFile, File, Response
from typing import Literal

from api.schemas import CaseCreate, ScanRequest, SearchRequest, ReportRequest, RootRequest, MonitorRequest, UrlRequest, Collection, JobView
from api.security.policy import ServiceError
from api.services.forensics import page
from modules.integrity import EvidenceIntegrity
from modules.scanned_evidence import scan_record_id

router = APIRouter(prefix="/api/v1")


def svc(request):
    return request.app.state.service


@router.get('/health')
def health(request: Request) -> dict:
    return dict(status="ok", app="Aegis Forensics", boundary="local single operator", csrf_token=request.app.state.token,
        max_upload_bytes=20*1024*1024, concurrency=1)


@router.get('/cases', response_model=Collection)
def cases(request: Request) -> dict:
    return page(svc(request).cases(), 1, 100)


@router.post('/cases', status_code=201)
def create_case(body: CaseCreate, request: Request) -> dict:
    return svc(request).create_case(body.case_id, body.description)


@router.get('/dashboard')
def dashboard(request: Request, case_id: str | None = None) -> dict:
    return svc(request).dashboard(case_id)


@router.get('/cases/{case_id}/audit')
def audit(case_id: str, request: Request, page_number: int = Query(1, ge=1), page_size: int = Query(25, ge=1, le=100)) -> dict:
    service = svc(request)
    valid, message = EvidenceIntegrity.verify_audit_trail(case_id, service.audit_path(case_id))
    # Broken entries are not returned as trusted case data.
    entries = service.entries(case_id) if valid else []
    return dict(case_id=case_id, verified=valid, message=message, **page(list(reversed(entries)), page_number, page_size))


@router.get('/cases/{case_id}/evidence', response_model=Collection)
def evidence(case_id: str, request: Request, q: str = '', file_type: str = '', sort: Literal['filename','acquired_at_utc','scan_count'] = 'acquired_at_utc',
             descending: bool = True, page_number: int = Query(1, ge=1),
             page_size: int = Query(25, ge=1, le=100)) -> dict:
    items = svc(request).evidence(case_id)
    items = [item for item in items if q.casefold() in item['filename'].casefold() and (not file_type or item['type'] == file_type)]
    return page(sorted(items, key=lambda item: item[sort], reverse=descending), page_number, page_size)


@router.post('/cases/{case_id}/evidence', status_code=201)
async def upload(case_id: str, request: Request, file: UploadFile = File(...)) -> dict:
    service = svc(request)
    service.entries(case_id)
    from api.security.policy import safe_filename
    safe_filename(file.filename or '')
    data = bytearray()
    try:
        while block := await file.read(1024*1024):
            data.extend(block)
            if len(data) > 20*1024*1024:
                raise ServiceError("Uploads are limited to 20 MiB.", 413)
        from starlette.concurrency import run_in_threadpool
        return await run_in_threadpool(service.upload, case_id, file.filename, bytes(data))
    finally:
        await file.close()


@router.post('/cases/{case_id}/evidence/{evidence_id}/verify')
def verify(case_id: str, evidence_id: str, request: Request) -> dict:
    item, _ = svc(request).source(case_id, evidence_id)
    return dict(verified=True, sha256=item['sha256'], case_id=case_id, evidence_id=evidence_id)


@router.get('/cases/{case_id}/evidence/{evidence_id}')
def evidence_detail(case_id: str, evidence_id: str, request: Request) -> dict:
    return svc(request).source(case_id, evidence_id)[0]


@router.get('/cases/{case_id}/evidence/{evidence_id}/preview')
def preview(case_id: str, evidence_id: str, request: Request, page_number: int = Query(1, ge=1),
            page_size: int = Query(25, ge=1, le=100)) -> dict:
    return svc(request).preview(case_id, evidence_id, page_number, page_size)


@router.post('/cases/{case_id}/scans', response_model=JobView, status_code=202)
def scan(case_id: str, body: ScanRequest, request: Request) -> dict:
    service = svc(request)
    service.source(case_id, body.evidence_id)
    return request.app.state.jobs.submit(case_id, lambda progress: service.scan(case_id, body, progress))


@router.get('/cases/{case_id}/jobs/{job_id}', response_model=JobView)
def job(case_id: str, job_id: str, request: Request) -> dict:
    svc(request).entries(case_id)
    return request.app.state.jobs.get(case_id, job_id)


@router.post('/cases/{case_id}/jobs/{job_id}/cancel', response_model=JobView)
def cancel_job(case_id: str, job_id: str, request: Request) -> dict:
    svc(request).entries(case_id)
    return request.app.state.jobs.cancel(case_id, job_id)


@router.get('/cases/{case_id}/evidence/{evidence_id}/scans', response_model=Collection)
def scans(case_id: str, evidence_id: str, request: Request) -> dict:
    records = svc(request).scans(case_id, evidence_id)
    return page([dict(scan_id=scan_record_id(r), case_id=case_id, scanned_at_utc=r['scanned_at_utc'],
        finding_count=len(r['findings']), models=sorted({f.get('model_name', 'rule') for f in r['findings']})) for r in records], 1, 100)


@router.get('/cases/{case_id}/evidence/{evidence_id}/scans/{scan_id}/findings', response_model=Collection)
def findings(case_id: str, evidence_id: str, scan_id: str, request: Request, q: str = '', severity: str = '', source: str = '',
             page_number: int = Query(1, ge=1), page_size: int = Query(25, ge=1, le=100)) -> dict:
    rows = svc(request).findings(case_id, evidence_id, scan_id)
    rows = [r for r in rows if (not severity or r.get('severity') == severity) and (not source or r.get('source') == source) and q.casefold() in str(r).casefold()]
    return page(rows, page_number, page_size)


@router.post('/cases/{case_id}/evidence/{evidence_id}/scans/{scan_id}/findings/{finding_id}/review')
def review(case_id: str, evidence_id: str, scan_id: str, finding_id: str, request: Request) -> dict:
    return svc(request).review(case_id, evidence_id, scan_id, finding_id)


@router.post('/cases/{case_id}/evidence/{evidence_id}/search')
def search(case_id: str, evidence_id: str, body: SearchRequest, request: Request,
           page_number: int = Query(1, ge=1), page_size: int = Query(25, ge=1, le=100)) -> dict:
    result = svc(request).search(case_id, evidence_id, body.query)
    return {**{k: v for k, v in result.items() if k != 'matches'}, **page(result['matches'], page_number, page_size)}


@router.get('/cases/{case_id}/evidence/{evidence_id}/timeline')
def timeline(case_id: str, evidence_id: str, request: Request, column: str | None = None,
             unresolved: bool = False, start: str | None = None, end: str | None = None,
             page_number: int = Query(1, ge=1), page_size: int = Query(25, ge=1, le=100)) -> dict:
    result = svc(request).timeline(case_id, evidence_id, column)
    resolved_count, unresolved_count = len(result['resolved']), len(result['unresolved'])
    rows = result['unresolved'] if unresolved else result['resolved']
    if start or end:
        from modules.event_timestamps import parse_timestamp
        bounds = [parse_timestamp(value) if value else None for value in (start, end)]
        if any(value and value.utc is None for value in bounds):
            raise ServiceError("Time filters require ISO timestamps with an explicit timezone.", 422)
        rows = [row for row in rows if (stamp := parse_timestamp(row.get('aegis_timestamp_utc'))).utc is not None
                and (not bounds[0] or stamp.utc >= bounds[0].utc) and (not bounds[1] or stamp.utc <= bounds[1].utc)]
    return dict(status=result['status'], column=result['column'], resolved_count=resolved_count,
                unresolved_count=unresolved_count, **page(rows, page_number, page_size))


@router.post('/cases/{case_id}/evaluation', response_model=JobView, status_code=202)
def evaluation(case_id: str, body: ScanRequest, request: Request) -> dict:
    service = svc(request)
    service.source(case_id, body.evidence_id)
    return request.app.state.jobs.submit(case_id, lambda progress: service.evaluate(case_id, body, progress))


@router.get('/cases/{case_id}/reports', response_model=Collection)
def reports(case_id: str, request: Request) -> dict:
    return page(svc(request).reports(case_id), 1, 100)


@router.post('/cases/{case_id}/reports', status_code=201)
def generate_report(case_id: str, body: ReportRequest, request: Request) -> dict:
    return svc(request).report(case_id, body.evidence_id, body.scan_id)


@router.get('/cases/{case_id}/reports/{report_id}')
def report_preview(case_id: str, report_id: str, request: Request) -> dict:
    record = svc(request).report_record(case_id, report_id)
    return {key: record.get(key) for key in ('text', 'validation', 'mode', 'case_id', 'generated_at_utc', 'limitations')}


@router.get('/cases/{case_id}/reports/{report_id}/download')
def download(case_id: str, report_id: str, request: Request, format: Literal['md', 'pdf'] = 'md') -> Response:
    from modules.report_validation import render_forensic_text
    from modules.pdf_report import render_forensic_pdf
    record = svc(request).report_record(case_id, report_id)
    # Existing exporter revalidates source bytes, chain, snapshot and report text.
    context = dict(expected_case_id=case_id, expected_sha256=record['sha256'])
    if format == 'pdf':
        data, mime = render_forensic_pdf(record, **context), 'application/pdf'
    else:
        data, mime = render_forensic_text(record, **context).encode('utf-8'), 'text/markdown; charset=utf-8'
    return Response(data, media_type=mime, headers={'Content-Disposition': f'attachment; filename="aegis-{report_id}.{format}"', 'X-Content-Type-Options': 'nosniff'})


@router.post('/scans/url')
def url_inspection(body: UrlRequest) -> dict:
    from modules.safety_checks import inspect_url
    return dict(inspect_url(body.url), method="Static URL indicators only; no network request is made.")


@router.get('/settings')
def settings(request: Request) -> dict:
    import os
    from modules.yara_scanner import YARA_AVAILABLE
    return dict(trust_boundary="Loopback, single local operator; no multi-user authentication", yara_available=YARA_AVAILABLE,
        roots=[dict(id=key, label=key) for key in svc(request).approved_roots],
        windows_monitoring=os.name == 'nt', max_upload_mib=20, max_records=10000,
        running_cancellation=False, rule_editing=False, image_ai_detection=False,
        models=[dict(model=model, splits=['random', 'official']) for model in ('xgboost', 'iforest')])


@router.post('/cases/{case_id}/scans/folder', response_model=JobView, status_code=202)
def folder_scan(case_id: str, body: RootRequest, request: Request) -> dict:
    service = svc(request)
    service.entries(case_id)
    service.approved_root(body.root_id)
    return request.app.state.jobs.submit(case_id, lambda progress: service.folder_scan(case_id, body.root_id, progress))


@router.get('/monitoring')
def monitoring() -> dict:
    from modules.background_monitor import get_background_status, load_background_alerts
    status = get_background_status()
    return dict(status={key: status.get(key) for key in ('state', 'running', 'pid', 'heartbeat_utc', 'health', 'error')},
                alerts=load_background_alerts(50), scope="Local backend observations; monitor alerts are not case-attributed unless explicitly promoted.")


@router.post('/cases/{case_id}/scans/system', response_model=JobView, status_code=202)
def system_review(case_id: str, request: Request) -> dict:
    service = svc(request)
    service.entries(case_id)
    return request.app.state.jobs.submit(case_id, lambda progress: service.system_review(case_id, progress))


@router.post('/monitoring/start')
def start_monitor(body: MonitorRequest, request: Request) -> dict:
    from modules.background_monitor import start_background_monitor
    return start_background_monitor([svc(request).approved_root(key) for key in body.root_ids])


@router.post('/monitoring/stop')
def stop_monitor() -> dict:
    from modules.background_monitor import stop_background_monitor
    return stop_background_monitor()


@router.get('/rules', response_model=Collection)
def rules(request: Request) -> dict:
    from modules.yara_scanner import DEFAULT_RULES_DIR
    rules = [dict(name=path.name, category='YARA', content=path.read_text(encoding='utf-8', errors='replace')[:100000])
             for path in sorted(DEFAULT_RULES_DIR.glob('*.yar*')) if path.is_file() and not path.is_symlink()]
    return page(rules, 1, 100)
