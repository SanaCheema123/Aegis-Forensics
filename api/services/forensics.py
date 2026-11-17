from collections import Counter, OrderedDict
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
from threading import RLock
from uuid import uuid4

from api.security.policy import ServiceError, case_identifier, safe_filename, unlinked_path
from modules.integrity import EvidenceIntegrity
from modules.evidence_storage import save_evidence_copy
from modules.scanned_evidence import add_scanned_evidence, load_scanned_evidence_records, scan_record_id, select_saved_scan


def now():
    return datetime.now(timezone.utc).isoformat()


def page(items, number=1, size=25):
    return dict(items=items[(number-1)*size:number*size], total=len(items), page=number, page_size=size)


class ForensicsService:
    def __init__(self, root, approved_roots=None):
        self.root = Path(root).resolve()
        self.cases_dir = self.root / "data/cases"
        self.raw = self.root / "data/raw_evidence"
        self.report_dir = self.root / "reports/web_exports"
        self.approved_roots = {key: Path(value).resolve() for key, value in (approved_roots or {}).items()}
        self.lock = RLock()
        self.search_cache = OrderedDict()
        self._scanner = None

    def audit_path(self, case_id):
        return unlinked_path(self.cases_dir / f"{case_identifier(case_id)}_audit.log", self.cases_dir)

    def entries(self, case_id):
        try:
            return EvidenceIntegrity.read_verified_audit(case_id, self.audit_path(case_id))
        except (ValueError, OSError) as exc:
            # Verification messages contain no evidence content; retain supported cause.
            message = str(exc).replace(str(self.root), "[local workspace]")
            raise ServiceError(f"Case verification failed: {message}", 409) from exc

    def cases(self):
        result = []
        for path in sorted(self.cases_dir.glob("*_audit.log")):
            case = path.name.removesuffix("_audit.log")
            valid, message = EvidenceIntegrity.verify_audit_trail(case, path)
            count = len(self.entries(case)) if valid else None
            result.append(dict(case_id=case, verified=valid, message=message, audit_events=count))
        return result

    def create_case(self, case_id, description):
        path = self.audit_path(case_id)
        with self.lock:
            if path.exists():
                raise ServiceError("This case already exists.", 409)
            EvidenceIntegrity.log_audit_trail(case_id, "CASE_CREATED", description or "Case created through local web interface.", audit_path=path)
        return dict(case_id=case_id, verified=True)

    @staticmethod
    def evidence_key(filename, digest):
        return hashlib.sha256((filename + "\0" + digest).encode()).hexdigest()[:32]

    def evidence(self, case_id):
        entries = self.entries(case_id)
        items = {}
        scans = load_scanned_evidence_records(self.cases_dir, case_ids=[case_id])
        for entry in entries:
            if entry.get("action") != "EVIDENCE_UPLOAD":
                continue
            match = re.fullmatch(r"File uploaded: (.+) \| SHA256: ([a-fA-F0-9]{64})", entry.get("details", ""))
            if not match:
                continue
            name, digest = match.group(1), match.group(2).lower()
            try:
                safe_filename(name)
            except ServiceError:
                continue
            key = self.evidence_key(name, digest)
            linked = [r for r in scans if r['sha256'] == digest and r.get('stored_filename') == name]
            items.setdefault(key, dict(id=key, filename=name, sha256=digest, case_id=case_id,
                type=Path(name).suffix.lower(), acquired_at_utc=entry.get("timestamp"),
                scan_count=len(linked), finding_count=sum(len(r['findings']) for r in linked)))
        return list(items.values())

    def source(self, case_id, evidence_id):
        item = next((item for item in self.evidence(case_id) if item['id'] == evidence_id), None)
        if item is None:
            raise ServiceError("Evidence not found in this case.", 404)
        path = unlinked_path(self.raw / item['filename'], self.raw)
        if not path.is_file():
            raise ServiceError("Recorded source file is unavailable.", 409)
        try:
            EvidenceIntegrity.require_evidence(case_id, path, audit_path=self.audit_path(case_id), expected_hash=item['sha256'])
        except ValueError as exc:
            raise ServiceError("Evidence bytes do not match the verified case record.", 409) from exc
        return item, path

    def upload(self, case_id, filename, data):
        self.entries(case_id)
        filename = safe_filename(filename)
        if not data:
            raise ServiceError("The evidence file is empty.", 422)
        with self.lock:
            unlinked_path(self.raw, self.root)
            path = save_evidence_copy(self.raw, filename, data)
            digest = EvidenceIntegrity.calculate_sha256(path)
            EvidenceIntegrity.log_audit_trail(case_id, "EVIDENCE_UPLOAD",
                f"File uploaded: {path.name} | SHA256: {digest}", audit_path=self.audit_path(case_id))
        return next(item for item in self.evidence(case_id) if item['id'] == self.evidence_key(path.name, digest))

    def frame(self, case_id, evidence_id):
        from modules.parser import LogParser
        item, path = self.source(case_id, evidence_id)
        if path.stat().st_size > 20 * 1024 * 1024:
            raise ServiceError("Interactive parsing is limited to 20 MiB.", 413)
        if path.suffix.lower() not in {".csv", ".json", ".txt", ".log"}:
            raise ServiceError("This evidence type does not support text records.", 422)
        frame = LogParser(str(path)).parse_logs()
        from modules.csv_evidence import CSV_METADATA
        if CSV_METADATA in frame.attrs and frame.attrs[CSV_METADATA]['sha256'] != item['sha256']:
            raise ServiceError("Evidence changed during parsing; analysis was blocked.", 409)
        self.source(case_id, evidence_id)
        if len(frame) > 10000:
            raise ServiceError("Interactive analysis supports at most 10,000 records; use a smaller evidence export.", 413)
        return item, path, frame

    def preview(self, case_id, evidence_id, number=1, size=25):
        from modules.csv_evidence import source_locator
        item, _, frame = self.frame(case_id, evidence_id)
        start = (number-1)*size
        rows = json.loads(frame.iloc[start:start+size].to_json(orient="records", date_format="iso"))
        for position, row in enumerate(rows, start):
            row['_source'] = source_locator(frame, frame.index[position], filename=item['filename'], sha256=item['sha256'], position=position)
        return dict(items=rows, total=len(frame), page=number, page_size=size, columns=list(frame.columns))

    def scanner(self):
        from modules.yara_scanner import YaraScanner
        if self._scanner is None:
            self._scanner = YaraScanner()
        return self._scanner

    def scan(self, case_id, options, progress):
        from modules.ai_reporter import ml_to_report_findings, yara_to_report_findings
        from modules.safety_checks import check_uploaded_file
        item, path = self.source(case_id, options.evidence_id)
        provenance = None
        if options.kind == "network":
            from modules.ml_detector import MLAnomalyDetector
            from modules.model_store import ModelReliabilityError
            from modules.rules import RuleEngine
            item, path, frame = self.frame(case_id, options.evidence_id)
            if path.suffix.lower() != '.csv':
                raise ServiceError("Network inference requires CSV evidence.", 422)
            detector = MLAnomalyDetector(frame, model=options.model, split=options.split,
                threshold=options.threshold, evidence_sha256=item['sha256'])
            try:
                anomalies = detector.detect_anomalies()
            except ModelReliabilityError as exc:
                raise ServiceError(str(exc).replace(str(self.root), '[local workspace]'), 422) from exc
            if detector.last_mode != f'trained_{options.model}':
                raise ServiceError("Insufficient records for the selected checkpoint; no inference or alternate model ran.", 422)
            provenance = detector.last_provenance
            findings = ml_to_report_findings(anomalies, frame, detector.last_mode, options.split, item['filename'], item['sha256'])
            rules_supported, missing = RuleEngine.can_run(frame)
            if rules_supported:
                findings += RuleEngine(frame, source_file=item['filename']).run()
            input_records = len(frame)
            flagged = len(anomalies)
            warnings = [] if rules_supported else ["Event-log rules unavailable: required fields are absent: " + ', '.join(missing)]
        else:
            analysis = check_uploaded_file(item['filename'], path.read_bytes(), self.scanner())
            # Preserve static findings as supplied, with distinct IDs if necessary.
            from modules.evidence_reports import merge_investigation_findings
            findings = merge_investigation_findings(yara_to_report_findings(analysis.get('findings', [])), analysis.get('heuristic_findings', []))
            input_records, flagged = None, None
            warnings = analysis.get('scan_warnings', [])
            if path.suffix.lower() == '.csv':
                from modules.rules import RuleEngine
                _, _, frame = self.frame(case_id, options.evidence_id)
                supported, missing = RuleEngine.can_run(frame)
                if supported:
                    findings = merge_investigation_findings(findings, RuleEngine(frame, source_file=item['filename']).run())
                else:
                    warnings.append('Event-log rules unavailable: required fields are absent: ' + ', '.join(missing))
        evidence_bytes = path.read_bytes()
        if hashlib.sha256(evidence_bytes).hexdigest() != item['sha256']:
            raise ServiceError("Evidence changed during analysis; no scan snapshot was saved.", 409)
        self.source(case_id, options.evidence_id)  # Re-check case/bytes before committing snapshot.
        record = add_scanned_evidence(self.raw, item['filename'], evidence_bytes, findings,
            case_id=case_id, scanned_at_utc=now(), audit_log_path=self.audit_path(case_id),
            audit_logger=lambda c, a, d: EvidenceIntegrity.log_audit_trail(c, a, d, audit_path=self.audit_path(c)))
        canonical_id = self.evidence_key(record['stored_filename'], record['sha256'])
        return dict(scan_id=scan_record_id(record), evidence_id=canonical_id, input_records=input_records,
            flagged_records=flagged, finding_count=len(findings), provenance=provenance, warnings=warnings,
            yara_available=self.scanner().ready, yara_scan_performed=options.kind == 'file' and self.scanner().ready)

    def scans(self, case_id, evidence_id):
        item, path = self.source(case_id, evidence_id)
        return [r for r in load_scanned_evidence_records(self.cases_dir, item['sha256'], case_ids=[case_id])
                if r.get('stored_filename') == path.name]

    def scan_record(self, case_id, evidence_id, scan_id):
        item, path = self.source(case_id, evidence_id)
        try:
            record = select_saved_scan(self.cases_dir, item['sha256'], case_ids=[case_id], scan_id=scan_id, source_path=path)
        except ValueError as exc:
            raise ServiceError("Saved scan is unavailable in this case/evidence context.", 404) from exc
        if record is None:
            raise ServiceError("No saved scan is available.", 404)
        return record

    def findings(self, case_id, evidence_id, scan_id):
        from modules.evidence_reports import saved_evidence_findings
        from modules.finding_reviews import review_status
        record = self.scan_record(case_id, evidence_id, scan_id)
        output = []
        for finding in saved_evidence_findings(record):
            scoped = {**finding, 'scan_id': scan_record_id(record), 'case_id': case_id}
            pending = review_status(scoped, case_id, audit_path=self.audit_path(case_id))
            if pending is None:
                # Honor an exact structured Streamlit note, without guessing an
                # old free-text note's case/evidence/scan associations.
                pending = review_status(finding, case_id, audit_path=self.audit_path(case_id))
            output.append({**scoped, 'review_pending': pending is not None})
        return output

    def review(self, case_id, evidence_id, scan_id, finding_id):
        from modules.finding_reviews import mark_for_review
        finding = next((f for f in self.findings(case_id, evidence_id, scan_id) if f['id'] == finding_id), None)
        if finding is None:
            raise ServiceError("Finding not found in this saved scan.", 404)
        finding.pop('review_pending', None)
        entry = mark_for_review(finding, case_id, audit_path=self.audit_path(case_id))
        return dict(status="pending_false_positive_review", timestamp=entry['timestamp'], predictions_changed=False)

    def search(self, case_id, evidence_id, query):
        from modules.semantic_search import prepare_evidence_search, search_evidence
        item, _, frame = self.frame(case_id, evidence_id)
        prepared = prepare_evidence_search(frame, sha256=item['sha256'], case_id=case_id, query=query, filename=item['filename'])
        with self.lock:
            if prepared['key'] in self.search_cache:
                return self.search_cache[prepared['key']]
        result = search_evidence(prepared)
        result['status'] = 'no_searchable_data' if not prepared['records'] else ('success' if result['matches'] else 'no_match')
        with self.lock:
            self.search_cache[prepared['key']] = result
            while len(self.search_cache) > 8:
                self.search_cache.popitem(last=False)
        return result

    def timeline(self, case_id, evidence_id, column=None):
        from modules.timeline import TimelineConstructor
        _, _, frame = self.frame(case_id, evidence_id)
        builder = TimelineConstructor(frame)
        resolved = builder.build_timeline(column)
        return dict(column=builder.selection.get('column'), status=builder.selection['status'],
            resolved=json.loads(resolved.to_json(orient='records', date_format='iso')),
            unresolved=json.loads(builder.unresolved_events.to_json(orient='records', date_format='iso')))

    def evaluate(self, case_id, options, progress):
        from modules.ml_detector import MLAnomalyDetector
        from modules.ml_evaluation import evaluate_labeled_csv
        item, _, frame = self.frame(case_id, options.evidence_id)
        detector = MLAnomalyDetector(frame, model=options.model, split=options.split, threshold=options.threshold,
            evidence_sha256=item['sha256'])
        anomalies = detector.detect_anomalies()
        return dict(evaluate_labeled_csv(frame, anomalies), dataset=item, model=options.model, split=options.split,
            provenance=detector.last_provenance, limitation="This labeled file only; not independent holdout or deployment performance.")

    def report(self, case_id, evidence_id, scan_id):
        from modules.evidence_reports import build_saved_evidence_report
        record = self.scan_record(case_id, evidence_id, scan_id)
        _, path = self.source(case_id, evidence_id)
        report = build_saved_evidence_report(record, evidence_id, path, audit_path=self.audit_path(case_id))
        report_id = str(uuid4())
        self.report_dir.mkdir(parents=True, exist_ok=True)
        (self.report_dir / f'{report_id}.json').write_text(json.dumps(report, default=str), encoding='utf-8')
        return dict(id=report_id, case_id=case_id, evidence_id=evidence_id, scan_id=scan_id,
            text=report['text'], generated_at_utc=report['generated_at_utc'], mode=report['mode'], validation=report['validation'])

    def report_record(self, case_id, report_id):
        if not re.fullmatch(r'[0-9a-f-]{36}', report_id):
            raise ServiceError("Report not found.", 404)
        self.entries(case_id)
        path = unlinked_path(self.report_dir / f'{report_id}.json', self.report_dir)
        if not path.is_file():
            raise ServiceError("Report not found.", 404)
        report = json.loads(path.read_text(encoding='utf-8'))
        if report.get('case_id') != case_id:
            raise ServiceError("Report not found in this case.", 404)
        return report

    def reports(self, case_id):
        self.entries(case_id)
        records = []
        for path in sorted(self.report_dir.glob('*.json'), key=lambda p: p.stat().st_mtime, reverse=True):
            record = json.loads(path.read_text(encoding='utf-8'))
            if record.get('case_id') == case_id:
                records.append(dict(id=path.stem, case_id=case_id, filename=record['filename'], scan_id=record['scan_id'], generated_at_utc=record['generated_at_utc']))
        return records

    def approved_root(self, root_id):
        if root_id not in self.approved_roots:
            raise ServiceError("This local folder is not approved by the backend operator.", 403)
        root = self.approved_roots[root_id]
        unlinked_path(root, root)
        if not root.is_dir():
            raise ServiceError("The approved local folder is unavailable.", 409)
        return root

    def folder_scan(self, case_id, root_id, progress):
        from modules.laptop_scanner import scan_laptop
        self.entries(case_id)
        result = scan_laptop(self.approved_root(root_id), self.scanner(), progress_callback=progress,
            max_files=100, max_seconds=30, max_findings=500)
        return result

    def system_review(self, case_id, progress):
        from modules.windows_security import get_defender_status, read_security_events, inspect_startup_items, inspect_running_processes
        self.entries(case_id)
        result = dict(scope='Read-only observations of the local backend Windows machine; not visitor-device scanning.',
                      observed_at_utc=now(), observations={}, errors=[])
        for name, operation in [('defender', get_defender_status), ('security_events', lambda: read_security_events(days=1)),
                                ('startup', inspect_startup_items), ('processes', inspect_running_processes)]:
            try:
                result['observations'][name] = operation()
            except (OSError, ValueError, RuntimeError) as exc:
                result['errors'].append(dict(source=name, error='Local observation unavailable: ' + type(exc).__name__))
        return result

    def dashboard(self, case_id=None):
        cases = self.cases()
        selected = [item for item in cases if item['case_id'] == case_id] if case_id else cases
        evidence, findings, activity, reviews = [], [], [], set()
        for case in selected:
            if not case['verified']:
                continue
            cid = case['case_id']
            evidence.extend(self.evidence(cid))
            records = load_scanned_evidence_records(self.cases_dir, case_ids=[cid])
            for record in records:
                findings.extend(record['findings'])
            for entry in self.entries(cid):
                activity.append(dict(case_id=cid, timestamp=entry['timestamp'], action=entry['action']))
                if entry['action'] == 'FINDING_MARKED_FALSE_POSITIVE_FOR_REVIEW':
                    reviews.add((cid, entry.get('details')))
        verified_evidence = 0
        for item in evidence:
            try:
                self.source(item['case_id'], item['id'])
                verified_evidence += 1
            except ServiceError:
                pass
        return dict(total_cases=len(cases), saved_evidence=len(evidence), verified_evidence=verified_evidence, open_reviews=len(reviews),
            high_critical=sum(f.get('severity') in {'High', 'Critical'} for f in findings),
            severity=dict(Counter(f.get('severity', 'Unknown') for f in findings)),
            methods=dict(Counter(f.get('source', 'rule') for f in findings)),
            evidence_types=dict(Counter(item['type'] or 'unknown' for item in evidence)),
            activity=sorted(activity, key=lambda e: e['timestamp'], reverse=True)[:20],
            invalid_cases=[item for item in selected if not item['verified']],
            scope="Verified case histories only; saved findings count scan versions separately.")
