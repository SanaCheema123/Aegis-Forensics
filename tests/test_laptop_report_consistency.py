"""Snapshot-only normalization and complete, provenance-aware laptop reports."""
import ast
from copy import deepcopy
import hashlib
from io import BytesIO
import json
from pathlib import Path
import re
import tempfile
import unittest

from pypdf import PdfReader

from modules.ai_reporter import ID_PATTERN, validate_report
from modules.evidence_reports import build_laptop_scan_report
from modules.integrity import EvidenceIntegrity
from modules.laptop_findings import collect_laptop_findings, laptop_source_coverage
from modules.pdf_report import render_forensic_pdf
from modules.report_validation import bind_report_context, render_forensic_text, validate_report_export


class LaptopReportConsistencyTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.path = self.root / 'artifact.txt'
        self.path.write_bytes(b'header\nrecorded marker\n')
        self.digest = hashlib.sha256(self.path.read_bytes()).hexdigest()
        self.audit = self.root / 'CASE-LAPTOP_audit.log'

    def snapshot(self):
        file_finding = dict(source='Static heuristic', rule='Recorded content indicator',
                            severity='Medium', description='A recorded file indicator requires review.',
                            path=str(self.path), sha256=self.digest,
                            evidence=[dict(file=str(self.path), line=2, offset=7)],
                            recommended_action='Review the recorded file indicator.')
        yara = {**deepcopy(file_finding), 'source': 'YARA', 'rule': 'Recorded_Signature',
                'severity': 'High', 'matches': [dict(line=2, offset=7, string='$marker')]}
        return dict(case_id='CASE-LAPTOP', root=str(self.root), started_at_utc='2026-11-13T10:00:00Z',
            completed_at_utc='2026-11-13T10:01:00Z', scan_complete=True, yara_available=True,
            files_checked=1, files_skipped=0, findings=[file_finding, yara],
            defender_status=dict(status={'AntivirusEnabled': True}, detections=[dict(
                DetectionID='DEF-42', ThreatID=900, ThreatName='Recorded detection',
                InitialDetectionTime='2026-11-13T09:00:00Z', Resources=['file:C:\\unavailable.exe'])]),
            running_processes=[dict(ProcessId=42, ParentProcessId=4, Name='review.exe',
                ExecutablePath='C:\\unavailable.exe', CommandLine='review.exe -encoded command',
                review_reasons=['Encoded command requires review.'])],
            processes_reviewed=100,
            startup_inventory=dict(startup_count=1, scheduled_task_count=1, errors=[],
                flagged_startup_items=[dict(Name='Review startup', Location='HKCU\\Run',
                    Command='review.exe', User='alice', review_reasons=['Startup command requires review.'])],
                flagged_scheduled_tasks=[dict(Name='Review task', Path='\\Tasks\\', Execute='review.exe',
                    Arguments='--check', User='alice', review_reasons=['Task action requires review.'])]),
            security_events=dict(events=[dict(Log='Security', EventId=4625, RecordId=99,
                Computer='HOST-A', Provider='Microsoft-Windows-Security-Auditing',
                Time='2026-11-13T09:30:00Z', EventData={'TargetUserName': 'alice', 'IpAddress': '192.0.2.1'})], errors=[]),
            system_collection_times={kind: '2026-11-13T10:02:00Z' for kind in
                ('defender', 'process', 'startup', 'scheduled task', 'windows event')})

    def record_snapshot(self, scan):
        entry = EvidenceIntegrity.log_audit_trail(scan['case_id'], 'LAPTOP_SCAN_COMPLETED',
            'test snapshot; snapshot_sha256=' + EvidenceIntegrity.scan_snapshot_hash(scan), audit_path=self.audit)
        scan['audit_trail'] = [entry]
        return scan

    def test_shared_complete_collection_preserves_sources_and_native_references(self):
        scan = self.snapshot()
        original = deepcopy(scan)
        findings = collect_laptop_findings(scan)
        self.assertEqual(len(findings), 7)
        self.assertEqual({f['source_type'] for f in findings},
            {'filesystem', 'yara', 'defender', 'process', 'startup', 'scheduled task', 'windows event'})
        by_type = {f['source_type']: f for f in findings}
        self.assertEqual(by_type['process']['process_id'], 42)
        self.assertEqual(by_type['process']['parent_process_id'], 4)
        self.assertEqual(by_type['process']['command_line'], 'review.exe -encoded command')
        self.assertEqual(by_type['windows event']['event_id'], 4625)
        self.assertEqual(by_type['windows event']['record_id'], 99)
        self.assertEqual(by_type['windows event']['first_seen'], '2026-11-13T09:30:00.000Z')
        self.assertEqual(by_type['windows event']['evidence'][0]['computer'], 'HOST-A')
        self.assertEqual(by_type['filesystem']['evidence'][0]['offset'], 7)
        self.assertEqual(by_type['filesystem']['sha256'], self.digest)
        for kind in ('defender', 'process', 'startup', 'scheduled task', 'windows event'):
            self.assertNotIn('sha256', by_type[kind])
            self.assertIn('not an immutable', by_type[kind]['evidence_status'])
            self.assertTrue(ID_PATTERN.fullmatch(by_type[kind]['id']))
        self.assertEqual(scan, original)

    def test_combined_report_has_identical_markdown_pdf_and_dashboard_findings(self):
        scan = self.record_snapshot(self.snapshot())
        original = deepcopy(scan)
        report = build_laptop_scan_report(scan, audit_path=self.audit)
        self.assertEqual(report['findings'], collect_laptop_findings(scan))
        self.assertTrue(report['validation']['passed'], report['validation'])
        self.assertTrue(validate_report_export(report)['passed'])
        markdown = render_forensic_text(report)
        pdf = render_forensic_pdf(report)
        extracted = '\n'.join(page.extract_text() for page in PdfReader(BytesIO(pdf)).pages)
        compact = re.sub(r'\s+', '', extracted)
        for finding in report['findings']:
            self.assertIn(f"[{finding['id']}]", markdown)
            self.assertIn(finding['id'], compact)
        for value in ('Process ID 42', 'Event ID 4625', 'Record ID 99', 'not immutable forensic artifacts'):
            self.assertIn(value, markdown)
        references = report['windows_event_references']
        self.assertEqual(references[0]['finding_id'], next(f['id'] for f in report['findings'] if f['source_type'] == 'windows event'))
        self.assertEqual(scan, original)

    def test_multiline_windows_messages_keep_citations_and_original_metadata(self):
        scan = self.snapshot()
        message = 'Recorded script block\r\nsecond recorded line\nlast recorded line'
        scan['security_events']['events'][0]['Message'] = message
        scan['running_processes'][0]['CommandLine'] = 'review.exe\r\n-recorded option'
        scan = self.record_snapshot(scan)
        original = deepcopy(scan)
        report = build_laptop_scan_report(scan, audit_path=self.audit)
        self.assertTrue(report['validation']['passed'], report['validation'])
        self.assertTrue(validate_report_export(report)['passed'])
        event = next(f for f in report['findings'] if f['source_type'] == 'windows event')
        self.assertEqual(event['technical_record']['Message'], message)
        self.assertEqual(report['findings'], collect_laptop_findings(scan))
        markdown = render_forensic_text(report)
        self.assertIn(r'Recorded script block\r\nsecond recorded line\nlast recorded line', markdown)
        pdf = '\n'.join(page.extract_text() for page in PdfReader(BytesIO(render_forensic_pdf(report))).pages)
        self.assertIn('Record ID 99', pdf)
        self.assertIn(r'second recorded line\nlast recorded line', pdf)
        self.assertEqual(scan, original)
        # Citation validation is unchanged: invented claims remain blocked.
        report['text'] += '\nAn invented claim without a citation.'
        self.assertFalse(validate_report_export(report)['passed'])

    def test_windows_message_larger_than_a_pdf_page_splits_without_losing_findings(self):
        scan = self.snapshot()
        scan['security_events']['events'][0]['Message'] = (
            'BEGIN-RECORDED-MESSAGE\n' + 'Recorded event text retained for review.\n' * 180
            + 'END-RECORDED-MESSAGE')
        report = build_laptop_scan_report(self.record_snapshot(scan), audit_path=self.audit)
        self.assertTrue(validate_report_export(report)['passed'], report['validation'])
        pdf = PdfReader(BytesIO(render_forensic_pdf(report)))
        self.assertGreater(len(pdf.pages), 2)
        text = '\n'.join(page.extract_text() for page in pdf.pages)
        self.assertIn('BEGIN-RECORDED-MESSAGE', text)
        self.assertIn('END-RECORDED-MESSAGE', text)
        for finding in report['findings']:
            self.assertIn(finding['id'], re.sub(r'\s+', '', text))

    def test_report_does_not_truncate_findings_at_llm_context_limit(self):
        scan = self.snapshot()
        template = scan['running_processes'][0]
        scan['running_processes'] = [{**template, 'ProcessId': n} for n in range(40)]
        scan = self.record_snapshot(scan)
        report = build_laptop_scan_report(scan, audit_path=self.audit)
        self.assertEqual(len(report['findings']), 46)
        self.assertEqual(report['finding_summary']['omitted_count'], 0)
        self.assertEqual(len(report['validation']['cited_ids']), 46)
        self.assertTrue(validate_report_export(report)['passed'], report['validation'])
        self.assertTrue(render_forensic_pdf(report).startswith(b'%PDF-'))

    def test_missing_failed_and_partial_sources_are_not_clean_verdicts(self):
        scan = self.snapshot()
        scan['defender_status'] = None
        scan['defender_status_error'] = 'Access denied'
        scan.pop('running_processes')
        scan['process_inventory_error'] = 'Process inventory unavailable'
        scan['startup_inventory']['errors'] = [{'Source': 'Tasks', 'Error': 'Access denied'}]
        scan['security_events']['errors'] = [{'Log': 'System', 'Error': 'Unavailable'}]
        coverage = {s['source']: s for s in laptop_source_coverage(scan)}
        self.assertEqual(coverage['defender']['status'], 'unavailable')
        self.assertEqual(coverage['process']['status'], 'unavailable')
        self.assertEqual(coverage['startup and scheduled tasks']['status'], 'partial')
        self.assertEqual(coverage['windows event']['status'], 'partial')
        report = build_laptop_scan_report(self.record_snapshot(scan), audit_path=self.audit)
        self.assertEqual(len(report['findings']), 5)
        self.assertIn('Access denied', report['text'])
        self.assertTrue(validate_report_export(report)['passed'], report['validation'])
        minimal = dict(case_id='CASE-LAPTOP', findings=deepcopy(scan['findings']), scan_complete=False)
        self.assertEqual(len(collect_laptop_findings(minimal)), 2)
        self.assertIn('not recorded', {s['status'] for s in laptop_source_coverage(minimal)})

    def test_duplicate_records_collapse_but_distinct_native_identities_remain(self):
        scan = self.snapshot()
        for key in ('findings', 'running_processes'):
            scan[key] += deepcopy(scan[key])
        scan['defender_status']['detections'] *= 2
        scan['startup_inventory']['flagged_startup_items'] *= 2
        scan['security_events']['events'] *= 2
        findings = collect_laptop_findings(scan)
        self.assertEqual(len(findings), 7)
        self.assertEqual(len({f['id'] for f in findings}), 7)
        process = deepcopy(scan['running_processes'][0])
        process['CreationDate'] = '2026-11-13T11:00:00Z'  # same PID, new observation
        scan['running_processes'].append(process)
        event = deepcopy(scan['security_events']['events'][0])
        event['Computer'] = 'HOST-B'  # same Record ID on another host
        scan['security_events']['events'].append(event)
        another = deepcopy(scan['findings'][0])
        another['path'] = str(self.root / 'different' / self.path.name)
        scan['findings'].append(another)
        self.assertEqual(len(collect_laptop_findings(scan)), 10)
        reversed_scan = deepcopy(scan)
        for key in ('findings', 'running_processes'):
            reversed_scan[key].reverse()
        reversed_scan['security_events']['events'].reverse()
        self.assertEqual(collect_laptop_findings(scan), collect_laptop_findings(reversed_scan))

    def test_normal_events_excluded_and_suspicious_service_logon_retained(self):
        scan = self.snapshot()
        scan['security_events']['events'] += [dict(EventId=4624, RecordId=1, Time='2026-11-13T10:00:00Z'),
            dict(EventId=4624, RecordId=2, Time='2026-11-13T10:00:00Z',
                 EventData={'TargetUserName': 'service', 'LogonType': '5', 'IpAddress': '192.0.2.5'})]
        events = [f for f in collect_laptop_findings(scan) if f['source_type'] == 'windows event']
        self.assertEqual(len(events), 2)
        self.assertIn(2, {f['record_id'] for f in events})

    def test_modified_scan_or_file_blocks_verification_without_repair(self):
        scan = self.record_snapshot(self.snapshot())
        report = build_laptop_scan_report(scan, audit_path=self.audit)
        audit_before = self.audit.read_bytes()
        altered = deepcopy(scan)
        altered['running_processes'][0]['CommandLine'] = 'modified command'
        with self.assertRaises(ValueError):
            build_laptop_scan_report(altered, audit_path=self.audit)
        self.assertEqual(self.audit.read_bytes(), audit_before)
        self.path.write_bytes(b'changed file bytes')
        self.assertFalse(validate_report_export(report)['passed'])
        self.assertEqual(self.path.read_bytes(), b'changed file bytes')

    def test_cannot_bind_omitted_or_fabricated_observations_to_valid_snapshot(self):
        scan = self.record_snapshot(self.snapshot())
        report = build_laptop_scan_report(scan, audit_path=self.audit)
        for changed in (report['findings'][:-1], deepcopy(report['findings'])):
            if len(changed) == len(report['findings']):
                changed[0]['description'] = 'Fabricated observation'
            with self.assertRaisesRegex(ValueError, 'findings differ'):
                bind_report_context(deepcopy(report), changed, scan_report=scan, audit_path=self.audit)
        self.assertFalse(validate_report_export(report, expected_scan_snapshot_sha256='f' * 64)['passed'])

    def test_missing_observation_identifiers_are_not_invented(self):
        scan = self.snapshot()
        scan['running_processes'][0].pop('ProcessId')
        scan['security_events']['events'][0].pop('RecordId')
        findings = collect_laptop_findings(scan)
        process = next(f for f in findings if f['source_type'] == 'process')
        event = next(f for f in findings if f['source_type'] == 'windows event')
        self.assertIsNone(process['process_id'])
        self.assertIsNone(event['record_id'])
        self.assertEqual(process['collected_at_utc'], '2026-11-13T10:02:00Z')
        self.assertTrue(validate_report('Review the observation [' + process['id'] + '].', [process])['passed'])

    def test_system_only_findings_require_snapshot_not_live_executable_hashes(self):
        scan = self.snapshot()
        scan['findings'] = []
        scan['running_processes'][0]['SHA256'] = 'a' * 64
        report = build_laptop_scan_report(self.record_snapshot(scan), audit_path=self.audit)
        self.assertEqual(len(report['findings']), 5)
        self.assertEqual(report['validation_context']['sources'], [])
        self.assertTrue(validate_report_export(report)['passed'], report['validation'])
        process = next(f for f in report['findings'] if f['source_type'] == 'process')
        self.assertNotIn('sha256', process)
        self.assertEqual(process['reported_sha256'], 'a' * 64)
        self.assertIn('reported SHA-256 (unverified)', report['text'])

    def test_all_system_sources_unavailable_still_reports_verified_file_findings(self):
        scan = self.snapshot()
        for field, error_field in (
            ('defender_status', 'defender_status_error'), ('running_processes', 'process_inventory_error'),
            ('startup_inventory', 'startup_inventory_error'), ('security_events', 'security_event_error')):
            scan[field] = None
            scan[error_field] = 'Read-only source inaccessible'
        report = build_laptop_scan_report(self.record_snapshot(scan), audit_path=self.audit)
        self.assertEqual(len(report['findings']), 2)
        self.assertTrue(validate_report_export(report)['passed'], report['validation'])
        self.assertEqual(sum(c['status'] == 'unavailable' for c in report['source_coverage']), 4)

    def test_missing_file_hash_is_explicit_and_keeps_trusted_exports_blocked(self):
        scan = self.snapshot()
        for finding in scan['findings']:
            finding.pop('sha256')
        report = build_laptop_scan_report(self.record_snapshot(scan), audit_path=self.audit)
        self.assertFalse(report['validation']['passed'])
        self.assertFalse(validate_report_export(report)['passed'])
        files = [f for f in report['findings'] if f['source_type'] in {'filesystem', 'yara'}]
        self.assertTrue(all('hash not recorded' in f['evidence_status'] for f in files))
        self.assertTrue(all(not f.get('sha256') for f in files))

    def test_legacy_scan_is_not_rewritten_or_automatically_repaired(self):
        scan = self.snapshot()
        before = json.dumps(scan, sort_keys=True)
        with self.assertRaises(ValueError):
            build_laptop_scan_report(scan, audit_path=self.audit)
        self.assertEqual(json.dumps(scan, sort_keys=True), before)
        self.assertFalse(self.audit.exists())

    def test_dashboard_history_and_report_use_shared_collector(self):
        source = (Path(__file__).resolve().parents[1] / 'dashboard/app.py').read_text(encoding='utf-8')
        tree = ast.parse(source)
        functions = {n.name: n for n in tree.body if isinstance(n, ast.FunctionDef)}
        self.assertIn('collect_laptop_findings(report)', ast.get_source_segment(source, functions['show_laptop_scan']))
        self.assertIn('collect_laptop_findings(scan_report)', ast.get_source_segment(source, functions['_scan_findings_for_report']))
        self.assertIn('build_laptop_scan_report(scan_report)', ast.get_source_segment(source, functions['show_ai_reports']))


if __name__ == '__main__':
    unittest.main()
