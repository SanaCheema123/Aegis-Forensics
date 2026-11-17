"""Verified-context citations and fail-closed, format-independent exports."""
import ast
from copy import deepcopy
from io import BytesIO
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import MagicMock
import zipfile

from pypdf import PdfReader

from modules.ai_reporter import LocalLLMReporter, _evidence_text, validate_report
from modules.integrity import EvidenceIntegrity
from modules.evidence_reports import build_saved_evidence_report
from modules.pdf_report import render_forensic_pdf
from modules.scanned_evidence import add_scanned_evidence
from modules.report_validation import (
    DRAFT_WARNING, bind_report_context, render_forensic_text, validate_report_export, report_digest,
)


class ReportExportValidationTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.source = self.root / 'evidence.csv'
        self.source.write_bytes(b'user,message\nalice,review\n')
        self.audit = self.root / 'CASE-A_audit.log'
        self.digest = EvidenceIntegrity.calculate_sha256(str(self.source))
        EvidenceIntegrity.log_audit_trail('CASE-A', 'EVIDENCE_UPLOAD',
            f'File uploaded: evidence.csv | SHA256: {self.digest}', audit_path=self.audit)

    def finding(self, identifier='F-001', **changes):
        return dict(id=identifier, rule='Recorded check', severity='Medium', source='rule',
                    mitre='n/a', first_seen=None, last_seen=None,
                    description='The recorded content requires review.',
                    evidence=[dict(file='evidence.csv', line=2)], **changes)

    def report(self, findings=None, text=None):
        findings = findings or [self.finding()]
        reporter = LocalLLMReporter()
        body = reporter.generate_grounded_report('', '', findings=findings, use_llm=False)
        report = dict(case_id='CASE-A', filename='evidence.csv', sha256=self.digest,
                      source_paths=[str(self.source)], findings=reporter.last_report_findings,
                      text=body if text is None else text, finding_summary=reporter.last_finding_summary)
        return bind_report_context(report, findings, audit_path=self.audit)

    def assert_blocked_both(self, report, **context):
        for renderer in (render_forensic_text, render_forensic_pdf):
            with self.subTest(renderer=renderer.__name__):
                with self.assertRaisesRegex(ValueError, 'export blocked'):
                    renderer(report, **context)

    def test_valid_f_y_ml_and_hex_or_numeric_mon_citations(self):
        findings = [self.finding(identifier) for identifier in
                    ('F-001', 'Y-001', 'ML-001', 'MON-abc123def456', 'MON-001')]
        text = 'Review the referenced records [F-001, Y-001, ML-001, MON-abc123def456, MON-001].'
        self.assertTrue(validate_report(text, findings)['passed'])
        report = self.report(findings)
        self.assertTrue(validate_report_export(report)['passed'])
        self.assertIn('MON-abc123def456', render_forensic_text(report))
        pdf = render_forensic_pdf(report)
        extracted = '\n'.join(p.extract_text() for p in PdfReader(BytesIO(pdf)).pages)
        self.assertIn('MON-abc123def456', extracted)
        self.assertNotIn('UNVERIFIED DRAFT', extracted)

    def test_unknown_malformed_cross_case_and_duplicate_citations(self):
        finding = self.finding()
        for citation in ('F-999', 'Y-999', 'ML-999', 'MON-deadbeef', 'F-12', 'F-001, F-001'):
            self.assertFalse(validate_report(f'Review [{citation}].', [finding])['passed'])
        other = self.finding(case_id='CASE-B')
        self.assertFalse(validate_report('Review [F-001].', [other], case_id='CASE-A')['passed'])
        self.assertFalse(validate_report('Review [F-001].', [finding, deepcopy(finding)])['passed'])
        self.assert_blocked_both(self.report(text='Review [MON-fabricated].'))

    def test_export_context_case_and_evidence_reuse(self):
        report = self.report()
        self.assert_blocked_both(report, expected_case_id='CASE-B')
        self.assert_blocked_both(report, expected_sha256='f' * 64)
        report['case_id'] = 'CASE-B'
        report['validation'] = {'passed': True}
        self.assert_blocked_both(report)

    def test_cached_flags_text_findings_and_context_cannot_bypass_gate(self):
        original = self.report()
        for field in ('text', 'findings', 'validation_context', 'windows_event_references'):
            report = deepcopy(original)
            report['validation'] = {'passed': True}
            if field == 'text':
                report[field] += '\nFabricated claim [MON-fake].'
            elif field == 'findings':
                report[field][0]['evidence'][0]['line'] = 100
            elif field == 'validation_context':
                report[field]['findings'][0]['description'] = 'Invented details'
            else:
                report[field] = [dict(event_id=4625, record_id=999)]
            self.assert_blocked_both(report)
        forged = deepcopy(original)
        forged['text'] += '\nAn added claim [F-001].'
        forged['export_binding']['digest'] = report_digest(forged)
        self.assert_blocked_both(forged)

    def test_missing_out_of_bounds_and_duplicate_evidence_references(self):
        for references in ([], [dict(file='other.csv', line=2)], [dict(file='evidence.csv', line=99)],
                           [dict(file='evidence.csv', offset=999)],
                           [dict(file='evidence.csv', line=2)] * 2):
            finding = self.finding()
            finding['evidence'] = references
            report = self.report([finding])
            self.assertFalse(report['validation']['passed'])
            self.assert_blocked_both(report)

    def test_modified_evidence_blocks_both_formats_without_repair(self):
        report = self.report()
        self.source.write_bytes(b'modified bytes')
        audit_bytes = self.audit.read_bytes()
        self.assert_blocked_both(report)
        self.assertEqual(self.audit.read_bytes(), audit_bytes)
        self.assertEqual(self.source.read_bytes(), b'modified bytes')

    def test_invalid_audit_chain_blocks_exports_without_repair(self):
        report = self.report()
        self.audit.write_text(self.audit.read_text().replace('EVIDENCE_UPLOAD', 'CHANGED_ACTION'))
        audit_bytes = self.audit.read_bytes()
        self.assert_blocked_both(report)
        self.assertEqual(self.audit.read_bytes(), audit_bytes)

    def test_claims_must_use_the_cited_finding_not_an_unrelated_one(self):
        left, right = self.finding(), self.finding('MON-abc')
        left['description'] = 'A login from 192.0.2.1 was recorded.'
        right['description'] = 'A login from 192.0.2.2 was recorded.'
        self.assertFalse(validate_report('Login from 192.0.2.2 [F-001].', [left, right])['passed'])
        self.assertFalse(validate_report('Confirmed ransomware infection [F-001].', [left])['passed'])
        self.assertFalse(validate_report('Review line 99 [F-001].', [left])['passed'])
        self.assertFalse(validate_report('An uncited claim.\nReview [F-001].', [left])['passed'])

    def test_verified_archive_and_native_event_report_exports(self):
        for archive in (False, True):
            with self.subTest(archive=archive):
                finding = self.finding('MON-abcdef123456')
                if archive:
                    buffer = BytesIO()
                    with zipfile.ZipFile(buffer, 'w') as stream:
                        stream.writestr('nested/log.txt', b'line one\nline two\n')
                    data = buffer.getvalue()
                    finding.update(member='nested/log.txt', container_path='container.zip',
                                   member_path='container.zip!nested/log.txt',
                                   evidence=[dict(file='container.zip!nested/log.txt', line=2, offset=9)])
                    filename = 'container.zip'
                else:
                    reference = dict(Log='Security', EventId=4625, RecordId=42,
                                     Time='2026-11-13T10:00:00Z')
                    data = json.dumps(reference).encode()
                    filename = 'event.json'
                    finding['evidence'] = [reference]
                record = add_scanned_evidence(self.root / 'evidence', filename, data, [finding],
                    case_id='CASE-A', scanned_at_utc='2026-11-13T11:00:00Z', audit_log_path=self.audit,
                    audit_logger=lambda case, action, details: EvidenceIntegrity.log_audit_trail(
                        case, action, details, audit_path=self.audit))
                report = build_saved_evidence_report(record, 1,
                    self.root / 'evidence' / record['stored_filename'], audit_path=self.audit)
                self.assertTrue(validate_report_export(report)['passed'], report['validation'])
                self.assertIn('MON-abcdef123456', render_forensic_text(report))
                self.assertTrue(render_forensic_pdf(report).startswith(b'%PDF-'))

    def test_legacy_preview_is_explicitly_unverified_and_never_mutated(self):
        legacy = dict(case_id='CASE-A', text='Legacy report [F-001].', validation={'passed': True})
        before = json.dumps(legacy, sort_keys=True)
        self.assert_blocked_both(legacy)
        self.assertTrue(render_forensic_text(legacy, draft=True).startswith(DRAFT_WARNING))
        pdf = render_forensic_pdf(legacy, draft=True)
        extracted = '\n'.join(p.extract_text() for p in PdfReader(BytesIO(pdf)).pages)
        self.assertIn('UNVERIFIED DRAFT', extracted)
        self.assertEqual(json.dumps(legacy, sort_keys=True), before)

    def test_all_recorded_locator_types_survive_text_and_pdf(self):
        finding = self.finding()
        finding.update(member='nested/log.txt', member_path='case.zip!nested/log.txt')
        finding['evidence'] = [dict(file='case.zip!nested/log.txt', line=2, page=3,
                                    offset=0, EventId=4625, RecordId=42, Time='2026-11-13T10:00:00Z')]
        rendered = _evidence_text(finding)
        for value in ('line 2', 'page 3', 'byte offset 0', 'Event ID 4625', 'Record ID 42', 'nested/log.txt'):
            self.assertIn(value, rendered)
        report = dict(text=rendered, findings=[finding])
        pdf = render_forensic_pdf(report, draft=True)
        extracted = '\n'.join(p.extract_text() for p in PdfReader(BytesIO(pdf)).pages)
        for value in ('Event ID 4625', 'Record ID 42', 'nested/log.txt'):
            self.assertIn(value, extracted)

    def test_alternate_ui_exports_share_the_same_gate(self):
        source = (Path(__file__).resolve().parents[1] / 'dashboard/app.py').read_text(encoding='utf-8')
        tree = ast.parse(source)
        helper = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == '_report_export_payloads')
        namespace = dict(st=MagicMock(), DRAFT_WARNING=DRAFT_WARNING,
                         validate_report_export=validate_report_export,
                         render_forensic_text=render_forensic_text, render_forensic_pdf=render_forensic_pdf)
        exec(compile(ast.Module(body=[helper], type_ignores=[]), 'helper', 'exec'), namespace)
        report = self.report()
        self.assertIsNone(namespace['_report_export_payloads'](report, cached_text='different cached text'))
        self.assertIsNotNone(namespace['_report_export_payloads'](report, cached_text=report['text']))
        namespace['st'].warning.assert_called()
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == 'download_button':
                label = str(ast.unparse(node.args[0])) if node.args else ''
                if 'report (.md)' in label or 'report (.pdf)' in label:
                    self.assertTrue(any(k.arg == 'disabled' for k in node.keywords), label)


if __name__ == '__main__':
    unittest.main()
