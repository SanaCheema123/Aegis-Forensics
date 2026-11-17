"""CSV physical spans, logical identities and consumer/export regressions."""
import ast
from copy import deepcopy
from io import BytesIO
from pathlib import Path
import tempfile
import tracemalloc
import unittest
from unittest.mock import patch

import pandas as pd
from pypdf import PdfReader

from modules.csv_evidence import (CSV_METADATA, iter_csv_locations, read_evidence_csv,
    source_locator, file_sha256, locator_label, physical_line_number, refresh_csv_session)
from modules.parser import LogParser
from modules.rules import load_log_csv, RuleEngine
from modules.timeline import TimelineConstructor
from modules.semantic_search import prepare_evidence_search, search_evidence
from modules.ai_reporter import ml_to_report_findings, LocalLLMReporter, _evidence_text, validate_report
from modules.integrity import EvidenceIntegrity
from modules.pdf_report import render_forensic_pdf
from modules.report_validation import bind_report_context, render_forensic_text, validate_report_export
from modules.yara_scanner import YaraScanner

ROOT = Path(__file__).resolve().parents[1]


class CsvEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.path = self.root / 'events.csv'

    def write(self, content):
        self.path.write_bytes(content)
        return self.path

    def multiline(self, newline=b'\n'):
        return self.write(newline.join([
            b'timestamp,event_id,user,source_ip,message',
            b'2026-11-16T03:00:00Z,4624,alice,192.0.2.1,"failed login,',
            b'with ""quotes"""', b'',
            b'2026-11-16T02:00:00Z,4624,bob,192.0.2.2,failed login', b'']))

    def ml(self, frame):
        anomalies = pd.DataFrame({'ml_score': [0.9] * len(frame),
            'ml_model': ['trained_xgboost'] * len(frame), 'anomaly_score': [-1] * len(frame)},
            index=frame.index)
        return ml_to_report_findings(anomalies, frame, 'trained_xgboost', 'random',
            self.path.name, file_sha256(self.path))

    def report(self, findings):
        digest = file_sha256(self.path)
        audit = self.root / 'CASE-CSV_audit.log'
        EvidenceIntegrity.log_audit_trail('CASE-CSV', 'EVIDENCE_UPLOAD',
            f'File uploaded: {self.path.name} | SHA256: {digest}', audit_path=audit)
        reporter = LocalLLMReporter()
        text = reporter.generate_grounded_report('', '', findings=findings, use_llm=False)
        report = dict(case_id='CASE-CSV', filename=self.path.name, sha256=digest,
            source_paths=[str(self.path)], findings=reporter.last_report_findings, text=text)
        return bind_report_context(report, findings, audit_path=audit)

    def test_ordinary_csv_bom_and_original_bytes_are_preserved(self):
        path = self.write(b'\xef\xbb\xbfid,message\n1,first\n2,second\n')
        before = path.read_bytes()
        frame = LogParser(str(path)).parse_logs()
        self.assertEqual(list(iter_csv_locations(path)), [(1, 2, 2), (2, 3, 3)])
        ref = source_locator(frame, 1)
        self.assertEqual((ref['record_number'], ref['line'], ref['line_end']), (2, 3, 3))
        self.assertEqual(ref['sha256'], file_sha256(path))
        self.assertEqual(ref['csv_record_id'], f"csv:{ref['sha256']}:record:2")
        self.assertEqual(list(frame.columns), ['id', 'message'])
        self.assertEqual(path.read_bytes(), before)

    def test_multiline_delimiters_quotes_blanks_and_newline_conventions(self):
        for newline in (b'\n', b'\r\n', b'\r'):
            with self.subTest(newline=newline):
                path = self.multiline(newline)
                frame = load_log_csv(path)
                self.assertEqual(list(iter_csv_locations(path)), [(1, 2, 3), (2, 5, 5)])
                self.assertIn('failed login,', frame.iloc[0]['message'])
                self.assertIn('with "quotes"', frame.iloc[0]['message'])
                self.assertEqual(frame['line_no'].tolist(), [2, 5])
                self.assertEqual(frame['line_end'].tolist(), [3, 5])

    def test_leading_blanks_whitespace_and_quoted_empty_records(self):
        path = self.write(b'\n  \r\nid,message\r\n1,""\r\n \r\n2," \r\n "\r\n')
        frame = read_evidence_csv(path)
        self.assertEqual(len(frame), 2)
        self.assertEqual(list(iter_csv_locations(path)), [(1, 4, 4), (2, 6, 7)])
        self.assertEqual(source_locator(frame, 1)['line_end'], 7)
        self.write(b'message\n""\n\n" "\nlast')
        self.assertEqual(len(read_evidence_csv(self.path)), 3)
        self.assertEqual(list(iter_csv_locations(self.path)), [(1, 2, 2), (2, 4, 4), (3, 5, 5)])

    def test_multiline_header_and_trailing_missing_fields(self):
        path = self.write(b'"first\ncolumn",message\n1,one\n2\n')
        frame = read_evidence_csv(path)
        self.assertEqual(list(iter_csv_locations(path)), [(1, 3, 3), (2, 4, 4)])
        self.assertTrue(pd.isna(frame.iloc[1]['message']))

    def test_malformed_csv_and_encoding_errors_fail_closed(self):
        for content in (b'id,message\n1,"unterminated\n', b'id,message\n1,"bad"tail\n',
                        b'id,message\n1,two,extra\n', b'id,message\n1,\x00value\n',
                        b'id,message\n1,\xff\n', b''):
            with self.subTest(content=content):
                self.write(content)
                with self.assertRaises((ValueError, UnicodeError)):
                    read_evidence_csv(self.path)

    def test_parser_disagreement_and_changing_evidence_fail_closed(self):
        self.write(b'id,message\n1,one\n')
        with patch('modules.csv_evidence.pd.read_csv', return_value=pd.DataFrame({'id': [1, 2]})):
            with self.assertRaisesRegex(ValueError, 'disagree'):
                read_evidence_csv(self.path)
        with patch('modules.csv_evidence.file_sha256', side_effect=['a' * 64, 'b' * 64]):
            with self.assertRaisesRegex(ValueError, 'changed'):
                read_evidence_csv(self.path)

    def test_search_and_ml_preserve_same_locators_after_filter_and_sort(self):
        self.multiline()
        raw = load_log_csv(self.path)
        view = raw.iloc[[1, 0]]
        prepared = prepare_evidence_search(view, sha256=file_sha256(self.path), case_id='CASE-CSV',
            query='failed login', filename=self.path.name, source_rows=raw)
        with patch('modules.semantic_matcher._SENTENCE_TRANSFORMERS_AVAILABLE', False):
            matches = search_evidence(prepared)['matches']
        ml = self.ml(view)
        by_record = {f['source_locator']['record_number']: f['source_locator'] for f in ml}
        self.assertEqual({m['record_number'] for m in matches}, {1, 2})
        for match in matches:
            ref = by_record[match['record_number']]
            for key in ('csv_record_id', 'line', 'line_end', 'file', 'sha256'):
                self.assertEqual(match[key], ref[key])
            self.assertEqual(match['source_line'], ref['line'])
            self.assertEqual(match['source_line_end'], ref['line_end'])
        self.assertEqual(ml[0]['original_csv_line'], 5)
        self.assertEqual(ml[1]['original_csv_line_end'], 3)
        self.assertIn('logical CSV record 1, lines 2-3', ml[1]['description'])

    def test_unmapped_frames_use_logical_records_and_legacy_lines_stay_explicit(self):
        self.write(b'id,message\n1,first\n2,second\n')
        frame = pd.DataFrame({'message': ['first', 'second']}, index=[90, 30])
        findings = self.ml(frame)
        self.assertEqual([f['original_csv_record'] for f in findings], [1, 2])
        self.assertTrue(all('line' not in f['evidence'][0] for f in findings))
        self.assertTrue(all(f['original_csv_line'] is None for f in findings))
        self.assertIn('logical CSV record 1', findings[0]['description'])
        self.assertTrue(validate_report_export(self.report(findings))['passed'])
        legacy = pd.DataFrame({'line_no': [23]})
        self.assertEqual(source_locator(legacy, 0), {'line': 23})
        original = {'id': 'F-001', 'file': 'old.csv', 'evidence': [{'file': 'old.csv', 'line': 23}]}
        before = deepcopy(original)
        self.assertEqual(_evidence_text(original), 'old.csv, line 23')
        self.assertEqual(before, original)

    def test_rule_findings_and_sorted_timeline_keep_record_ranges(self):
        self.multiline()
        raw = load_log_csv(self.path)
        findings = RuleEngine(raw, source_file=self.path.name).run()
        self.assertTrue(findings)
        self.assertEqual({(e['record_number'], e['line'], e['line_end'])
            for f in findings for e in f['evidence']}, {(1, 2, 3), (2, 5, 5)})
        timeline = TimelineConstructor(raw).build_timeline()
        self.assertEqual(timeline['source_record_number'].tolist(), [2, 1])
        self.assertEqual(timeline['source_line'].tolist(), [5, 2])
        self.assertEqual(timeline['source_line_end'].tolist(), [5, 3])
        unlocated = raw.drop(columns=['line_no', 'line_end'])
        unlocated.attrs = {}
        logical = RuleEngine(unlocated, source_file=self.path.name).run()
        self.assertTrue(all('line' not in e for f in logical for e in f['evidence']))
        self.assertEqual({e['record_number'] for f in logical for e in f['evidence']}, {1, 2})

    def test_markdown_pdf_and_citation_validation_agree_on_locators(self):
        self.multiline()
        findings = self.ml(load_log_csv(self.path))
        report = self.report(findings)
        self.assertTrue(validate_report_export(report)['passed'], report.get('validation'))
        markdown = render_forensic_text(report)
        pdf = render_forensic_pdf(report)
        text = '\n'.join(p.extract_text() for p in PdfReader(BytesIO(pdf)).pages)
        for locator in ('logical CSV record 1, lines 2-3', 'logical CSV record 2, line 5'):
            self.assertIn(locator, markdown)
            self.assertIn(locator, text)
        self.assertIn(file_sha256(self.path), markdown)
        forged = 'Review logical CSV record 99 [ML-001].'
        self.assertFalse(validate_report(forged, findings)['passed'])
        self.assertFalse(validate_report('Review lines 2-5 [ML-001].', findings)['passed'])
        self.assertTrue(validate_report('Review lines 2-3 [ML-001].', findings)['passed'])

    def test_wrong_ranges_record_ids_numbers_and_hashes_block_trusted_exports(self):
        self.multiline()
        original = self.ml(load_log_csv(self.path))
        for change in ({'line': 3, 'line_end': 3}, {'line_end': 5}, {'record_number': 99},
                       {'csv_record_id': 'invented'}, {'sha256': 'f' * 64}, {'line_end': 1}):
            with self.subTest(change=change):
                findings = deepcopy(original)
                findings[0]['evidence'][0].update(change)
                findings[0]['matches'][0].update(change)
                report = self.report(findings)
                self.assertFalse(validate_report_export(report)['passed'])
                for render in (render_forensic_text, render_forensic_pdf):
                    with self.assertRaises(ValueError):
                        render(report)

    def test_evidence_hash_mismatch_blocks_reusing_locators(self):
        self.multiline()
        frame = read_evidence_csv(self.path)
        with self.assertRaisesRegex(ValueError, 'SHA-256'):
            source_locator(frame, 0, sha256='f' * 64)
        with self.assertRaisesRegex(ValueError, 'SHA-256'):
            prepare_evidence_search(frame, sha256='f' * 64, case_id='CASE-CSV',
                query='login', filename=self.path.name)

    def test_anomaly_review_presentation_uses_logical_number_and_physical_range(self):
        self.multiline()
        finding = self.ml(load_log_csv(self.path))[0]
        tree = ast.parse((ROOT / 'dashboard/app.py').read_text(encoding='utf-8'))
        node = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == '_finding_presentation')
        namespace = {'RULE_FRIENDLY_TEXT': {}}
        exec(compile(ast.Module(body=[node], type_ignores=[]), 'app.py', 'exec'), namespace)
        affected = namespace['_finding_presentation'](finding)['affected']
        self.assertIn('logical CSV record 1', affected)
        self.assertIn('CSV lines 2–3', affected)
        self.assertNotIn('CSV row', affected)

    def test_large_csv_location_pass_has_bounded_memory(self):
        with self.path.open('wb') as stream:
            stream.write(b'id,message\r\n')
            for i in range(150_000):
                stream.write(f'{i},"record, with ""quotes""\r\ncontinued"\r\n'.encode())
        tracemalloc.start()
        try:
            last = None
            for location in iter_csv_locations(self.path):
                last = location
            _, peak = tracemalloc.get_traced_memory()
        finally:
            tracemalloc.stop()
        self.assertEqual(last, (150_000, 300_000, 300_001))
        self.assertLess(peak, 2 * 1024 * 1024)
        self.peak_locator_memory = peak

    def test_csv_native_record_id_is_preserved_alongside_csv_identity(self):
        self.write(b'timestamp,event_id,user,source_ip,host,record_id\n'
            b'2026-11-16T03:00:00Z,4625,alice,192.0.2.1,server,43\n')
        frame = load_log_csv(self.path)
        engine = RuleEngine(frame, source_file=self.path.name, failed_threshold=1)
        finding = engine.run()[0]
        reference = finding['evidence'][0]
        self.assertEqual(reference['record_id'], 43)
        self.assertEqual(reference['csv_record_id'], f"csv:{file_sha256(self.path)}:record:1")
        self.assertEqual(reference['record_number'], 1)

    def test_csv_session_cache_version_changes_preserve_archived_reports(self):
        self.multiline()
        frame = read_evidence_csv(self.path)
        archived = {'text': 'original historical report'}
        state = dict(ai_report={'text': 'old locator cache'}, investigation_search_result='old',
                     archived_reports=[archived])
        refresh_csv_session(state, frame)
        self.assertNotIn('ai_report', state)
        self.assertNotIn('investigation_search_result', state)
        self.assertEqual(state['archived_reports'], [archived])
        state['ai_report'] = 'new'
        refresh_csv_session(state, frame)
        self.assertEqual(state['ai_report'], 'new')

    def test_large_single_field_and_csv_yara_physical_newlines(self):
        self.write(b'id,message\n1,"' + b'x' * 262_144 + b'\ncontinued"\n')
        self.assertEqual(source_locator(read_evidence_csv(self.path), 0)['line_end'], 3)
        for content in (b'a\rb\rmarker', b'a\r\nb\r\nmarker', b'a\nb\nmarker'):
            offset = content.index(b'marker')
            self.assertEqual(physical_line_number(content, offset), 3)
            match = type('Match', (), {'strings': [(offset, '$test', b'marker')]})()
            hits, _, _ = YaraScanner._extract(match, content, True, name='events.csv')
            self.assertEqual(hits[0]['line'], 3)


if __name__ == '__main__':
    unittest.main()
