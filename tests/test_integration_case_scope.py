"""Regression tests for reproduced dashboard case-routing and startup defects."""
import ast
import json
from pathlib import Path
import re
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock

from modules.evidence_reports import build_saved_evidence_report
from modules.integrity import EvidenceIntegrity
from modules.report_validation import validate_report_export
from modules.safety_checks import check_uploaded_file
from modules.scanned_evidence import add_scanned_evidence, select_saved_scan, scan_record_id, invalidate_scan_session
from modules.yara_scanner import YaraScanner

ROOT = Path(__file__).resolve().parents[1]
TREE = ast.parse((ROOT / 'dashboard/app.py').read_text(encoding='utf-8'))


class IntegrationCaseScopeTests(unittest.TestCase):
    def test_report_mode_and_failure_reason_are_visible(self):
        ui = SimpleNamespace(caption=Mock(), info=Mock())
        node = next(node for node in TREE.body if isinstance(node, ast.FunctionDef)
                    and node.name == '_render_report_mode')
        namespace = dict(st=ui)
        exec(compile(ast.Module(body=[node], type_ignores=[]), '<report mode>', 'exec'), namespace)
        namespace['_render_report_mode']({'mode': 'template', 'note': 'LLM unavailable: read timed out.'})
        ui.caption.assert_called_with('Report mode: Deterministic template')
        ui.info.assert_called_with('LLM unavailable: read timed out.')

    def test_same_hash_sources_are_resolved_by_recorded_path_and_case_not_position(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); raw = root / 'raw'; raw.mkdir(); cases = root / 'cases'; cases.mkdir()
            first = raw / 'network.csv'; second = raw / 'network_1.csv'
            first.write_bytes(b'source,record\n'); second.write_bytes(first.read_bytes())
            digest = EvidenceIntegrity.calculate_sha256(first)
            for case, path in (('CASE-FIRST', first), ('CASE-SECOND', second)):
                EvidenceIntegrity.log_audit_trail(case, 'EVIDENCE_UPLOAD',
                    f'File uploaded: {path.name} | SHA256: {digest}', audit_path=cases / f'{case}_audit.log')
            node = next(node for node in TREE.body if isinstance(node, ast.FunctionDef)
                        and node.name == '_selected_saved_evidence_path')
            namespace = dict(Path=Path, RAW_DIR=raw, CASES_DIR=cases, EvidenceIntegrity=EvidenceIntegrity)
            exec(compile(ast.Module(body=[node], type_ignores=[]), '<source resolution>', 'exec'), namespace)
            resolve = namespace['_selected_saved_evidence_path']
            selection = dict(case_id='CASE-SECOND', sha256=digest, stored_filename=second.name)
            self.assertEqual(resolve(selection), second)
            selection.pop('stored_filename')
            self.assertEqual(resolve(selection), second)
            # Multiple uploads in the same case require an explicit source path.
            EvidenceIntegrity.log_audit_trail('CASE-SECOND', 'EVIDENCE_UPLOAD',
                f'File uploaded: {first.name} | SHA256: {digest}', audit_path=cases / 'CASE-SECOND_audit.log')
            with self.assertRaisesRegex(ValueError, 'Multiple case-linked copies'):
                resolve(selection)
            selection['stored_filename'] = '../network.csv'
            with self.assertRaisesRegex(ValueError, 'leaves the evidence store'):
                resolve(selection)
            selection['stored_filename'] = second.name
            second.write_bytes(b'changed evidence')
            self.assertIsNone(resolve(selection))

    def test_pdf_layout_error_is_shown_without_bypassing_export_validation(self):
        from reportlab.platypus.doctemplate import LayoutError
        warning = Mock()
        validate = Mock(return_value={'passed': True})
        pdf = Mock(side_effect=LayoutError('Recorded field exceeds the PDF layout'))
        namespace = dict(st=SimpleNamespace(warning=warning), DRAFT_WARNING='Unverified draft:',
                         validate_report_export=validate, render_forensic_text=Mock(return_value='report'),
                         render_forensic_pdf=pdf)
        node = next(node for node in TREE.body if isinstance(node, ast.FunctionDef)
                    and node.name == '_report_export_payloads')
        exec(compile(ast.Module(body=[node], type_ignores=[]), '<export guard>', 'exec'), namespace)
        self.assertIsNone(namespace['_report_export_payloads']({'text': 'report'}))
        self.assertIn('exceeds the PDF layout', warning.call_args.args[0])
        validate.return_value = {'passed': False, 'errors': ['Evidence hash mismatch']}
        pdf.reset_mock()
        self.assertIsNone(namespace['_report_export_payloads']({'text': 'report'}))
        pdf.assert_not_called()

    def test_optional_embedding_import_is_deferred_in_a_fresh_process(self):
        result = subprocess.run([sys.executable, '-c',
            "import sys; from modules.semantic_matcher import SemanticMatcher; "
            "m=SemanticMatcher(); m.correlate_events(['audit event'], 'audit'); "
            "assert m.last_mode == 'lexical_heuristic'; "
            "assert not {'sentence_transformers','transformers','torch'} & set(sys.modules)"],
            cwd=ROOT, capture_output=True, text=True, timeout=15)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_scoped_latest_and_historical_reports_retain_fail_closed_integrity(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            cases = root / 'cases'; cases.mkdir()
            raw = root / 'raw'
            data = b'AEGIS_YARA_TEST_MARKER_2026\n'
            findings = check_uploaded_file('marker.txt', data, YaraScanner())['findings']
            audit = cases / 'CASE-GOOD_audit.log'
            records = []
            for number, severity in ((1, 'Low'), (2, 'Medium')):
                records.append(add_scanned_evidence(raw, 'marker.txt', data,
                    [dict(findings[0], id=f'Y-00{number}', severity=severity)], case_id='CASE-GOOD',
                    scanned_at_utc=f'2026-11-16T0{number}:00:00Z', audit_log_path=audit,
                    audit_logger=lambda c, a, d: EvidenceIntegrity.log_audit_trail(c, a, d, audit_path=audit)))
            bad = cases / 'CASE-BAD_audit.log'
            bad.write_text('{"action":"LEGACY_TEST"}\n', encoding='utf-8')
            original_bad = bad.read_bytes()
            state = {}
            namespace = dict(st=SimpleNamespace(session_state=state, warning=Mock()), CASES_DIR=cases,
                DEFAULT_CASE_ID='CASE-BAD', EvidenceIntegrity=EvidenceIntegrity,
                select_saved_scan=select_saved_scan, scan_record_id=scan_record_id,
                invalidate_scan_session=invalidate_scan_session,
                build_saved_evidence_report=build_saved_evidence_report, save_forensic_report=Mock(),
                navigate_to=Mock(), HASH_RE=re.compile(r'File uploaded: (.+?) \| SHA256: ([0-9a-fA-F]{64})'))
            nodes = [node for node in TREE.body if isinstance(node, ast.FunctionDef) and node.name in
                {'_open_saved_evidence', '_generate_saved_evidence_report', 'recorded_hashes'}]
            exec(compile(ast.Module(body=nodes, type_ignores=[]), '<dashboard workflow>', 'exec'), namespace)
            path = raw / records[0]['stored_filename']
            namespace['_open_saved_evidence'](path, ['CASE-GOOD'], 1)
            # Global default does not silently skip the invalid unrelated chain.
            with self.assertRaises(ValueError):
                namespace['_generate_saved_evidence_report'](path, 1, ['CASE-GOOD'])
            state['selected_saved_evidence']['history_case_id'] = 'CASE-GOOD'
            report = namespace['_generate_saved_evidence_report'](path, 1, ['CASE-GOOD'])
            self.assertEqual(report['scan_id'], scan_record_id(records[1]))
            self.assertEqual(report['findings'][0]['severity'], 'Medium')
            self.assertTrue(validate_report_export(report)['passed'])
            state['ai_report'] = report
            namespace['_open_saved_evidence'](path, ['CASE-GOOD'], 1, scan_id=scan_record_id(records[0]))
            self.assertNotIn('ai_report', state)
            historical = namespace['_generate_saved_evidence_report'](path, 1, ['CASE-GOOD'])
            self.assertEqual(historical['scan_id'], scan_record_id(records[0]))
            self.assertEqual(historical['findings'][0]['severity'], 'Low')
            state['selected_saved_evidence']['history_case_id'] = 'CASE-BAD'
            with self.assertRaises(ValueError):
                namespace['_generate_saved_evidence_report'](path, 1, ['CASE-GOOD'])
            self.assertEqual(bad.read_bytes(), original_bad)
            # Damage the selected chain only in this temporary negative fixture.
            state['selected_saved_evidence']['history_case_id'] = 'CASE-GOOD'
            entries = audit.read_text(encoding='utf-8').splitlines()
            entry = json.loads(entries[-1]); entry['details'] = 'tampered'
            audit.write_text('\n'.join(entries[:-1] + [json.dumps(entry)]) + '\n', encoding='utf-8')
            with self.assertRaises(ValueError):
                namespace['_generate_saved_evidence_report'](path, 1, ['CASE-GOOD'])

    def test_new_evidence_case_choice_is_explicit_and_does_not_verify_or_rewrite_history(self):
        with tempfile.TemporaryDirectory() as temporary:
            cases = Path(temporary)
            damaged = cases / 'CASE-BAD_audit.log'
            damaged.write_bytes(b'invalid historical data\n')
            (cases / 'CASE-GOOD_audit.log').touch()
            select = Mock(return_value='CASE-GOOD')
            namespace = dict(st=SimpleNamespace(selectbox=select), CASES_DIR=cases)
            node = next(node for node in TREE.body if isinstance(node, ast.FunctionDef)
                        and node.name == '_choose_investigation_case')
            exec(compile(ast.Module(body=[node], type_ignores=[]), '<case picker>', 'exec'), namespace)
            self.assertEqual(namespace['_choose_investigation_case']('CASE-BAD', 'test'), 'CASE-GOOD')
            self.assertEqual(select.call_args.args[1], ['CASE-BAD', 'CASE-GOOD'])
            self.assertEqual(damaged.read_bytes(), b'invalid historical data\n')


if __name__ == '__main__':
    unittest.main()
