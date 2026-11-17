"""Audit remediation: durable review identity, network handoff and evaluation."""
import ast
from copy import deepcopy
from pathlib import Path
import tempfile
import unittest
from unittest.mock import MagicMock, Mock

from modules.csv_evidence import read_evidence_csv
from modules.finding_reviews import mark_for_review, review_status
from modules.integrity import EvidenceIntegrity
from modules.ml_evaluation import evaluate_labeled_csv
from modules.scanned_evidence import add_scanned_evidence, select_saved_scan, scan_record_id

ROOT = Path(__file__).resolve().parents[1]


class ReviewPersistenceTests(unittest.TestCase):
    def test_restart_duplicates_and_scan_evidence_case_isolation(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "A_audit.log"
            finding = dict(id="ML-001", sha256="a" * 64, scan_id="scan-1", original_csv_record=109)
            original = deepcopy(finding)
            first = mark_for_review(finding, "A", audit_path=path)
            before = path.read_bytes()
            self.assertEqual(review_status(deepcopy(finding), "A", audit_path=path), first)
            self.assertEqual(mark_for_review(finding, "A", audit_path=path), first)
            self.assertEqual(path.read_bytes(), before)
            self.assertEqual(finding, original)
            for changes in (dict(scan_id="scan-2"), dict(sha256="b" * 64), dict(original_csv_record=110)):
                self.assertIsNone(review_status({**finding, **changes}, "A", audit_path=path))
            with self.assertRaises(ValueError):
                review_status(finding, "B", audit_path=path)
            with self.assertRaises(ValueError):
                mark_for_review({**finding, "case_id": "B"}, "A", audit_path=path)
            self.assertTrue(EvidenceIntegrity.verify_audit_trail("A", path)[0])

    def test_broken_history_cannot_be_flagged_or_repaired(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "A_audit.log"
            mark_for_review(dict(id="ML-001"), "A", audit_path=path)
            path.write_text(path.read_text().replace("ML-001", "ML-002"))
            before = path.read_bytes()
            with self.assertRaises(ValueError):
                mark_for_review(dict(id="ML-003"), "A", audit_path=path)
            self.assertEqual(path.read_bytes(), before)


class EvaluationTests(unittest.TestCase):
    def test_metrics_align_reordered_duplicate_content_by_source_identity(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "labels.csv"
            path.write_text("message,label\nsame,0\nsame,1\nsame,1\nsame,0\n")
            frame = read_evidence_csv(path)
            result = evaluate_labeled_csv(frame.iloc[::-1], frame.iloc[[0, 1]])
            self.assertEqual(result["confusion_matrix"], [[1, 1], [1, 1]])
            for key in ("accuracy", "precision", "recall", "f1"):
                self.assertEqual(result[key], 0.5)
            self.assertEqual(evaluate_labeled_csv(frame, frame.iloc[:0])["flagged"], 0)
            with self.assertRaises(ValueError):
                evaluate_labeled_csv(frame, frame.iloc[[0, 0]])
            different = frame.copy()
            different.attrs = deepcopy(frame.attrs)
            different.attrs['aegis_csv_source_v1']['sha256'] = 'b' * 64
            with self.assertRaises(ValueError):
                evaluate_labeled_csv(frame, different.iloc[[0]])
            with self.assertRaises(ValueError):
                evaluate_labeled_csv(frame.assign(label=[0, None, 1, 0]), frame.iloc[:0])


class NetworkHandoffTests(unittest.TestCase):
    def test_actual_dashboard_handoff_saves_and_selects_exact_scan(self):
        tree = ast.parse((ROOT / "dashboard/app.py").read_text(encoding="utf-8"))
        branch = next(node for node in tree.body if isinstance(node, ast.If)
            and ast.unparse(node.test) == 'network_csv_mode' and any(
                isinstance(child, ast.Assign) and any(isinstance(t, ast.Name) and t.id == 'network_scan_findings'
                for t in child.targets) for child in node.body))
        button = next(node for node in branch.body if isinstance(node, ast.If)
                      and 'open_network_csv_investigation' in ast.unparse(node.test))
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            raw = root / "evidence"
            cases = root / "cases"
            cases.mkdir()
            raw.mkdir()
            path = raw / "network.csv"
            data = b"proto,attack_cat\ntcp,Generic\n"
            path.write_bytes(data)
            digest = EvidenceIntegrity.calculate_sha256(path)
            finding = dict(id="ML-001", source="ml", model_name="XGBoost", checkpoint_split="random",
                           checkpoint_sha256="c" * 64, original_csv_record=1, sha256=digest)
            st = MagicMock()
            st.session_state = {}
            def persist(*args, **kwargs):
                kwargs['audit_logger'] = lambda c, a, d: EvidenceIntegrity.log_audit_trail(c, a, d,
                    audit_path=cases / f"{c}_audit.log")
                return add_scanned_evidence(*args, **kwargs)
            from datetime import datetime, timezone
            scope = dict(st=st, RAW_DIR=raw, CASES_DIR=cases, safe_name=path.name, upload_bytes=data,
                findings=[], yara_findings=[], ml_findings=[finding], case_id="CASE-N", datetime=datetime,
                timezone=timezone, add_scanned_evidence=persist, yara_to_report_findings=lambda f: f,
                sha256_hash=digest, Path=Path, file_path=str(path), _evidence_vault_id=lambda p: 1,
                scan_record_id=scan_record_id, navigate_to=Mock())
            exec(compile(ast.Module(body=[button], type_ignores=[]), 'dashboard/app.py', 'exec'), scope)
            st.error.assert_not_called()
            selected = st.session_state['selected_saved_evidence']
            saved = select_saved_scan(cases, digest, case_ids=['CASE-N'],
                                     scan_id=selected['historical_scan_id'], source_path=path)
            self.assertEqual(saved['findings'][0]['checkpoint_sha256'], 'c' * 64)
            self.assertEqual(saved['case_id'], 'CASE-N')
            self.assertEqual(saved['sha256'], digest)
            self.assertEqual(select_saved_scan(cases, digest, case_ids=['OTHER']), None)
            scope['navigate_to'].assert_called_once_with('Investigation')


class StreamlitSearchRerunTests(unittest.TestCase):
    def test_real_widgets_keep_selected_search_tab_and_results_after_rerun(self):
        from streamlit.testing.v1 import AppTest
        tree = ast.parse((ROOT / 'dashboard/app.py').read_text(encoding='utf-8'))
        tabs = next(node for node in tree.body if isinstance(node, ast.Assign)
                    and isinstance(node.value, ast.Call)
                    and isinstance(node.value.func, ast.Attribute) and node.value.func.attr == 'tabs')
        search = next(node for node in tree.body if isinstance(node, ast.With)
                      and ast.unparse(node.items[0].context_expr) == 'tab3')
        setup = '''
import streamlit as st
import pandas as pd
import modules.semantic_matcher as matcher
matcher._SENTENCE_TRANSFORMERS_AVAILABLE = False
from modules.semantic_search import prepare_evidence_search, search_evidence
df = pd.DataFrame({'proto': ['tcp', 'udp'], 'attack_cat': ['Generic', 'Normal']})
sha256_hash, case_id, safe_name = 'a' * 64, 'CASE-A', 'network.csv'
raw_df = None
SEMANTIC_SEARCH_MAX_RECORDS = 10000
def _render_technical_table(frame, key):
    st.dataframe(frame)
'''
        app = AppTest.from_string(setup + '\n' + ast.unparse(tabs) + '\n' + ast.unparse(search)).run()
        self.assertFalse(app.exception)
        app.session_state['investigation_workspace_tab'] = 'Search'
        app.text_input[0].set_value('Generic')
        app.button[0].click().run()
        self.assertFalse(app.exception)
        self.assertEqual(app.session_state['investigation_workspace_tab'], 'Search')
        first = app.session_state['investigation_search_result']
        self.assertEqual(len(first['matches']), 1)
        app.run()
        self.assertEqual(app.session_state['investigation_search_result']['key'], first['key'])
        self.assertEqual(app.session_state['investigation_workspace_tab'], 'Search')
        app.text_input[0].set_value('nonexistent').run()
        self.assertNotIn('investigation_search_result', app.session_state)


if __name__ == '__main__':
    unittest.main()
