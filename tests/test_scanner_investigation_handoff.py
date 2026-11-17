"""Regression coverage for saved scanner evidence in the investigation workspace."""
import ast
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock

from modules.ai_reporter import LocalLLMReporter
from modules.integrity import EvidenceIntegrity
from modules.evidence_reports import (
    build_saved_evidence_report,
    merge_investigation_findings,
    saved_evidence_findings,
)
from modules.scanned_evidence import add_scanned_evidence, load_scanned_evidence_records


ROOT = Path(__file__).resolve().parents[1]
APP_TREE = ast.parse((ROOT / "dashboard/app.py").read_text(encoding="utf-8"))


def assignment(name):
    return next(node for node in APP_TREE.body if isinstance(node, ast.Assign)
                and any(isinstance(target, ast.Name) and target.id == name
                        for target in node.targets))


def execute(node, namespace):
    exec(compile(ast.Module(body=[node], type_ignores=[]), "dashboard/app.py", "exec"), namespace)


class ScannerInvestigationHandoffTests(unittest.TestCase):
    def persist(self, root, filename):
        data = b'timestamp,message\n2026-11-09T10:00:00Z,review\n'
        digest = hashlib.sha256(data).hexdigest()
        findings = [
            {"id": "Y-001", "source": "yara", "rule": "Saved signature",
             "severity": "High", "description": "Recorded signature match.",
             "sha256": digest, "evidence": [{"file": filename, "offset": 7}],
             "matches": [{"offset": 7, "identifier": "$marker"}]},
            {"id": "F-001", "source": "Static heuristic", "rule": "Saved content check",
             "severity": "Medium", "description": "Recorded content check.",
             "sha256": digest, "evidence": [{"file": filename, "page": 2}],
             "matches": [{"page": 2}], "container_sha256": digest},
        ]
        cases = root / "cases"
        cases.mkdir()
        audit = cases / "CASE-TEST_audit.log"

        def logger(case_id, action, details):
            return EvidenceIntegrity.log_audit_trail(case_id, action, details, audit_path=audit)

        record = add_scanned_evidence(
            root / "evidence", filename, data, findings + [deepcopy(findings[0])],
            case_id="CASE-TEST", scanned_at_utc="2026-11-09T10:00:00Z",
            audit_log_path=audit, audit_logger=logger,
        )
        loaded = load_scanned_evidence_records(cases, record["sha256"])[0]
        return loaded

    def test_file_evidence_displays_both_sources_and_reports_saved_metadata(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            record = self.persist(root, "sample.bin")
            original = deepcopy(record)
            saved = saved_evidence_findings(record)
            self.assertEqual([item["id"] for item in saved], ["Y-001", "F-001"])
            for expected, actual in zip(record["findings"], saved):
                for field in ("id", "sha256", "severity", "evidence", "matches"):
                    self.assertEqual(actual[field], expected[field])
            self.assertEqual(saved[1]["container_sha256"], record["sha256"])

            class Stopped(Exception):
                pass

            st = Mock()
            st.stop.side_effect = Stopped
            namespace = dict(is_log=False, st=st, yara_findings=[saved[0]],
                             saved_findings=saved, scanner=Mock(ready=False),
                             case_id="CASE-TEST", render_yara=Mock(),
                             _render_alert_collection=Mock())
            branch = next(node for node in APP_TREE.body if isinstance(node, ast.If)
                          and ast.unparse(node.test) == "not is_log")
            with self.assertRaises(Stopped):
                execute(branch, namespace)
            namespace["render_yara"].assert_called_once()
            self.assertEqual(namespace["_render_alert_collection"].call_args.args[0], [saved[1]])
            report = build_saved_evidence_report(record, 1, root / "evidence/sample.bin")
            self.assertEqual(len(report["findings"]), 2)
            self.assertIn("Saved content check", report["text"])
            self.assertIn("Saved signature", report["text"])
            self.assertIn("byte offset 7", report["text"])
            self.assertIn("page 2", report["text"])
            self.assertEqual(record, original)

    def test_log_report_merges_saved_and_new_findings_without_id_collisions(self):
        with tempfile.TemporaryDirectory() as temporary:
            record = self.persist(Path(temporary), "events.csv")
            saved = saved_evidence_findings(record)
            fresh = {"id": "F-001", "source": "rule", "rule": "Fresh log rule",
                     "mitre": "n/a",
                     "severity": "Low", "description": "Fresh log event.",
                     "first_seen": None, "last_seen": None,
                     "evidence": [{"file": "events.csv", "line": 2}]}
            ml = {**fresh, "id": "ML-001", "source": "ml", "rule": "ML review"}
            namespace = dict(saved_findings=saved, saved_scan_record=record,
                             findings=[fresh], yara_findings=[saved[0]], ml_findings=[ml],
                             merge_investigation_findings=merge_investigation_findings)
            execute(assignment("report_findings"), namespace)
            merged = namespace["report_findings"]
            self.assertEqual([item["id"] for item in merged],
                             ["Y-001", "F-001", "F-002", "ML-001"])
            self.assertEqual(merged[:2], saved)
            self.assertEqual(fresh["id"], "F-001")
            merged_rule_assignment = [
                node for node in APP_TREE.body if isinstance(node, ast.Assign)
                and any(isinstance(target, ast.Name) and target.id == "findings"
                        for target in node.targets)
            ][-1]
            execute(merged_rule_assignment, namespace)
            self.assertEqual([item["id"] for item in namespace["findings"]], ["F-002"])
            rules_tab = next(node for node in APP_TREE.body if isinstance(node, ast.With)
                             and ast.unparse(node.items[0].context_expr) == "tab5")
            static_assignment = next(node for node in rules_tab.body if isinstance(node, ast.Assign)
                                     and node.targets[0].id == "saved_static_findings")
            static_branch = next(node for node in rules_tab.body if isinstance(node, ast.If)
                                 and ast.unparse(node.test) == "saved_static_findings")
            namespace.update(_render_alert_collection=Mock(), case_id="CASE-TEST")
            execute(static_assignment, namespace)
            execute(static_branch, namespace)
            self.assertEqual(namespace["_render_alert_collection"].call_args.args[0], [saved[1]])
            reporter = LocalLLMReporter()
            report = reporter.generate_grounded_report("", "", findings=merged, use_llm=False)
            for finding_id in ("Y-001", "F-001", "F-002", "ML-001"):
                self.assertIn(finding_id, report)
            self.assertIn("Saved content check", report)
            self.assertEqual(len(reporter.last_report_findings), 4)

    def test_repeated_findings_are_deduplicated_but_distinct_references_remain(self):
        finding = {"id": "Y-001", "source": "yara", "rule": "Signature",
                   "sha256": "a" * 64, "file": "file.bin", "severity": "High",
                   "evidence": [{"file": "file.bin", "offset": 5}]}
        duplicate = {**finding, "rule": "YARA: Signature"}
        distinct = {**finding, "evidence": [{"file": "file.bin", "offset": 9}]}
        merged = merge_investigation_findings([finding], [duplicate, distinct])
        self.assertEqual(len(merged), 2)
        self.assertEqual(merged[0], finding)
        self.assertEqual(merged[1]["id"], "Y-002")
        self.assertEqual(merged[1]["evidence"], distinct["evidence"])


if __name__ == "__main__":
    unittest.main()
