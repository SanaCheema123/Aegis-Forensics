import ast
import hashlib
import json
import re
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from modules.alert_investigation import alert_file_details, promote_alert_to_evidence
from modules.evidence_reports import build_saved_evidence_report
from modules.integrity import EvidenceIntegrity
from modules.report_history import load_forensic_reports, save_forensic_report
from modules.scanned_evidence import (load_scanned_evidence_records, select_saved_scan,
    scan_record_id, invalidate_scan_session)
ROOT = Path(__file__).resolve().parents[1]
APP_PATH = ROOT / "dashboard" / "app.py"
APP_TREE = ast.parse(APP_PATH.read_text(encoding="utf-8"))
FIXTURE_PATH = ROOT / "tests" / "fixtures" / "aegis_yara_test.txt"
CASE_ID = "CASE-LIVE-ALERT-INVESTIGATION-TEST"
DETECTED_AT = "2026-11-10T07:00:00+00:00"
WRITE_AUDIT = EvidenceIntegrity.log_audit_trail


class LiveProtectionInvestigationTests(unittest.TestCase):
    def test_alert_confirmation_deduplicates_evidence_and_generates_a_grounded_report(self):
        source_bytes = FIXTURE_PATH.read_bytes()
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            original_path = root / FIXTURE_PATH.name
            original_path.write_bytes(source_bytes)
            digest = hashlib.sha256(source_bytes).hexdigest()
            alert = {
                "created_at_utc": DETECTED_AT,
                "severity": "Low",
                "source": "YARA",
                "message": "Created file: Harmless marker for validating YARA alert flow",
                "evidence": {
                    "path": str(original_path),
                    "sha256": digest,
                    "rule": "Aegis_Harmless_Test_Marker",
                    "evidence": [{
                        "line": 2,
                        "content": "AEGIS_YARA_TEST_MARKER_2026",
                    }],
                    "matched_strings": ["AEGIS_YARA_TEST_MARKER_2026"],
                    "matches": [],
                },
            }
            evidence_directory = root / "raw_evidence"
            cases_directory = root / "cases"
            cases_directory.mkdir()
            audit_path = cases_directory / f"{CASE_ID}_audit.log"
            audit_entries = []

            def audit_logger(case_id, action, details, **options):
                self.assertEqual(Path(options.get('audit_path', audit_path)), audit_path)
                entry = WRITE_AUDIT(case_id, action, details, audit_path=audit_path)
                audit_entries.append(entry)
                return entry

            filename, full_path, expected_hash = alert_file_details(alert)
            self.assertEqual(filename, FIXTURE_PATH.name)
            self.assertEqual(full_path, str(original_path))
            self.assertEqual(expected_hash, digest)

            saved = promote_alert_to_evidence(
                alert,
                original_path.read_bytes(),
                filename=filename,
                case_id=CASE_ID,
                evidence_directory=evidence_directory,
                audit_log_path=audit_path,
                audit_logger=audit_logger,
            )
            repeated = promote_alert_to_evidence(
                alert,
                original_path.read_bytes(),
                filename=filename,
                case_id=CASE_ID,
                evidence_directory=evidence_directory,
                audit_log_path=audit_path,
                audit_logger=audit_logger,
            )

            self.assertEqual(original_path.read_bytes(), source_bytes)
            self.assertEqual(saved["sha256"], digest)
            self.assertTrue(repeated["duplicate"])
            self.assertEqual(len(list(evidence_directory.iterdir())), 1)
            self.assertEqual(
                sum(entry["action"] == "SCANNED_EVIDENCE_ADDED" for entry in audit_entries),
                1,
            )
            linked_records = load_scanned_evidence_records(cases_directory, digest)
            self.assertEqual(len(linked_records), 1)
            linked_finding = linked_records[0]["findings"][0]
            self.assertEqual(linked_records[0]["case_id"], CASE_ID)
            self.assertEqual(linked_finding["rule"], "Aegis_Harmless_Test_Marker")
            self.assertEqual(linked_finding["severity"], "Low")
            self.assertEqual(linked_finding["scanned_at_utc"], DETECTED_AT)
            self.assertEqual(linked_finding["technical_record"], alert)

            workflow_nodes = [
                node for node in APP_TREE.body
                if isinstance(node, ast.FunctionDef)
                and node.name in {
                    "_section_page_key",
                    "_saved_scan_for_case",
                    "navigate_to",
                    "_apply_pending_navigation",
                    "_open_saved_evidence",
                    "recorded_hashes",
                    "_generate_saved_evidence_report",
                }
            ]
            class WidgetGuardState(dict):
                instantiated_widget_keys = set()

                def __setitem__(self, key, value):
                    if key in self.instantiated_widget_keys:
                        raise AssertionError(f"Cannot update instantiated widget state: {key}")
                    super().__setitem__(key, value)

            session_state = WidgetGuardState()
            session_state["site_subpage_investigations"] = "Evidence"
            session_state["pending_monitor_alert_investigation"] = {"stale_alert": True}
            session_state.instantiated_widget_keys.add("site_subpage_investigations")
            dashboard_state = SimpleNamespace(session_state=session_state)
            namespace = {
                "CASES_DIR": cases_directory,
                "DEFAULT_CASE_ID": CASE_ID,
                "HASH_RE": re.compile(r"File uploaded: (.+?) \| SHA256: ([0-9a-fA-F]{64})"),
                "EvidenceIntegrity": EvidenceIntegrity,
                "load_scanned_evidence_records": load_scanned_evidence_records,
                "select_saved_scan": select_saved_scan,
                "scan_record_id": scan_record_id,
                "invalidate_scan_session": invalidate_scan_session,
                "Path": Path,
                "re": re,
                "ui": SimpleNamespace(
                    NAVIGATION_DESTINATIONS={
                        "Investigation": ("Investigations", "Investigation"),
                    },
                    SECTION_PAGES={
                        "Investigations": ("Investigation", "Evidence"),
                    },
                ),
                "build_saved_evidence_report": build_saved_evidence_report,
                "save_forensic_report": save_forensic_report,
                "st": dashboard_state,
            }
            exec(
                compile(
                    ast.Module(body=workflow_nodes, type_ignores=[]),
                    str(APP_PATH),
                    "exec",
                ),
                namespace,
            )
            evidence_path = evidence_directory / saved["stored_filename"]
            namespace["_open_saved_evidence"](evidence_path, [CASE_ID], 15)
            self.assertEqual(session_state["site_subpage_investigations"], "Evidence")
            self.assertEqual(session_state["_pending_navigation"], ("Investigations", "Investigation"))
            self.assertEqual(session_state["selected_saved_evidence"]["evidence_id"], 15)
            self.assertEqual(session_state["selected_saved_evidence"]["case_id"], CASE_ID)
            self.assertEqual(session_state["selected_saved_evidence"]["sha256"], digest)
            self.assertNotIn("pending_monitor_alert_investigation", session_state)
            session_state.instantiated_widget_keys.clear()
            namespace["_apply_pending_navigation"]()
            self.assertEqual(session_state["site_subpage_investigations"], "Investigation")
            self.assertEqual(session_state["active_section"], "Investigations")
            self.assertEqual(
                dashboard_state.session_state["selected_saved_evidence"]["scan_record"]["findings"][0]["rule"],
                "Aegis_Harmless_Test_Marker",
            )
            history_path = root / "forensic_report_history.jsonl"
            with (
                patch("modules.report_history.REPORT_HISTORY_PATH", history_path),
                patch.object(EvidenceIntegrity, "log_audit_trail", audit_logger),
            ):
                report = namespace["_generate_saved_evidence_report"](
                    evidence_path,
                    15,
                    [CASE_ID],
                )
                archived = load_forensic_reports()
            self.assertEqual(len(archived), 1)
            self.assertEqual(archived[0]["case_id"], CASE_ID)
            self.assertEqual(archived[0]["evidence_id"], "15")
            self.assertEqual(archived[0]["filename"], FIXTURE_PATH.name)
            self.assertEqual(archived[0]["sha256"], digest)
            self.assertEqual(
                archived[0]["findings"][0]["yara_rule"],
                "Aegis_Harmless_Test_Marker",
            )

    def test_manual_upload_with_mismatched_alert_hash_is_not_added_as_evidence(self):
        alert = {
            "created_at_utc": DETECTED_AT,
            "severity": "Low",
            "source": "YARA",
            "message": "YARA match",
            "evidence": {
                "path": "C:/missing/aegis_ui_test.txt",
                "sha256": "0" * 64,
                "rule": "Aegis_Harmless_Test_Marker",
            },
        }
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            audit_path = root / "cases" / f"{CASE_ID}_audit.log"
            audit_path.parent.mkdir()
            with self.assertRaisesRegex(ValueError, "does not match"):
                promote_alert_to_evidence(
                    alert,
                    b"different contents",
                    filename="aegis_ui_test.txt",
                    case_id=CASE_ID,
                    evidence_directory=root / "raw_evidence",
                    audit_log_path=audit_path,
                    audit_logger=lambda *_: {},
                )
            self.assertFalse((root / "raw_evidence").exists())
            self.assertFalse(audit_path.exists())


if __name__ == "__main__":
    unittest.main()
