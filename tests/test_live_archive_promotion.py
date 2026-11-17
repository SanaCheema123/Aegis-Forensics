"""Archive identity must survive scanning, live alerts, and evidence promotion."""
import ast
from copy import deepcopy
import hashlib
import html
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import MagicMock, Mock, patch
import zipfile

from modules.alert_investigation import alert_file_details, alert_identity, promote_alert_to_evidence
from modules.evidence_reports import build_saved_evidence_report
from modules.integrity import EvidenceIntegrity
from modules.realtime_monitor import RealtimeMonitor
from modules.scanned_evidence import load_scanned_evidence_records


ROOT = Path(__file__).resolve().parents[1]
PAYLOAD = b'Write-Output "test marker"\n'
MEMBER = "scripts/member.ps1"


def archive_bytes():
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr(MEMBER, PAYLOAD)
    return buffer.getvalue()


class MemberScanner:
    ready = True

    def scan_file(self, path, timeout=60):
        return []

    def scan_bytes(self, data, name, timeout=5):
        return [{
            "id": "Y-001", "rule": "Archive_Test_Marker", "severity": "High",
            "description": "Embedded test marker.", "file": name,
            "sha256": hashlib.sha256(data).hexdigest(),
            "matches": [{"line": 1, "offset": 0, "string": "$marker"}],
            "matched_strings": ["$marker"], "confidence": "test confidence",
            "mitre": "T1059", "custom_metadata": "retained",
        }]


class LiveArchivePromotionTests(unittest.TestCase):
    def make_alert(self, root):
        path = root / "archive!original.zip"
        data = archive_bytes()
        path.write_bytes(data)
        monitor = RealtimeMonitor([root], MemberScanner())
        with patch("modules.realtime_monitor.time.sleep"):
            monitor._scan_changed_file(str(path), "created")
        alerts = monitor.snapshot()["alerts"]
        alert = next(item for item in alerts if item["source"] == "YARA")
        return path, data, alert

    def promote(self, root, alert, data):
        cases = root / "cases"
        cases.mkdir(exist_ok=True)
        audit = cases / "CASE-ARCHIVE_audit.log"

        def logger(case_id, action, details):
            return EvidenceIntegrity.log_audit_trail(case_id, action, details, audit_path=audit)

        return promote_alert_to_evidence(
            alert, data, filename=alert_file_details(alert)[0], case_id="CASE-ARCHIVE",
            evidence_directory=root / "evidence", audit_log_path=audit, audit_logger=logger,
        )

    def test_zip_member_alert_preserves_container_and_member_identities(self):
        with tempfile.TemporaryDirectory() as directory:
            path, data, alert = self.make_alert(Path(directory))
            evidence = alert["evidence"]
            self.assertEqual(evidence["path"], f"{path}!{MEMBER}")
            self.assertEqual(evidence["member_path"], evidence["path"])
            self.assertEqual(evidence["container_path"], str(path))
            self.assertEqual(evidence["sha256"], hashlib.sha256(PAYLOAD).hexdigest())
            self.assertEqual(evidence["member_sha256"], evidence["sha256"])
            self.assertEqual(evidence["container_sha256"], hashlib.sha256(data).hexdigest())
            self.assertEqual(evidence["custom_metadata"], "retained")
            self.assertEqual(evidence["matches"][0]["offset"], 0)
            self.assertEqual(alert_file_details(alert),
                             (path.name, str(path), hashlib.sha256(data).hexdigest()))

    def test_original_archive_promotes_and_retains_metadata_without_rewriting_history(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path, data, alert = self.make_alert(root)
            original_alert = deepcopy(alert)
            cases = root / "cases"
            cases.mkdir()
            audit = cases / "CASE-ARCHIVE_audit.log"
            EvidenceIntegrity.log_audit_trail("CASE-ARCHIVE", "EXISTING_HISTORY", "keep", audit_path=audit)
            prior_history = audit.read_text(encoding="utf-8")
            saved = self.promote(root, alert, data)
            finding = saved["findings"][0]
            self.assertEqual((root / "evidence" / saved["stored_filename"]).read_bytes(), data)
            self.assertEqual(saved["sha256"], hashlib.sha256(data).hexdigest())
            self.assertEqual(finding["container_sha256"], saved["sha256"])
            self.assertEqual(finding["member_sha256"], hashlib.sha256(PAYLOAD).hexdigest())
            self.assertEqual(finding["member_path"], f"{path}!{MEMBER}")
            self.assertEqual(finding["evidence"][0]["file"], f"{path}!{MEMBER}")
            self.assertEqual(finding["matches"], alert["evidence"]["matches"])
            self.assertEqual(finding["severity"], "High")
            self.assertEqual(finding["custom_metadata"], "retained")
            self.assertEqual(finding["technical_record"], alert)
            self.assertEqual(finding["id"], f"MON-{alert_identity(alert)}")
            self.assertEqual(alert, original_alert)
            self.assertTrue(audit.read_text(encoding="utf-8").startswith(prior_history))
            repeated = self.promote(root, alert, data)
            self.assertTrue(repeated["duplicate"])
            self.assertEqual(len(load_scanned_evidence_records(cases)), 1)
            report = build_saved_evidence_report(saved, 1, root / "evidence" / saved["stored_filename"])
            self.assertEqual(report["findings"][0]["member_sha256"], finding["member_sha256"])
            self.assertIn(MEMBER, report["text"])
            self.assertEqual(path.read_bytes(), data)

    def test_container_hash_mismatch_does_not_write_evidence_or_history(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _, data, alert = self.make_alert(root)
            with self.assertRaisesRegex(ValueError, "does not match"):
                self.promote(root, alert, data + b"changed")
            self.assertFalse((root / "evidence").exists())
            self.assertFalse((root / "cases/CASE-ARCHIVE_audit.log").exists())

    def test_member_hash_mismatch_does_not_write_evidence_or_history(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _, data, alert = self.make_alert(root)
            alert["evidence"]["member_sha256"] = "0" * 64
            with self.assertRaisesRegex(ValueError, "embedded member does not match"):
                self.promote(root, alert, data)
            self.assertFalse((root / "evidence").exists())
            self.assertFalse((root / "cases/CASE-ARCHIVE_audit.log").exists())

    def test_missing_archive_disables_original_action_but_accepts_verified_manual_copy(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path, data, alert = self.make_alert(root)
            path.unlink()  # Only the temporary fixture, never project evidence.
            source = (ROOT / "dashboard/app.py").read_text(encoding="utf-8")
            renderer = next(node for node in ast.parse(source).body
                            if isinstance(node, ast.FunctionDef)
                            and node.name == "_render_pending_monitor_alert_investigation")
            st = MagicMock()
            actions = [Mock(), Mock()]
            for action in actions:
                action.button.return_value = False
            st.columns.return_value = actions
            st.button.return_value = False
            st.file_uploader.return_value = None
            save = Mock()
            namespace = dict(st=st, html=html, Path=Path, CASES_DIR=root / "cases",
                             DEFAULT_CASE_ID="CASE-ARCHIVE", LOG_EXT=(".txt",), BINARY_EXT=(".zip",),
                             alert_file_details=alert_file_details, alert_identity=alert_identity,
                             _save_pending_monitor_alert=save)
            exec(compile(ast.Module(body=[renderer], type_ignores=[]), "dashboard/app.py", "exec"), namespace)
            namespace[renderer.name](alert)
            self.assertTrue(actions[0].button.call_args.kwargs["disabled"])
            self.assertTrue(any("missing or inaccessible" in str(call)
                                for call in st.error.call_args_list))
            save.assert_not_called()
            self.assertFalse((root / "evidence").exists())
            saved = self.promote(root, alert, data)
            self.assertEqual(saved["sha256"], hashlib.sha256(data).hexdigest())

    def test_legacy_virtual_path_with_container_hash_is_supported(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path, data, alert = self.make_alert(root)
            for field in ("container_path", "member_path", "member", "member_sha256"):
                alert["evidence"].pop(field)
            self.assertEqual(alert_file_details(alert)[1], str(path))
            self.assertEqual(self.promote(root, alert, data)["findings"][0]["member"], MEMBER)

    def test_legacy_alert_without_container_hash_requires_rescan(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _, data, alert = self.make_alert(root)
            alert["evidence"].pop("container_sha256")
            self.assertIsNone(alert_file_details(alert)[2])
            with self.assertRaisesRegex(ValueError, "no container SHA-256"):
                self.promote(root, alert, data)
            self.assertFalse((root / "evidence").exists())


if __name__ == "__main__":
    unittest.main()
