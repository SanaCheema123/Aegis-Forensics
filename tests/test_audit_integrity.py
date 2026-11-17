"""Audit trust gates, non-destructive failure handling, and process locking."""
import ast
from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import MagicMock, patch

from modules.evidence_reports import build_saved_evidence_report
from modules.integrity import AuditVerificationError, EvidenceIntegrity, audit_lock
from modules.scanned_evidence import add_scanned_evidence, load_scanned_evidence_records


ROOT = Path(__file__).resolve().parents[1]
CASE = "CASE-INTEGRITY"


class AuditIntegrityTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.cases = self.root / "cases"
        self.path = self.cases / f"{CASE}_audit.log"

    def append(self, action="TEST", details="original"):
        return EvidenceIntegrity.log_audit_trail(CASE, action, details, audit_path=self.path)

    def verify(self):
        return EvidenceIntegrity.verify_audit_trail(CASE, self.path)

    def write_lines(self, lines):
        self.path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    def evidence(self):
        data = b"original evidence bytes"
        finding = {"id": "F-001", "source": "Static heuristic", "rule": "Recorded check",
                   "severity": "Medium", "description": "Content needs review.",
                   "evidence": [{"file": "file.bin", "offset": 0}]}
        record = add_scanned_evidence(
            self.root / "raw_evidence", "file.bin", data, [finding], case_id=CASE,
            scanned_at_utc="2026-11-12T00:00:00Z", audit_log_path=self.path,
            audit_logger=lambda case, action, details: EvidenceIntegrity.log_audit_trail(
                case, action, details, audit_path=self.path),
        )
        return record, self.root / "raw_evidence" / record["stored_filename"]

    def test_valid_chain_verifies_and_appends_without_rewriting_prefix(self):
        first = self.append()
        original = self.path.read_bytes()
        second = self.append("SECOND")
        self.assertEqual(second["prev_hash"], first["entry_hash"])
        self.assertTrue(self.path.read_bytes().startswith(original))
        valid, message = self.verify()
        self.assertTrue(valid)
        self.assertIn("unanchored", message)

    def test_modified_entry_is_rejected_and_never_repaired_or_appended(self):
        self.append()
        self.path.write_text(self.path.read_text().replace("original", "modified"), encoding="utf-8")
        broken = self.path.read_bytes()
        self.assertFalse(self.verify()[0])
        with self.assertRaises(AuditVerificationError):
            self.append("AFTER_FAILURE")
        self.assertEqual(self.path.read_bytes(), broken)

    def test_missing_first_or_middle_entry_breaks_chain(self):
        for number in range(3):
            self.append(details=str(number))
        lines = self.path.read_text().splitlines()
        for missing in (0, 1):
            with self.subTest(missing=missing):
                self.write_lines([line for index, line in enumerate(lines) if index != missing])
                self.assertFalse(self.verify()[0])

    def test_tail_truncation_is_explicitly_not_proven_by_unanchored_chain(self):
        self.append()
        first = self.path.read_bytes()
        self.append("SECOND")
        self.path.write_bytes(first)
        valid, message = self.verify()
        self.assertTrue(valid)
        self.assertIn("truncation", message)

    def test_missing_empty_malformed_and_legacy_records_are_not_verified(self):
        self.assertFalse(self.verify()[0])
        self.cases.mkdir()
        for content in (b"", b"not json\n", b"[]\n",
                        json.dumps({"case_id": CASE, "action": "LEGACY"}).encode() + b"\n"):
            with self.subTest(content=content):
                self.path.write_bytes(content)
                self.assertFalse(self.verify()[0])
                with self.assertRaises((ValueError, OSError)):
                    self.append()
                self.assertEqual(self.path.read_bytes(), content)

    def test_case_mismatch_is_not_verified_even_with_valid_entry_hash(self):
        entry = self.append()
        entry["case_id"] = "OTHER-CASE"
        entry["entry_hash"] = EvidenceIntegrity._entry_hash(entry)
        self.write_lines([json.dumps(entry)])
        self.assertFalse(self.verify()[0])

    def test_valid_record_without_final_newline_remains_unchanged_on_append(self):
        self.append()
        original = self.path.read_bytes().rstrip(b"\n")
        self.path.write_bytes(original)
        self.append("SECOND")
        self.assertTrue(self.path.read_bytes().startswith(original))
        self.assertTrue(self.verify()[0])

    def test_concurrent_threads_produce_one_chain(self):
        with ThreadPoolExecutor(max_workers=8) as pool:
            list(pool.map(lambda number: self.append(details=str(number)), range(40)))
        self.assertTrue(self.verify()[0])
        entries = EvidenceIntegrity.read_verified_audit(CASE, self.path)
        self.assertEqual(len(entries), 40)
        self.assertEqual(len({entry["entry_hash"] for entry in entries}), 40)

    def test_concurrent_windows_processes_produce_one_chain(self):
        script = (
            "import sys\nfrom modules.integrity import EvidenceIntegrity\n"
            "for i in range(12):\n"
            " EvidenceIntegrity.log_audit_trail(sys.argv[2], 'PROCESS', "
            "sys.argv[3]+':'+str(i), audit_path=sys.argv[1])\n"
        )
        env = dict(os.environ, PYTHONPATH=str(ROOT), PYTHONDONTWRITEBYTECODE="1")
        processes = [subprocess.Popen(
            [sys.executable, "-B", "-c", script, str(self.path), CASE, str(number)],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=env,
        ) for number in range(4)]
        for process in processes:
            stdout, stderr = process.communicate(timeout=45)
            self.assertEqual(process.returncode, 0, stdout + stderr)
        entries = EvidenceIntegrity.read_verified_audit(CASE, self.path)
        self.assertEqual(len(entries), 48)
        self.assertEqual(len({entry["details"] for entry in entries}), 48)
        self.assertTrue(self.verify()[0])

    @unittest.skipUnless(os.name == "nt", "Windows byte-lock failure handling")
    def test_windows_lock_timeout_does_not_bypass_lock_or_change_log(self):
        self.append()
        original = self.path.read_bytes()
        with patch("msvcrt.locking", side_effect=OSError("busy")):
            with self.assertRaises(TimeoutError):
                with audit_lock(self.path, timeout=0.01):
                    self.fail("Must never enter without the lock")
        self.assertEqual(self.path.read_bytes(), original)

    def test_laptop_report_requires_hash_bound_scan_snapshot(self):
        report = {"case_id": CASE, "findings": [{"severity": "High", "path": "sample.bin"}]}
        self.append("LAPTOP_SCAN_COMPLETED", "legacy scan counters only")
        with self.assertRaisesRegex(AuditVerificationError, "unverified or legacy"):
            EvidenceIntegrity.require_scan_report(report, self.path)
        self.append("LAPTOP_SCAN_COMPLETED", f"scan; snapshot_sha256={EvidenceIntegrity.scan_snapshot_hash(report)}")
        EvidenceIntegrity.require_scan_report(report, self.path)
        report["findings"][0]["severity"] = "Low"
        with self.assertRaises(AuditVerificationError):
            EvidenceIntegrity.require_scan_report(report, self.path)

    def test_valid_saved_report_requires_verified_findings_and_matching_bytes(self):
        record, path = self.evidence()
        original_hash = EvidenceIntegrity.calculate_sha256(str(path))
        with patch.object(EvidenceIntegrity, "verify_audit_trail", wraps=EvidenceIntegrity.verify_audit_trail) as verify:
            report = build_saved_evidence_report(record, 1, path)
        self.assertTrue(verify.called)
        self.assertEqual(report["findings"][0]["id"], "F-001")
        self.assertEqual(EvidenceIntegrity.calculate_sha256(str(path)), original_hash)

    def test_tampered_chain_blocks_case_loading_and_report_before_model_initialization(self):
        record, path = self.evidence()
        self.path.write_text(self.path.read_text().replace("Content needs review", "Altered finding"), encoding="utf-8")
        broken = self.path.read_bytes()
        with self.assertRaises(AuditVerificationError):
            load_scanned_evidence_records(self.cases)
        with patch("modules.evidence_reports.LocalLLMReporter") as reporter:
            with self.assertRaises(AuditVerificationError):
                build_saved_evidence_report(record, 1, path)
            reporter.assert_not_called()
        self.assertEqual(self.path.read_bytes(), broken)
        self.assertEqual(path.read_bytes(), b"original evidence bytes")

    def test_detached_or_modified_session_findings_cannot_bypass_verification(self):
        record, path = self.evidence()
        altered = deepcopy(record)
        altered["findings"][0]["severity"] = "Critical"
        with self.assertRaisesRegex(AuditVerificationError, "Saved findings"):
            build_saved_evidence_report(altered, 1, path)

    def test_changed_evidence_bytes_block_report(self):
        record, path = self.evidence()
        path.write_bytes(b"changed test fixture")
        with self.assertRaisesRegex(AuditVerificationError, "SHA-256"):
            build_saved_evidence_report(record, 1, path)

    def test_changes_during_report_generation_are_rechecked(self):
        record, path = self.evidence()
        with patch("modules.evidence_reports.LocalLLMReporter") as reporter:
            reporter.return_value.generate_grounded_report.side_effect = lambda *args, **kwargs: (
                path.write_bytes(b"changed during generation") or "report")
            with self.assertRaises(AuditVerificationError):
                build_saved_evidence_report(record, 1, path)

    def test_invalid_case_can_be_excluded_only_with_explicit_warning(self):
        self.evidence()
        legacy = self.cases / "LEGACY_audit.log"
        legacy.write_text('{"case_id":"LEGACY","action":"OLD"}\n', encoding="utf-8")
        warnings = []
        records = load_scanned_evidence_records(self.cases, verification_warnings=warnings)
        self.assertEqual(len(records), 1)
        self.assertIn("Legacy", warnings[0])
        self.assertEqual(len(load_scanned_evidence_records(self.cases, case_ids=[CASE])), 1)

    def test_dashboard_report_guard_stops_before_generation_on_failed_chain(self):
        record, path = self.evidence()
        self.path.write_text(self.path.read_text().replace("Content needs review", "changed"), encoding="utf-8")
        tree = ast.parse((ROOT / "dashboard/app.py").read_text(encoding="utf-8"))
        button = next(node for node in ast.walk(tree) if isinstance(node, ast.If)
                      and isinstance(node.test, ast.Call)
                      and ast.unparse(node.test.func) == "st.button"
                      and node.test.args and isinstance(node.test.args[0], ast.Constant)
                      and node.test.args[0].value == "Generate report")
        guard = button.body[0]
        class Stopped(Exception):
            pass
        st = MagicMock()
        st.stop.side_effect = Stopped
        namespace = dict(st=st, EvidenceIntegrity=EvidenceIntegrity, case_id=CASE,
                         file_path=str(path), CASES_DIR=self.cases,
                         sha256_hash=record["sha256"], saved_scan_record=record)
        with self.assertRaises(Stopped):
            exec(compile(ast.Module(body=[guard], type_ignores=[]), "dashboard/app.py", "exec"), namespace)
        self.assertIn("Report generation blocked", st.warning.call_args.args[0])

    def test_changed_session_upload_cannot_be_registered_as_new_original(self):
        tree = ast.parse((ROOT / "dashboard/app.py").read_text(encoding="utf-8"))
        guard = next(node for node in tree.body if isinstance(node, ast.If)
                     and "hashlib.sha256(upload_bytes)" in ast.unparse(node.test))
        class Stopped(Exception):
            pass
        st = MagicMock()
        st.stop.side_effect = Stopped
        namespace = dict(st=st, selected_saved_path=None, sha256_hash="0" * 64,
                         hashlib=hashlib, upload_bytes=b"original upload")
        with self.assertRaises(Stopped):
            exec(compile(ast.Module(body=[guard], type_ignores=[]), "dashboard/app.py", "exec"), namespace)
        self.assertIn("No new integrity record", st.warning.call_args.args[0])

    def test_dashboard_does_not_trust_upload_text_embedded_in_unrelated_details(self):
        record, path = self.evidence()
        self.append("NOTE", f"File uploaded: fabricated.bin | SHA256: {'0' * 64}")
        tree = ast.parse((ROOT / "dashboard/app.py").read_text(encoding="utf-8"))
        functions = [node for node in tree.body if isinstance(node, ast.FunctionDef)
                     and node.name in {"recorded_hashes", "verify_file"}]
        st = MagicMock()
        st.session_state = {}
        namespace = dict(CASES_DIR=self.cases, EvidenceIntegrity=EvidenceIntegrity, st=st,
                         HASH_RE=re.compile(r"File uploaded: (.+?) \| SHA256: ([0-9a-fA-F]{64})"))
        exec(compile(ast.Module(body=functions, type_ignores=[]), "dashboard/app.py", "exec"), namespace)
        self.assertNotIn("fabricated.bin", namespace["recorded_hashes"]())
        namespace["verify_file"](path, [(record["sha256"], CASE)], "verified", record_audit=False)
        self.assertEqual(st.session_state["verified"]["status"], "verified")
        self.path.write_text(self.path.read_text().replace("original", "tampered"), encoding="utf-8")
        self.assertEqual(namespace["recorded_hashes"](), {})
        namespace["verify_file"](path, [(record["sha256"], CASE)], "verified", record_audit=False)
        self.assertNotEqual(st.session_state["verified"]["status"], "verified")
        st.warning.assert_called()


if __name__ == "__main__":
    unittest.main()
