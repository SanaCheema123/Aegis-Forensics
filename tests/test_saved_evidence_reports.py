import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from io import BytesIO

from pypdf import PdfReader

from modules.evidence_reports import build_saved_evidence_report
from modules.integrity import EvidenceIntegrity
from modules.pdf_report import render_forensic_pdf
from modules.report_history import load_forensic_reports, save_forensic_report
from modules.safety_checks import check_uploaded_file
from modules.scanned_evidence import add_scanned_evidence, load_scanned_evidence_records
from modules.yara_scanner import YARA_AVAILABLE, YaraScanner


ROOT = Path(__file__).resolve().parents[1]
FIXTURE_PATH = ROOT / "tests" / "fixtures" / "aegis_yara_test.txt"
CASE_ID = "CASE-SAVED-EVIDENCE-REPORT-TEST"
SCANNED_AT = "2026-11-09T09:00:37.046031+00:00"
GENERATED_AT = "2026-11-09T10:00:00+00:00"


@unittest.skipUnless(YARA_AVAILABLE, "yara-python is required")
class SavedEvidenceReportTests(unittest.TestCase):
    def test_saved_yara_evidence_generates_and_archives_grounded_markdown_and_pdf(self):
        evidence_bytes = FIXTURE_PATH.read_bytes()
        scan = check_uploaded_file(FIXTURE_PATH.name, evidence_bytes, YaraScanner())
        finding = next(
            item for item in scan["findings"]
            if item["rule"] == "Aegis_Harmless_Test_Marker"
        )

        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            evidence_directory = root / "raw_evidence"
            cases_directory = root / "cases"
            cases_directory.mkdir()
            audit_path = cases_directory / f"{CASE_ID}_audit.log"

            def audit_logger(case_id, action, details):
                return EvidenceIntegrity.log_audit_trail(case_id, action, details, audit_path=audit_path)

            saved = add_scanned_evidence(
                evidence_directory,
                FIXTURE_PATH.name,
                evidence_bytes,
                [finding],
                case_id=CASE_ID,
                scanned_at_utc=SCANNED_AT,
                audit_log_path=audit_path,
                audit_logger=audit_logger,
            )
            linked = load_scanned_evidence_records(cases_directory, saved["sha256"])
            self.assertEqual(len(linked), 1)

            report = build_saved_evidence_report(
                linked[0],
                14,
                evidence_directory / saved["stored_filename"],
                generated_at_utc=GENERATED_AT,
            )
            history_path = root / "forensic_report_history.jsonl"
            with patch("modules.report_history.REPORT_HISTORY_PATH", history_path):
                save_forensic_report(report)
                archived = load_forensic_reports()

            self.assertEqual(len(archived), 1)
            archived_report = archived[0]
            self.assertEqual(archived_report["case_id"], CASE_ID)
            self.assertEqual(archived_report["evidence_id"], "14")
            self.assertEqual(archived_report["filename"], FIXTURE_PATH.name)
            self.assertEqual(archived_report["sha256"], saved["sha256"])
            self.assertEqual(archived_report["scanned_at_utc"], SCANNED_AT)
            self.assertTrue(archived_report["validation"]["passed"])
            self.assertEqual(len(archived_report["findings"]), 1)
            self.assertEqual(archived_report["findings"][0]["id"], finding["id"])
            self.assertEqual(archived_report["findings"][0]["severity"], "Low")
            self.assertEqual(
                archived_report["findings"][0]["yara_rule"],
                "Aegis_Harmless_Test_Marker",
            )
            self.assertIn("Aegis_Harmless_Test_Marker", archived_report["text"])
            self.assertIn("Evidence ID: 14", archived_report["text"])
            self.assertIn(FIXTURE_PATH.name, archived_report["text"])
            self.assertIn(SCANNED_AT, archived_report["text"])
            self.assertIn("does not prove that the file is unsafe", archived_report["text"])

            pdf_bytes = render_forensic_pdf(archived_report)
            extracted = "\n".join(
                page.extract_text() or ""
                for page in PdfReader(BytesIO(pdf_bytes)).pages
            )
            self.assertIn("Evidence ID", extracted)
            self.assertIn("14", extracted)
            self.assertIn(FIXTURE_PATH.name, extracted)
            self.assertIn("Aegis_Harmless_Test_Marker", extracted)
            self.assertIn("Low", extracted)
            self.assertIn(SCANNED_AT, extracted)
            self.assertIn("does not prove that the file is unsafe", extracted)


if __name__ == "__main__":
    unittest.main()
