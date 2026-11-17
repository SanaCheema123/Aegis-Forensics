import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from modules.safety_checks import check_uploaded_file
from modules.integrity import EvidenceIntegrity
from modules.scanned_evidence import (
    add_scanned_evidence,
    evidence_matches_search,
    evidence_search_display_name,
    load_scanned_evidence_aliases,
    load_scanned_evidence_records,
)
from modules.yara_scanner import YARA_AVAILABLE, YaraScanner


FIXTURE_PATH = Path(__file__).parent / "fixtures" / "aegis_yara_test.txt"
CASE_ID = "CASE-SCANNED-EVIDENCE-TEST"
SECOND_CASE_ID = "CASE-SCANNED-EVIDENCE-SECOND"
SCAN_TIME = "2026-11-02T09:00:00+00:00"
WRITE_AUDIT = EvidenceIntegrity.log_audit_trail


@unittest.skipUnless(YARA_AVAILABLE, "yara-python is required")
class ScannedEvidenceTests(unittest.TestCase):
    def test_harmless_yara_detection_is_saved_linked_and_openable_from_the_vault(self):
        fixture_bytes = FIXTURE_PATH.read_bytes()
        scan = check_uploaded_file(
            FIXTURE_PATH.name,
            fixture_bytes,
            YaraScanner(),
        )
        finding = next(
            item
            for item in scan["findings"]
            if item["rule"] == "Aegis_Harmless_Test_Marker"
        )
        self.assertEqual(finding["severity"], "Low")

        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            evidence_directory = root / "raw_evidence"
            cases_directory = root / "cases"
            cases_directory.mkdir()
            audit_log_path = cases_directory / f"{CASE_ID}_audit.log"
            audit_entries = []

            def audit_logger(case_id, action, details):
                entry = WRITE_AUDIT(case_id, action, details, audit_path=audit_log_path)
                audit_entries.append(entry)
                return entry

            record = add_scanned_evidence(
                evidence_directory,
                FIXTURE_PATH.name,
                fixture_bytes,
                scan["findings"],
                case_id=CASE_ID,
                scanned_at_utc=SCAN_TIME,
                audit_log_path=audit_log_path,
                audit_logger=audit_logger,
            )

            self.assertEqual(record["original_filename"], FIXTURE_PATH.name)
            self.assertEqual(record["stored_filename"], FIXTURE_PATH.name)
            self.assertEqual(record["sha256"], hashlib.sha256(fixture_bytes).hexdigest())
            self.assertEqual(record["scanned_at_utc"], SCAN_TIME)
            self.assertEqual(record["case_id"], CASE_ID)
            self.assertEqual(record["evidence_id"], 1)
            self.assertEqual(len(record["findings"]), 1)
            linked_finding = record["findings"][0]
            self.assertEqual(linked_finding["rule"], finding["rule"])
            self.assertEqual(linked_finding["severity"], "Low")
            self.assertEqual(linked_finding["id"], finding["id"])
            self.assertEqual(linked_finding["source_filename"], FIXTURE_PATH.name)
            self.assertEqual(linked_finding["sha256"], record["sha256"])
            self.assertEqual(linked_finding["scanned_at_utc"], SCAN_TIME)
            self.assertEqual(linked_finding["matched_strings"], finding["matched_strings"])
            self.assertEqual(linked_finding["matches"], finding["matches"])

            stored_path = evidence_directory / record["stored_filename"]
            self.assertEqual(stored_path.read_bytes(), fixture_bytes)
            vault_records = load_scanned_evidence_records(
                cases_directory,
                record["sha256"],
            )
            self.assertEqual(len(vault_records), 1)
            self.assertEqual(vault_records[0]["findings"][0]["rule"], finding["rule"])
            self.assertEqual(vault_records[0]["evidence_id"], record["evidence_id"])

            repeated = add_scanned_evidence(
                evidence_directory,
                FIXTURE_PATH.name,
                fixture_bytes,
                scan["findings"],
                case_id=CASE_ID,
                scanned_at_utc=SCAN_TIME,
                audit_log_path=audit_log_path,
                audit_logger=audit_logger,
            )
            self.assertTrue(repeated["duplicate"])
            self.assertEqual(repeated["evidence_id"], record["evidence_id"])
            self.assertEqual(len(list(evidence_directory.iterdir())), 1)
            self.assertEqual(len(audit_entries), 2)

    def test_duplicate_sha_stays_searchable_after_refresh_and_verifies(self):
        fixture_bytes = FIXTURE_PATH.read_bytes()
        scan = check_uploaded_file(
            FIXTURE_PATH.name,
            fixture_bytes,
            YaraScanner(),
        )

        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            evidence_directory = root / "raw_evidence"
            cases_directory = root / "cases"
            cases_directory.mkdir()

            def audit_logger(case_id, action, details):
                audit_path = cases_directory / f"{case_id}_audit.log"
                return WRITE_AUDIT(case_id, action, details, audit_path=audit_path)

            first_audit_log_path = cases_directory / f"{CASE_ID}_audit.log"
            second_audit_log_path = cases_directory / f"{SECOND_CASE_ID}_audit.log"
            existing = add_scanned_evidence(
                evidence_directory,
                "aegis_ui_test.txt",
                fixture_bytes,
                scan["findings"],
                case_id=CASE_ID,
                scanned_at_utc=SCAN_TIME,
                audit_log_path=first_audit_log_path,
                audit_logger=audit_logger,
            )
            reused = add_scanned_evidence(
                evidence_directory,
                "harm.txt",
                fixture_bytes,
                scan["findings"],
                case_id=SECOND_CASE_ID,
                scanned_at_utc="2026-11-03T09:00:00+00:00",
                audit_log_path=second_audit_log_path,
                audit_logger=audit_logger,
            )

            self.assertTrue(reused["duplicate"])
            self.assertEqual(reused["stored_filename"], "aegis_ui_test.txt")
            self.assertEqual(reused["sha256"], existing["sha256"])
            self.assertEqual(len(list(evidence_directory.iterdir())), 1)

            aliases = load_scanned_evidence_aliases(cases_directory)
            self.assertIn("harm.txt", aliases["aegis_ui_test.txt"])
            self.assertTrue(
                evidence_matches_search(
                    "aegis_ui_test.txt",
                    aliases["aegis_ui_test.txt"],
                    SECOND_CASE_ID,
                    "harm.txt",
                )
            )
            self.assertEqual(
                evidence_search_display_name(
                    "aegis_ui_test.txt",
                    aliases["aegis_ui_test.txt"],
                    "harm.txt",
                ),
                "harm.txt",
            )

            refreshed_records = load_scanned_evidence_records(
                cases_directory,
                reused["sha256"],
            )
            self.assertEqual(len(refreshed_records), 2)
            self.assertEqual(
                {record["case_id"] for record in refreshed_records},
                {CASE_ID, SECOND_CASE_ID},
            )
            second_case_record = next(
                record for record in refreshed_records
                if record["case_id"] == SECOND_CASE_ID
            )
            saved_finding = second_case_record["findings"][0]
            self.assertEqual(saved_finding["case_id"], SECOND_CASE_ID)
            self.assertEqual(saved_finding["source_filename"], "harm.txt")
            self.assertEqual(saved_finding["sha256"], reused["sha256"])
            self.assertEqual(reused["evidence_id"], existing["evidence_id"])

            stored_path = evidence_directory / reused["stored_filename"]
            self.assertEqual(
                EvidenceIntegrity.calculate_sha256(str(stored_path)),
                reused["sha256"],
            )

            restart_check = """
import hashlib
import json
import sys
from pathlib import Path
from modules.scanned_evidence import load_scanned_evidence_aliases, load_scanned_evidence_records

cases_directory = Path(sys.argv[1])
evidence_directory = Path(sys.argv[2])
expected_hash = sys.argv[3]
records = load_scanned_evidence_records(cases_directory, expected_hash)
aliases = load_scanned_evidence_aliases(cases_directory)
record = next(item for item in records if item["case_id"] == sys.argv[4])
stored_path = evidence_directory / record["stored_filename"]
assert hashlib.sha256(stored_path.read_bytes()).hexdigest() == expected_hash
assert record["original_filename"] in aliases[record["stored_filename"]]
print(json.dumps({
    "evidence_id": record["evidence_id"],
    "case_id": record["case_id"],
    "original_filename": record["original_filename"],
    "sha256": record["sha256"],
    "finding_case_id": record["findings"][0]["case_id"],
}))
"""
            restart_result = subprocess.run(
                [
                    sys.executable,
                    "-c",
                    restart_check,
                    str(cases_directory),
                    str(evidence_directory),
                    reused["sha256"],
                    SECOND_CASE_ID,
                ],
                check=True,
                capture_output=True,
                text=True,
            )
            restarted = json.loads(restart_result.stdout)
            self.assertEqual(restarted["evidence_id"], existing["evidence_id"])
            self.assertEqual(restarted["case_id"], SECOND_CASE_ID)
            self.assertEqual(restarted["finding_case_id"], SECOND_CASE_ID)
            self.assertEqual(restarted["original_filename"], "harm.txt")
            self.assertEqual(restarted["sha256"], reused["sha256"])

    def test_different_sha256_is_saved_as_separate_evidence(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            evidence_directory = root / "raw_evidence"
            cases_directory = root / "cases"
            cases_directory.mkdir()
            audit_log_path = cases_directory / f"{CASE_ID}_audit.log"

            def audit_logger(case_id, action, details):
                return WRITE_AUDIT(case_id, action, details, audit_path=audit_log_path)

            first = add_scanned_evidence(
                evidence_directory,
                "same_name.txt",
                b"first content",
                [],
                case_id=CASE_ID,
                scanned_at_utc=SCAN_TIME,
                audit_log_path=audit_log_path,
                audit_logger=audit_logger,
            )
            second = add_scanned_evidence(
                evidence_directory,
                "same_name.txt",
                b"different content",
                [],
                case_id=CASE_ID,
                scanned_at_utc="2026-11-04T09:00:00+00:00",
                audit_log_path=audit_log_path,
                audit_logger=audit_logger,
            )

            self.assertFalse(second["duplicate"])
            self.assertNotEqual(first["sha256"], second["sha256"])
            self.assertNotEqual(first["stored_filename"], second["stored_filename"])
            self.assertEqual(
                EvidenceIntegrity.calculate_sha256(
                    str(evidence_directory / second["stored_filename"])
                ),
                second["sha256"],
            )


if __name__ == "__main__":
    unittest.main()
