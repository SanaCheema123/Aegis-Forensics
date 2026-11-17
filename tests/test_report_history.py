import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from modules.report_history import load_forensic_reports, save_forensic_report


class ReportHistoryTests(unittest.TestCase):
    def test_reports_are_appended_and_loaded_newest_first(self):
        with tempfile.TemporaryDirectory() as directory:
            history_path = Path(directory) / "reports.jsonl"
            with patch("modules.report_history.REPORT_HISTORY_PATH", history_path):
                save_forensic_report({"case_id": "CASE-1", "text": "first"})
                save_forensic_report({"case_id": "CASE-2", "text": "second"})
                reports = load_forensic_reports()

        self.assertEqual([report["case_id"] for report in reports], ["CASE-2", "CASE-1"])


if __name__ == "__main__":
    unittest.main()
