import tempfile
import unittest
from pathlib import Path

from modules.laptop_scanner import analyze_file, scan_laptop


class FakeScanner:
    ready = True

    def __init__(self):
        self.scanned = []

    def scan_file(self, path, timeout=60):
        self.scanned.append(Path(path))
        return []


class LaptopScannerTests(unittest.TestCase):
    def test_static_script_review_reports_evidence_without_execution(self):
        scanner = FakeScanner()
        with tempfile.TemporaryDirectory() as directory:
            script = Path(directory) / "review.ps1"
            script.write_text(
                "Invoke-WebRequest -Uri 'https://example.invalid/file'\n",
                encoding="utf-8",
            )
            result = analyze_file(script, scanner)

        self.assertEqual(len(scanner.scanned), 1)
        self.assertEqual(result["path"], str(script))
        self.assertEqual(result["findings"][0]["severity"], "Medium")
        self.assertEqual(result["findings"][0]["sha256"], result["sha256"])
        self.assertEqual(result["findings"][0]["evidence"][0]["line"], 1)

    def test_scan_is_bounded_to_user_selected_root_and_file_limit(self):
        scanner = FakeScanner()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "one.ps1").write_text("Write-Output one", encoding="utf-8")
            (root / "two.ps1").write_text("Write-Output two", encoding="utf-8")
            report = scan_laptop(root, scanner, max_files=1)

        self.assertEqual(report["files_checked"], 1)
        self.assertTrue(report["limit_reached"])
        self.assertFalse(report["scan_complete"])
        self.assertIsNone(report["coverage_percent"])
        self.assertEqual(len(scanner.scanned), 1)

    def test_scan_reports_supported_coverage_and_unsupported_files(self):
        scanner = FakeScanner()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "review.ps1").write_text("Write-Output review", encoding="utf-8")
            (root / "notes.md").write_text("not supported", encoding="utf-8")
            report = scan_laptop(root, scanner)

        self.assertEqual(report["files_seen"], 2)
        self.assertEqual(report["supported_files_seen"], 1)
        self.assertEqual(report["unsupported_files"], 1)
        self.assertEqual(report["files_checked"], 1)
        self.assertEqual(report["files_skipped"], 1)
        self.assertEqual(report["coverage_percent"], 100.0)
        self.assertFalse(report["scan_complete"])

    def test_scan_limits_cannot_exceed_safe_hard_caps(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(ValueError):
                scan_laptop(directory, FakeScanner(), max_files=3001)
            with self.assertRaises(ValueError):
                scan_laptop(directory, FakeScanner(), max_file_size=50 * 1024 * 1024 + 1)
            with self.assertRaises(ValueError):
                scan_laptop(directory, FakeScanner(), max_seconds=15 * 60 + 1)

    def test_scan_rejects_missing_directory(self):
        with self.assertRaises(ValueError):
            scan_laptop("path-that-does-not-exist", FakeScanner())


if __name__ == "__main__":
    unittest.main()
