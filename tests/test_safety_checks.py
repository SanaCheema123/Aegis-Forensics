import io
import tempfile
import unittest
import zipfile
from pathlib import Path

from pypdf import PdfReader, PdfWriter
from pypdf.generic import NameObject
from reportlab.pdfgen import canvas

from modules.safety_checks import (
    check_uploaded_file,
    inspect_pdf_content,
    inspect_url,
    scan_local_folder,
)


class FakeScanner:
    ready = True

    def __init__(self):
        self.scanned = []

    def scan_file(self, path, timeout=60):
        self.scanned.append(Path(path).name)
        return []

    def scan_bytes(self, data, name, timeout=10):
        if b"embedded-indicator" not in data:
            return []
        return [{
            "id": "Y-001",
            "severity": "High",
            "rule": "Embedded_Test",
            "description": "Test indicator in embedded content",
            "mitre": "n/a",
            "tags": [],
            "file": name,
            "sha256": "embedded",
            "matches": [{"offset": 0, "line": 1, "string": "$test"}],
        }]


class UnavailableScanner(FakeScanner):
    ready = False


class SafetyCheckTests(unittest.TestCase):
    def test_url_check_uses_indicator_verdict_without_claiming_reputation(self):
        result = inspect_url("https://example.com/page")
        self.assertEqual(result["status"], "no_obvious_flags")
        self.assertEqual(result["signals"], [])
        self.assertEqual(result["verdict"], "Safe Indicators")
        shortened = inspect_url("https://bit.ly/abc")
        self.assertEqual(shortened["status"], "review")
        self.assertEqual(shortened["verdict"], "Suspicious Indicators")

    def test_url_rejects_non_http_schemes(self):
        self.assertEqual(inspect_url("javascript:alert(1)")["status"], "invalid")

    def test_image_extension_mismatch_is_flagged_and_scanned(self):
        scanner = FakeScanner()
        result = check_uploaded_file("photo.png", b"MZnot-an-image", scanner)
        self.assertTrue(result["signals"])
        self.assertEqual(result["verdict"], "Suspicious Indicators")
        self.assertEqual(len(result["sha256"]), 64)
        self.assertEqual(len(scanner.scanned), 1)

    def test_executable_signature_with_text_extension_is_flagged(self):
        result = check_uploaded_file("notes.txt", b"MZnot-a-real-program", FakeScanner())
        self.assertEqual(result["verdict"], "Suspicious Indicators")
        self.assertTrue(any("non-executable" in signal for signal in result["signals"]))

    def test_script_upload_keeps_static_evidence_when_yara_is_unavailable(self):
        result = check_uploaded_file(
            "review.ps1",
            b"Write-Output 'start'\nInvoke-WebRequest -Uri 'https://example.invalid/file'",
            UnavailableScanner(),
        )
        self.assertEqual(result["verdict"], "Suspicious Indicators")
        self.assertFalse(result["scanner_ready"])
        self.assertEqual(result["heuristic_findings"][0]["evidence"][0]["line"], 2)

    def test_unrecognized_upload_remains_unknown_without_rule_matches(self):
        result = check_uploaded_file("sample.bin", b"unclassified data", FakeScanner())
        self.assertEqual(result["verdict"], "Unknown")

    def test_uploaded_archive_scans_embedded_content_without_extracting(self):
        archive_data = io.BytesIO()
        with zipfile.ZipFile(archive_data, "w") as archive:
            archive.writestr("folder/embedded.txt", "embedded-indicator")
        result = check_uploaded_file("evidence.zip", archive_data.getvalue(), FakeScanner())

        self.assertEqual(result["verdict"], "Suspicious Indicators")
        self.assertEqual(len(result["findings"]), 1)
        self.assertIn("embedded.txt", result["findings"][0]["file"])

    def test_pdf_static_markers_and_extracted_text_are_reported_with_page_evidence(self):
        rendered = io.BytesIO()
        document_canvas = canvas.Canvas(rendered)
        document_canvas.drawString(20, 100, "Invoke-WebRequest")
        document_canvas.save()
        source = PdfReader(io.BytesIO(rendered.getvalue()))
        writer = PdfWriter()
        writer.append(source)
        writer.pages[0][NameObject("/OpenAction")] = NameObject("/JavaScript")
        document = io.BytesIO()
        writer.write(document)

        indicators, warnings = inspect_pdf_content(document.getvalue())

        self.assertFalse(warnings)
        self.assertTrue(any("action marker" in item["description"] for item in indicators))
        self.assertTrue(any(item.get("page") == 1 for item in indicators))
        self.assertTrue(all("not proof" in item["description"] for item in indicators))
        self.assertTrue(any("network-download indicator" in item["description"] for item in indicators))

    def test_folder_scan_checks_supported_files_only(self):
        scanner = FakeScanner()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "sample.ps1").write_text(
                "Write-Output test\nInvoke-WebRequest -Uri 'https://example.invalid/file'",
                encoding="utf-8",
            )
            (root / "notes.md").write_text("not scanned", encoding="utf-8")
            result = scan_local_folder(root, scanner)
        self.assertEqual(result["checked"], 1)
        self.assertEqual(result["findings"][0]["source"], "Static heuristic")
        self.assertEqual(result["findings"][0]["evidence"][0]["file"], str(root / "sample.ps1"))
        self.assertEqual(len(scanner.scanned), 1)


if __name__ == "__main__":
    unittest.main()
