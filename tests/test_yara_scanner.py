import io
import unittest
import zipfile

from modules.safety_checks import scan_embedded_content
from modules.yara_scanner import YARA_AVAILABLE, YaraScanner


@unittest.skipUnless(YARA_AVAILABLE, "yara-python is required")
class YaraContextTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.scanner = YaraScanner()

    def test_educational_docx_text_is_not_critical_and_has_safe_context(self):
        document = (
            b'<?xml version="1.0"?><w:document><w:t>'
            b'This report discusses Mimikatz, LSASS, sekurlsa::logonpasswords, '
            b'and lsadump::sam as forensic topics.'
            b'</w:t></w:document>'
        )
        findings = self.scanner.scan_bytes(
            document,
            "Project_Report_AI_Digital_Forensics.docx!word/document.xml",
        )

        finding = next(item for item in findings if item["rule"] == "Credential_Dumping_Tools")
        hits = {hit["string"]: hit for hit in finding["matches"]}
        self.assertEqual(set(hits), {"$m1", "$m2", "$m3", "$p2"})
        self.assertEqual(
            finding["matched_strings"],
            ["$m1", "$m2", "$m3", "$p2"],
        )
        self.assertEqual(finding["match_count"], 4)
        self.assertFalse(finding["matches_truncated"])
        self.assertEqual(finding["severity"], "Medium")
        self.assertEqual(finding["confidence"], "low")
        self.assertEqual(finding["content_type"], "document text")
        for identifier, value in (
            ("$m1", b"sekurlsa::logonpasswords"),
            ("$m2", b"lsadump::sam"),
            ("$m3", b"Mimikatz"),
            ("$p2", b"LSASS"),
        ):
            hit = hits[identifier]
            self.assertEqual(hit["offset"], document.index(value))
            self.assertIn(value.decode(), hit["context"])
            self.assertLessEqual(hit["context_start"], hit["offset"])
            self.assertGreaterEqual(hit["context_end"], hit["offset"] + len(value))

    def test_high_confidence_script_indicator_remains_critical(self):
        script = (
            b"Write-Output 'sekurlsa::logonpasswords'\n"
            b"Start-Process -FilePath 'controlled-demo.exe'\n"
        )
        findings = self.scanner.scan_bytes(script, "controlled-pattern.ps1")

        finding = next(item for item in findings if item["rule"] == "Credential_Dumping_Tools")
        self.assertEqual(finding["severity"], "Critical")
        self.assertEqual(finding["confidence"], "high")
        self.assertEqual(finding["content_type"], "script")

    def test_inert_script_reference_is_not_critical(self):
        script = b"Write-Output 'sekurlsa::logonpasswords'\n"
        findings = self.scanner.scan_bytes(script, "educational-reference.ps1")

        finding = next(item for item in findings if item["rule"] == "Credential_Dumping_Tools")
        self.assertEqual(finding["severity"], "High")

    def test_match_limit_keeps_all_identifiers_for_confidence(self):
        script = (
            (b"Mimikatz " * 25)
            + b"sekurlsa::logonpasswords\n"
            + b"Start-Process -FilePath 'controlled-demo.exe'"
        )
        findings = self.scanner.scan_bytes(script, "controlled-pattern.ps1")

        finding = next(item for item in findings if item["rule"] == "Credential_Dumping_Tools")
        self.assertEqual(finding["severity"], "Critical")
        self.assertEqual(finding["matched_strings"], ["$m1", "$m3"])
        self.assertEqual(finding["match_count"], 26)
        self.assertTrue(finding["matches_truncated"])

    def test_macro_member_is_distinguished_from_document_text(self):
        macro_content = b"sekurlsa::logonpasswords"
        findings = self.scanner.scan_bytes(
            macro_content,
            "controlled-pattern.docm!word/vbaProject.bin",
        )

        finding = next(item for item in findings if item["rule"] == "Credential_Dumping_Tools")
        self.assertEqual(finding["severity"], "High")
        self.assertEqual(finding["content_type"], "macro")

    def test_macro_with_execution_indicators_remains_critical(self):
        macro_content = b"AutoOpen CreateObject WScript.Shell sekurlsa::logonpasswords"
        findings = self.scanner.scan_bytes(
            macro_content,
            "controlled-pattern.docm!word/vbaProject.bin",
        )

        finding = next(item for item in findings if item["rule"] == "Credential_Dumping_Tools")
        self.assertEqual(finding["severity"], "Critical")
        self.assertEqual(finding["content_type"], "macro")

    def test_embedded_pe_content_is_distinguished_from_docx_text(self):
        executable = bytearray(128)
        executable[:2] = b"MZ"
        executable[0x3C:0x40] = (0x40).to_bytes(4, "little")
        executable[0x40:0x44] = b"PE\0\0"
        executable.extend(b"sekurlsa::logonpasswords")
        findings = self.scanner.scan_bytes(
            bytes(executable),
            "controlled-pattern.docx!word/embeddings/object.bin",
        )

        finding = next(item for item in findings if item["rule"] == "Credential_Dumping_Tools")
        self.assertEqual(finding["severity"], "Critical")
        self.assertEqual(finding["content_type"], "executable")

    def test_embedded_docx_document_member_is_scanned_with_member_offsets(self):
        xml = b'<w:document><w:t>Mimikatz is discussed for training.</w:t></w:document>'
        archive_data = io.BytesIO()
        with zipfile.ZipFile(archive_data, "w") as archive:
            archive.writestr("word/document.xml", xml)
            archive.writestr(
                "word/vbaProject.bin",
                b"AutoOpen CreateObject WScript.Shell sekurlsa::logonpasswords",
            )

        findings, warnings = scan_embedded_content(
            "training.docm",
            archive_data.getvalue(),
            self.scanner,
        )

        document_finding = next(
            item for item in findings if item["member"] == "word/document.xml"
        )
        macro_finding = next(
            item for item in findings if item["member"] == "word/vbaProject.bin"
        )
        self.assertEqual(warnings, [])
        self.assertEqual(document_finding["matches"][0]["offset"], xml.index(b"Mimikatz"))
        self.assertEqual(document_finding["content_type"], "document text")
        self.assertEqual(document_finding["severity"], "Medium")
        self.assertEqual(macro_finding["content_type"], "macro")
        self.assertEqual(macro_finding["severity"], "Critical")


if __name__ == "__main__":
    unittest.main()
