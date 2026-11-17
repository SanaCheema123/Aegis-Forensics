import re
import unittest
from io import BytesIO

from pypdf import PdfReader
from modules.pdf_report import render_forensic_pdf


class ForensicPdfReportTests(unittest.TestCase):
    def test_pdf_contains_evidence_metadata_findings_events_and_audit_fields(self):
        report = {
            "case_id": "CASE-TEST-1",
            "generated_at_utc": "2026-11-02T10:00:00+00:00",
            "investigation_started_at_utc": "2026-11-02T09:00:00+00:00",
            "investigation_completed_at_utc": "2026-11-02T09:30:00+00:00",
            "source_paths": ["data/raw_evidence/sample.csv"],
            "sha256": "a" * 64,
            "findings": [{
                "id": "F-001",
                "severity": "High",
                "source": "rule",
                "rule": "Failed logins",
                "description": "Résumé review: repeated failed logins were found.",
                "file": "sample.csv",
                "sha256": "b" * 64,
                "evidence": [{"file": "sample.csv", "page": 4}],
            }],
            "finding_summary": {
                "total_findings": 1000,
                "severity_counts": {"Medium": 1000},
                "source_counts": {"ml": 1000},
                "representative_count": 25,
                "omitted_count": 975,
            },
            "windows_event_references": [{
                "log": "Security",
                "event_id": 4625,
                "record_id": 42,
                "time_utc": "2026-11-02T09:10:00+00:00",
                "finding_id": "F-001",
            }],
            "limitations": ["This is a test; indicators are not proof of compromise."],
            "audit_trail": [{
                "timestamp": "2026-11-02T09:31:00+00:00",
                "action": "AI_REPORT_GENERATED",
                "entry_hash": "c" * 64,
                "prev_hash": "d" * 64,
            }],
            "text": "## Technical Findings\nF-001: Repeated failed logins.",
        }

        result = render_forensic_pdf(report, draft=True)

        self.assertTrue(result.startswith(b"%PDF-"))
        self.assertIn(b"%%EOF", result)
        extracted = "\n".join(
            page.extract_text() or ""
            for page in PdfReader(BytesIO(result)).pages
        )
        normalized = re.sub(r"\s+", " ", extracted)
        self.assertIn("Résumé review", extracted)
        self.assertIn("page 4", extracted)
        self.assertIn("Windows event references", extracted)
        self.assertIn("Limitations and uncertainty", extracted)
        self.assertIn("Audit trail", extracted)
        self.assertIn("Previous hash", extracted)
        self.assertIn("Total findings: 1000", normalized)
        self.assertIn("omitted from bounded report: 975", normalized)

    def test_large_report_wraps_long_paths_and_spans_pages(self):
        long_path = "C:\\evidence\\" + ("nested\\" * 80) + "artifact.pdf"
        report = {
            "case_id": "CASE-LARGE-1",
            "source_paths": [long_path],
            "findings": [{
                "id": f"F-{index:03d}",
                "severity": "Medium",
                "source": "Static heuristic",
                "rule": "Static content indicator",
                "description": "Review this finding without opening the evidence.",
                "file": long_path,
                "sha256": "a" * 64,
                "evidence": [{"file": long_path, "page": 1}],
            } for index in range(120)],
        }

        result = render_forensic_pdf(report, draft=True)
        reader = PdfReader(BytesIO(result))
        extracted = "\n".join(page.extract_text() or "" for page in reader.pages)

        self.assertGreater(len(reader.pages), 1)
        self.assertIn("F-119", extracted)
        self.assertIn("artifact.pdf", extracted)


if __name__ == "__main__":
    unittest.main()
