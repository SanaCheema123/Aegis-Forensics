import ast
import re
import unittest
from pathlib import Path
from unittest.mock import Mock

import pandas as pd

from modules.ai_reporter import (
    LocalLLMReporter,
    ml_to_report_findings,
    validate_report,
    yara_to_report_findings,
)


ROOT = Path(__file__).resolve().parents[1]
APP_SOURCE = (ROOT / "dashboard" / "app.py").read_text(encoding="utf-8")
APP_TREE = ast.parse(APP_SOURCE)


def build_rows(count):
    source_rows = pd.DataFrame({
        "line_no": range(2, count + 2),
        "flow_id": range(1000, 1000 + count),
    })
    anomalies = pd.DataFrame({
        "anomaly_score": [-1] * count,
        "ml_score": [0.91 - index / (count * 100) for index in range(count)],
        "ml_model": ["trained_xgboost"] * count,
    }, index=source_rows.index)
    return source_rows, anomalies


class InvestigationReportMLTests(unittest.TestCase):
    def test_ml_only_findings_enable_report_and_cite_real_rows(self):
        source_rows, anomalies = build_rows(1)
        ml_findings = ml_to_report_findings(
            anomalies,
            source_rows,
            "trained_xgboost",
            "official",
            "network_flows.csv",
            "a" * 64,
        )
        report_findings = ml_findings
        reporter = LocalLLMReporter()
        report = reporter.generate_grounded_report(
            "",
            "",
            findings=report_findings,
            use_llm=False,
        )

        self.assertTrue(report_findings)
        self.assertIn("Generate report", APP_SOURCE)
        self.assertIn("disabled=not report_findings", APP_SOURCE)
        report_assignment = next(
            node for node in APP_TREE.body
            if isinstance(node, ast.Assign)
            and any(
                isinstance(target, ast.Name) and target.id == "report_findings"
                for target in node.targets
            )
        )
        self.assertIn(
            "ml_findings",
            {node.id for node in ast.walk(report_assignment.value) if isinstance(node, ast.Name)},
        )
        self.assertIn("ML-001", report)
        self.assertIn("network_flows.csv, line 2", report)
        self.assertIn("official", report)
        self.assertTrue(reporter.last_validation["passed"])

    def test_no_findings_leave_report_generation_disabled(self):
        report_findings = []

        self.assertFalse(report_findings)
        self.assertIn("disabled=not report_findings", APP_SOURCE)
        reporter = LocalLLMReporter()
        self.assertIn(
            "No evidence-linked rule, YARA, or ML findings",
            reporter.generate_grounded_report("", "", findings=report_findings),
        )
        self.assertEqual(reporter.last_mode, "no_findings")

    def test_ml_row_references_must_exist_in_source_csv(self):
        source_rows, anomalies = build_rows(1)
        anomaly = anomalies.copy()
        anomaly.index = [55]

        with self.assertRaisesRegex(ValueError, "not present in the source evidence"):
            ml_to_report_findings(
                anomaly,
                source_rows,
                "trained_xgboost",
                "random",
                "network_flows.csv",
                "b" * 64,
            )

    def test_report_citations_and_evidence_point_to_converted_records(self):
        source_rows, anomalies = build_rows(2)
        findings = ml_to_report_findings(
            anomalies,
            source_rows,
            "trained_xgboost",
            "random",
            "network_flows.csv",
            "c" * 64,
        )
        reporter = LocalLLMReporter()
        report = reporter.generate_grounded_report("", "", findings=findings, use_llm=False)
        citation_ids = set(re.findall(r"\[(ML-\d{3,})\]", report))

        self.assertEqual([finding["id"] for finding in findings], ["ML-001", "ML-002"])
        self.assertTrue(citation_ids.issubset({finding["id"] for finding in findings}))
        self.assertTrue(reporter.last_validation["passed"])
        for finding in findings:
            self.assertEqual(finding["evidence"], [{
                "file": "network_flows.csv",
                "line": finding["original_csv_line"],
                "sha256": "c" * 64,
            }])
            self.assertEqual(finding["sha256"], "c" * 64)
            self.assertIn("not confirmation of malicious activity", finding["description"])

    def test_existing_rule_and_yara_findings_remain_in_report(self):
        rule_finding = {
            "id": "F-001",
            "severity": "High",
            "rule": "Failed logins",
            "source": "rule",
            "mitre": "T1110",
            "first_seen": "2026-11-02T09:00:00Z",
            "last_seen": "2026-11-02T09:05:00Z",
            "description": "Repeated failed logins were recorded.",
            "evidence": [{"file": "security.csv", "line": 2}],
        }
        yara_finding = {
            "id": "Y-001",
            "severity": "Medium",
            "rule": "Test_Signature",
            "file": "evidence.txt",
            "description": "A test signature matched.",
            "sha256": "f" * 64,
            "matches": [{"line": 4, "offset": 12, "string": "$a"}],
        }
        findings = [rule_finding, *yara_to_report_findings([yara_finding])]

        report = LocalLLMReporter().generate_grounded_report(
            "",
            "",
            findings=findings,
            use_llm=False,
        )

        self.assertIn("F-001", report)
        self.assertIn("Y-001", report)
        self.assertIn("security.csv, line 2", report)
        self.assertIn("evidence.txt", report)

    def test_large_ml_dataset_has_bounded_prompt_and_exact_aggregate_counts(self):
        source_rows, anomalies = build_rows(1000)
        findings = ml_to_report_findings(
            anomalies,
            source_rows,
            "trained_xgboost",
            "official",
            "network_flows.csv",
            "d" * 64,
        )
        reporter = LocalLLMReporter()
        prompts = []

        def fake_llm(prompt, max_tokens=700):
            prompts.append(prompt)
            return (
                "## Executive Summary\n"
                "The evidence contains 1000 medium findings and 1000 ML-predicted anomalies [ML-001].\n"
                "## Timeline Analysis\nNo timestamped findings. [ML-001]\n"
                "## Technical Findings\nThe model flagged one representative source row [ML-001].\n"
                "## Recommendations\nReview the cited evidence row [ML-001]."
            )

        reporter._call_ollama = Mock(side_effect=fake_llm)
        report = reporter.generate_grounded_report("", "", findings=findings, use_llm=True)

        self.assertEqual(reporter._call_ollama.call_count, 1)
        self.assertLessEqual(
            len(re.findall(r"^ML-\d+", prompts[0], re.MULTILINE)),
            reporter.MAX_PROMPT_FINDINGS,
        )
        self.assertIn("1000 medium (1000 findings in total)", prompts[0])
        self.assertIn("SOURCE TOTALS: {'ml': 1000}", prompts[0])
        self.assertIn("25 shown; 975 omitted", prompts[0])
        self.assertEqual(reporter.last_finding_summary["total_findings"], 1000)
        self.assertEqual(reporter.last_finding_summary["source_counts"]["ml"], 1000)
        self.assertEqual(len(reporter.last_report_findings), reporter.MAX_PROMPT_FINDINGS)
        self.assertIn("Total findings: 1000", report)
        self.assertIn("omits 975 additional findings", report)
        self.assertTrue(reporter.last_validation["passed"])


if __name__ == "__main__":
    unittest.main()
