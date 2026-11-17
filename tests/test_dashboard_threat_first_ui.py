import ast
import importlib.util
import re
import sys
import unittest
from collections import Counter
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
APP_PATH = ROOT / "dashboard" / "app.py"
UI_PATH = ROOT / "dashboard" / "forensic_ui.py"
APP_SOURCE = APP_PATH.read_text(encoding="utf-8")
APP_TREE = ast.parse(APP_SOURCE)
UI_SPEC = importlib.util.spec_from_file_location("aegis_forensic_ui", UI_PATH)
UI_MODULE = importlib.util.module_from_spec(UI_SPEC)
sys.modules[UI_SPEC.name] = UI_MODULE
UI_SPEC.loader.exec_module(UI_MODULE)


def function_node(tree, name):
    return next(
        node for node in tree.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == name
    )


def calls_in(node):
    result = set()
    for child in ast.walk(node):
        if isinstance(child, ast.Call):
            if isinstance(child.func, ast.Name):
                result.add(child.func.id)
            elif isinstance(child.func, ast.Attribute):
                result.add(child.func.attr)
    return result


def load_presentation_helpers():
    names = {"_finding_priority", "_finding_presentation", "_alert_summary"}
    nodes = [
        node for node in APP_TREE.body
        if isinstance(node, ast.FunctionDef) and node.name in names
    ]
    module = ast.Module(body=nodes, type_ignores=[])
    namespace = {
        "Counter": Counter,
        "SEVERITY_RANK": {"Critical": 0, "High": 1, "Medium": 2, "Low": 3},
        "RULE_FRIENDLY_TEXT": {},
    }
    exec(compile(module, str(APP_PATH), "exec"), namespace)
    return namespace


class DashboardThreatFirstUITests(unittest.TestCase):
    def test_repeated_finding_actions_get_distinct_deterministic_keys(self):
        helper = function_node(APP_TREE, "_alert_widget_identity")
        namespace = {"re": re}
        exec(compile(ast.Module(body=[helper], type_ignores=[]), str(APP_PATH), "exec"), namespace)

        findings = [
            {"severity": "High"},
            {"severity": "Medium"},
            {"id": "duplicate-id", "severity": "Low"},
            {"id": "duplicate-id", "severity": "Low"},
        ]
        identities = [
            namespace["_alert_widget_identity"]("laptop_scan", finding, index)
            for index, finding in enumerate(findings)
        ]
        action_keys = [
            f"{action}_{identity}"
            for identity in identities
            for action in ("review", "investigate", "false_positive")
        ]

        self.assertEqual(len(action_keys), len(set(action_keys)))
        self.assertEqual(identities, [
            "laptop_scan_finding_0",
            "laptop_scan_finding_1",
            "laptop_scan_duplicate-id_2",
            "laptop_scan_duplicate-id_3",
        ])
        collection_source = ast.get_source_segment(
            APP_SOURCE,
            function_node(APP_TREE, "_render_alert_collection"),
        )
        self.assertIn("enumerate(selected, start=start)", collection_source)
        self.assertIn("occurrence_index=selected_index", collection_source)
        alert_renderer_source = ast.get_source_segment(
            APP_SOURCE,
            function_node(APP_TREE, "_render_threat_alert"),
        )
        self.assertIn('"investigation_selected_finding"] = dict(finding)', alert_renderer_source)
        self.assertIn('"selected_finding": dict(finding)', alert_renderer_source)
        pending_source = ast.get_source_segment(
            APP_SOURCE,
            function_node(APP_TREE, "_render_pending_scanned_evidence"),
        )
        self.assertIn("item == selected_finding", pending_source)

    def test_alert_card_escapes_untrusted_content_and_shows_actionable_fields(self):
        card = UI_MODULE.threat_alert_card(
            title="<script>alert(1)</script>",
            severity="High",
            affected="C:\\evidence\\sample.exe",
            explanation="Needs review.",
            recommendation="Preserve the original.",
            certainty="Unconfirmed",
            detection_type="YARA · Sample_Rule",
            timestamp="2026-11-10 08:00:00 UTC",
        )
        self.assertNotIn("<script>", card)
        self.assertIn("&lt;script&gt;", card)
        for expected in (
            "High",
            "sample.exe",
            "Needs review.",
            "Preserve the original.",
            "Unconfirmed",
            "YARA · Sample_Rule",
            "2026-11-10 08:00:00 UTC",
        ):
            self.assertIn(expected, card)

    def test_shared_page_headers_and_dark_controls_are_compact(self):
        self.assertNotIn('st.expander("Learn more"', APP_SOURCE)
        header_source = ast.get_source_segment(
            UI_PATH.read_text(encoding="utf-8"),
            function_node(ast.parse(UI_PATH.read_text(encoding="utf-8")), "page_header"),
        )
        self.assertIn('class="sub"', header_source)
        self.assertNotIn("expander", header_source)
        for selector in (
            ".stNumberInput [data-baseweb=\"input\"]",
            "[data-baseweb=\"popover\"]",
            "[role=\"tooltip\"]",
            "[data-testid=\"stExpander\"]",
        ):
            self.assertIn(selector, UI_MODULE.DARK_THEME_CSS)
        self.assertIn("The selected alert is not linked to this evidence file.", APP_SOURCE)

    def test_evidence_vault_does_not_show_sha256_in_the_default_record_label(self):
        record = UI_MODULE.vault_record("CASE-123")
        self.assertIn("CASE-123", record)
        self.assertNotIn("a" * 64, record)

    def test_large_ml_sets_are_summarized_and_top_items_are_deduplicated(self):
        helpers = load_presentation_helpers()
        findings = [
            {
                "id": f"ML-{index:05d}",
                "source": "ml",
                "severity": "Medium",
                "model_name": "trained_xgboost",
                "file": "flows.csv",
                "evidence": [{"file": "flows.csv", "line": index + 2}],
            }
            for index in range(10_000)
        ]
        summary = helpers["_alert_summary"](findings)
        self.assertEqual(summary["total"], 10_000)
        self.assertEqual(len(summary["top_findings"]), 1)
        self.assertIn("model prediction", helpers["_finding_presentation"](findings[0])["explanation"])
        self.assertIn("not confirmation", helpers["_finding_presentation"](findings[0])["explanation"])

    def test_missing_source_line_is_not_presented_as_a_csv_reference(self):
        helpers = load_presentation_helpers()
        finding = {
            "id": "ML-001",
            "source": "ml",
            "model_name": "trained_xgboost",
            "file": "flows.csv",
            "severity": "Medium",
            "evidence": [{"file": "flows.csv"}],
        }
        presentation = helpers["_finding_presentation"](finding)
        self.assertEqual(presentation["affected"], "flows.csv")
        self.assertNotIn("CSV row", presentation["affected"])

    def test_detection_pages_use_cards_and_keep_technical_rows_collapsed(self):
        expected_pages = (
            "show_laptop_scan",
            "_render_live_alerts",
            "_render_windows_event_tables",
            "show_url_security_checker",
        )
        for name in expected_pages:
            node = function_node(APP_TREE, name)
            self.assertIn("_render_alert_collection", calls_in(node), name)
        scanner = function_node(APP_TREE, "show_safety_scan")
        self.assertIn("_render_scan_summary", calls_in(scanner))
        self.assertNotIn("_render_alert_collection", calls_in(scanner))
        self.assertNotIn("dataframe", calls_in(scanner))
        self.assertNotIn("dataframe", calls_in(function_node(APP_TREE, "_render_live_alerts")))
        self.assertIn("Technical Details", APP_SOURCE)

    def test_investigation_overview_summarizes_findings_without_repeating_cards(self):
        overview = next(
            node for node in ast.walk(APP_TREE)
            if isinstance(node, ast.With)
            and any(
                isinstance(item.context_expr, ast.Name) and item.context_expr.id == "tab0"
                for item in node.items
            )
        )
        self.assertIn("_render_investigation_finding_summary", calls_in(overview))
        self.assertNotIn("_render_alert_collection", calls_in(overview))
        summary = function_node(APP_TREE, "_render_investigation_finding_summary")
        self.assertIn("Review each finding once", ast.get_source_segment(APP_SOURCE, summary))

    def test_live_monitor_overview_does_not_repeat_historical_alert_cards(self):
        monitor_overview = function_node(APP_TREE, "_render_background_monitor_controls")
        source = ast.get_source_segment(APP_SOURCE, monitor_overview)
        self.assertNotIn("_render_protection_alerts", calls_in(monitor_overview))
        self.assertIn("Monitored Directories", source)
        self.assertIn("not full antivirus or system-wide protection", source)

    def test_ml_details_are_searchable_and_paginated(self):
        alerts = function_node(APP_TREE, "_render_alert_collection")
        calls = calls_in(alerts)
        self.assertIn("text_input", calls)
        self.assertIn("number_input", calls)
        self.assertIn("ML_DETAIL_PAGE_SIZE", APP_SOURCE)
        self.assertIn("Search individual ML records", APP_SOURCE)

    def test_synthetic_events_are_explicitly_labeled(self):
        synthetic = function_node(APP_TREE, "_render_synthetic_event_demo")
        source = ast.get_source_segment(APP_SOURCE, synthetic)
        self.assertIn("Demo Tools", source)
        self.assertIn("expanded=False", source)
        self.assertIn("never counted as Windows events", source)
        self.assertIn("synthetic event", APP_SOURCE)


if __name__ == "__main__":
    unittest.main()
