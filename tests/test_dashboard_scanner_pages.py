import ast
import unittest
from pathlib import Path


APP_PATH = Path(__file__).resolve().parents[1] / "dashboard" / "app.py"
APP_SOURCE = APP_PATH.read_text(encoding="utf-8")
APP_TREE = ast.parse(APP_SOURCE)


def function_node(name):
    return next(
        node for node in APP_TREE.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == name
    )


def calls_in(node):
    calls = set()
    for child in ast.walk(node):
        if not isinstance(child, ast.Call):
            continue
        if isinstance(child.func, ast.Name):
            calls.add(child.func.id)
        elif isinstance(child.func, ast.Attribute):
            calls.add(child.func.attr)
    return calls


class DashboardScannerPageTests(unittest.TestCase):
    def test_malware_scanner_is_upload_only_and_has_no_url_check(self):
        scanner = function_node("show_safety_scan")
        self.assertNotIn("inspect_url", calls_in(scanner))
        self.assertIn("check_uploaded_file", calls_in(scanner))
        self.assertIn("file_uploader", calls_in(scanner))
        self.assertIn('"Scan image" if image_mode else "Scan file"', APP_SOURCE)
        self.assertIn("_render_scan_summary", calls_in(scanner))
        self.assertIn("expander", calls_in(scanner))
        self.assertIn("Technical Details", APP_SOURCE)
        self.assertNotIn("dataframe", calls_in(scanner))
        self.assertNotIn("Check a link", APP_SOURCE[scanner.lineno - 1:scanner.end_lineno])
        self.assertNotIn("Paste the link here", APP_SOURCE[scanner.lineno - 1:scanner.end_lineno])

    def test_scanner_findings_route_through_confirmed_evidence_persistence(self):
        scanner = function_node("show_safety_scan")
        vault = function_node("show_evidence_vault")
        alert = function_node("_render_threat_alert")
        pending_confirmation = function_node("_render_pending_scanned_evidence")
        self.assertIn("evidence_context=evidence_context", APP_SOURCE)
        self.assertIn("pending_scanned_evidence", ast.get_source_segment(APP_SOURCE, alert))
        self.assertIn('navigate_to("Evidence")', ast.get_source_segment(APP_SOURCE, alert))
        self.assertIn("Confirm Add to Investigation", APP_SOURCE)
        self.assertIn("add_scanned_evidence", calls_in(pending_confirmation))
        self.assertIn('record["evidence_id"]', ast.get_source_segment(
            APP_SOURCE,
            pending_confirmation,
        ))
        self.assertIn("stored_filename", ast.get_source_segment(
            APP_SOURCE,
            pending_confirmation,
        ))
        self.assertIn("load_scanned_evidence_records", calls_in(vault))
        self.assertIn("load_scanned_evidence_aliases", calls_in(vault))
        self.assertIn("evidence_matches_search", calls_in(vault))
        self.assertIn("evidence_search_display_name", calls_in(vault))
        self.assertIn("Also scanned as:", ast.get_source_segment(APP_SOURCE, vault))
        self.assertIn("Evidence newly saved", APP_SOURCE)
        self.assertIn("Evidence reused", APP_SOURCE)
        self.assertIn("evidence_focus_sha256", ast.get_source_segment(APP_SOURCE, vault))
        scanner_source = "\n".join(APP_SOURCE.splitlines()[scanner.lineno - 1:scanner.end_lineno])
        self.assertIn("YARA", scanner_source)
        self.assertIn("_render_scan_summary", calls_in(scanner))
        self.assertNotIn("_render_alert_collection", calls_in(scanner))
        self.assertIn("add_scanned_file_to_investigation", scanner_source)
        self.assertIn("On-demand local checks only", scanner_source)
        self.assertIn('"sha256": result["sha256"]', scanner_source)
        self.assertNotIn("cached_ml", calls_in(scanner))

    def test_scanner_finding_summaries_do_not_repeat_investigation_controls(self):
        summary = function_node("_render_scan_summary")
        summary_source = ast.get_source_segment(APP_SOURCE, summary)
        self.assertNotIn("_render_threat_alert", calls_in(summary))
        self.assertNotIn("Investigate", summary_source)
        self.assertIn("YARA rule match", summary_source)
        self.assertIn("Technical Details", summary_source)

    def test_network_csv_scan_is_manual_and_opens_full_analysis_in_investigations(self):
        scanner_source = APP_SOURCE[
            APP_SOURCE.index('if network_csv_mode and selected_saved_path is None'):
            APP_SOURCE.index('if selected_saved_path is not None:', APP_SOURCE.index(
                'if network_csv_mode and selected_saved_path is None'
            ))
        ]
        network_scan_source = APP_SOURCE[
            APP_SOURCE.index("if network_csv_mode:\n    network_scan_findings"):
            APP_SOURCE.index("timeline_df = pd.DataFrame()")
        ]
        self.assertIn("Analyze network CSV", scanner_source)
        self.assertIn("network_csv_scan_identity", scanner_source)
        self.assertIn("_render_scan_summary", network_scan_source)
        self.assertIn("Open in Investigations", network_scan_source)
        self.assertIn('_evidence_vault_id(Path(file_path))', network_scan_source)
        self.assertIn('navigate_to("Investigation")', network_scan_source)
        self.assertIn("st.stop()", network_scan_source)
        self.assertNotIn("st.tabs", network_scan_source)

    def test_saved_evidence_opens_without_upload_and_generates_archived_report(self):
        vault = function_node("show_evidence_vault")
        opener = function_node("_open_saved_evidence")
        generator = function_node("_generate_saved_evidence_report")
        reports = function_node("show_ai_reports")
        vault_source = ast.get_source_segment(APP_SOURCE, vault)
        reports_source = ast.get_source_segment(APP_SOURCE, reports)
        workspace_source = APP_SOURCE[APP_SOURCE.index("selected_saved_evidence ="):APP_SOURCE.index("# 3. Parse logs")]

        self.assertIn("Open Investigation", vault_source)
        self.assertIn("Generate Forensic Report", vault_source)
        self.assertIn("selected_saved_evidence", ast.get_source_segment(APP_SOURCE, opener))
        self.assertIn("select_saved_scan", calls_in(opener))
        self.assertIn("navigate_to", calls_in(opener))
        self.assertIn("build_saved_evidence_report", calls_in(generator))
        self.assertIn("save_forensic_report", calls_in(generator))
        self.assertIn('"filename"', reports_source)
        self.assertIn('"evidence_id"', reports_source)
        self.assertIn("selected_saved_path.read_bytes()", workspace_source)
        self.assertIn("saved_evidence_findings(saved_scan_record)", workspace_source)
        self.assertIn("selected_saved_evidence", workspace_source)

    def test_live_alert_investigation_requires_confirmation_and_preserves_alert_context(self):
        alert_renderer = function_node("_render_protection_alerts")
        pending_renderer = function_node("_render_pending_monitor_alert_investigation")
        workspace_source = APP_SOURCE[APP_SOURCE.index("pending_monitor_alert ="):APP_SOURCE.index("# 3. Parse logs")]

        alert_source = ast.get_source_segment(APP_SOURCE, alert_renderer)
        pending_source = ast.get_source_segment(APP_SOURCE, pending_renderer)
        self.assertIn("pending_monitor_alert_investigation", alert_source)
        self.assertIn('navigate_to("Investigation")', alert_source)
        for field in ("Filename:", "Full path:", "Severity:", "Detection time (UTC):", "Alert details:"):
            self.assertIn(field, pending_source)
        self.assertIn("Add to Investigation", pending_source)
        self.assertIn("Add uploaded file to Investigation", pending_source)
        self.assertIn("source_path.read_bytes()", pending_source)
        self.assertIn("promote_alert_to_evidence", ast.get_source_segment(
            APP_SOURCE,
            function_node("_save_pending_monitor_alert"),
        ))
        self.assertIn("_render_pending_monitor_alert_investigation", workspace_source)
        self.assertIn("Generate Forensic Report", APP_SOURCE)
        self.assertIn("Evidence ID #", workspace_source)

    def test_dedicated_url_checker_still_inspects_and_assesses_urls(self):
        checker = function_node("show_url_security_checker")
        calls = calls_in(checker)
        self.assertIn("inspect_url", calls)
        self.assertIn("text_input", calls)
        self.assertIn("button", calls)
        self.assertIn("URL Input", APP_SOURCE)
        self.assertIn("Check URL", APP_SOURCE)
        self.assertIn("_render_alert_collection", calls_in(checker))
        self.assertIn("No obvious URL-format indicators found.", APP_SOURCE)

    def test_real_time_protection_has_a_separate_windows_events_panel(self):
        page = function_node("show_realtime_protection")
        panel = function_node("_render_windows_security_events")
        self.assertIn("_render_windows_security_events", calls_in(page))
        self.assertIn("read_latest_windows_security_events", calls_in(panel))
        self.assertIn("_render_alert_collection", calls_in(function_node("_render_windows_event_tables")))
        self.assertNotIn("dataframe", calls_in(function_node("_render_windows_event_tables")))
        self.assertIn("Windows Security Events", APP_SOURCE)
        self.assertIn("Last successful event-log read (UTC)", APP_SOURCE)
        self.assertIn("Normal events", APP_SOURCE)
        self.assertIn("Security alerts", APP_SOURCE)
        self.assertIn("Load latest 50 existing Windows security events (read-only)", APP_SOURCE)
        monitor = function_node("_render_background_monitor_controls")
        self.assertNotIn("_render_protection_alerts", calls_in(monitor))
        self.assertIn("Monitored Directories", ast.get_source_segment(APP_SOURCE, monitor))
        self.assertIn("not full antivirus or system-wide protection", ast.get_source_segment(APP_SOURCE, monitor))


if __name__ == "__main__":
    unittest.main()
