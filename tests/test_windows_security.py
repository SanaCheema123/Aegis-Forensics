import unittest
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

from modules.windows_security import (
    WindowsSecurityError,
    _review_reasons,
    build_review_report,
    get_defender_status,
    inspect_running_processes,
    inspect_startup_items,
    _event_timestamp_values,
    normalize_security_event,
    read_latest_windows_security_events,
    read_security_events,
    start_defender_scan,
    summarize_security_events,
)


class WindowsSecurityTests(unittest.TestCase):
    def test_windows_commands_are_unavailable_off_windows(self):
        with patch("modules.windows_security.os.name", "posix"):
            with self.assertRaises(WindowsSecurityError):
                get_defender_status()

    def test_defender_scan_only_accepts_explicit_scan_types(self):
        with self.assertRaises(ValueError):
            start_defender_scan("custom")

    def test_quick_scan_starts_only_the_requested_defender_command(self):
        with (
            patch("modules.windows_security._powershell_args", return_value=["powershell.exe", "-Command", "scan"]) as args,
            patch("modules.windows_security.subprocess.Popen", return_value="process") as popen,
        ):
            process = start_defender_scan("quick")
        self.assertEqual(process, "process")
        self.assertIn("Start-MpScan -ScanType QuickScan", args.call_args.args[0])
        self.assertEqual(popen.call_args.args[0], ["powershell.exe", "-Command", "scan"])

    def test_security_event_period_is_limited(self):
        with self.assertRaises(ValueError):
            read_security_events(3)

    def test_defender_status_result_is_validated(self):
        with patch(
            "modules.windows_security._run_powershell_json",
            return_value={"status": {"AntivirusEnabled": True}, "detections": []},
        ):
            self.assertTrue(get_defender_status()["status"]["AntivirusEnabled"])
        with patch("modules.windows_security._run_powershell_json", return_value=[]):
            with self.assertRaises(WindowsSecurityError):
                get_defender_status()

    def test_event_query_normalizes_single_event(self):
        with patch(
            "modules.windows_security._run_powershell_json",
            return_value={
                "events": {
                    "EventId": 4625,
                    "Log": "Security",
                    "Time": "/Date(1791965232702)/",
                    "EventData": {
                        "TargetUserName": "alice",
                        "TargetDomainName": "CONTOSO",
                        "LogonType": "3",
                        "IpAddress": "192.0.2.10",
                    },
                },
                "errors": None,
                "days": 7,
            },
        ):
            result = read_security_events()
        self.assertEqual(len(result["events"]), 1)
        self.assertEqual(result["events"][0]["EventId"], 4625)
        self.assertEqual(result["events"][0]["account"], "CONTOSO\\alice")
        self.assertEqual(result["events"][0]["logon_type"], "3")
        self.assertEqual(result["events"][0]["source_ip"], "192.0.2.10")
        self.assertEqual(result["events"][0]["description"], "Failed Windows logon")
        self.assertEqual(result["events"][0]["TimeUtc"], "2026-10-14T08:07:12.702Z")
        self.assertEqual(result["events"][0]["Time"], "/Date(1791965232702)/")
        self.assertEqual(result["errors"], [])

    def test_windows_serialized_timestamp_preserves_utc_and_formats_local_time(self):
        source = "/Date(1791965232702)/"
        utc_timestamp, local_timestamp = _event_timestamp_values(
            source,
            timezone(timedelta(hours=5, minutes=30)),
        )
        self.assertEqual(utc_timestamp, "2026-10-14T08:07:12.702Z")
        self.assertEqual(local_timestamp, "2026-10-14 13:37:12.702+05:30")

    def test_windows_serialized_timestamp_accepts_optional_timezone_offset(self):
        expected_utc = "2026-10-14T08:07:12.702Z"
        for source in (
            "/Date(1791965232702+0530)/",
            "/Date(1791965232702-0700)/",
        ):
            event = normalize_security_event({"EventId": 4624, "Time": source})
            self.assertEqual(event["Time"], source)
            self.assertEqual(event["TimeUtc"], expected_utc)
            self.assertNotEqual(event["TimeLocal"], source)
            self.assertIn("2026-", event["TimeLocal"])

    def test_event_timestamp_handles_iso_invalid_and_missing_values(self):
        utc_timestamp, local_timestamp = _event_timestamp_values(
            "2026-10-14T10:07:12+02:00",
            timezone.utc,
        )
        self.assertEqual(utc_timestamp, "2026-10-14T08:07:12.000Z")
        self.assertEqual(local_timestamp, "2026-10-14 08:07:12.000+00:00")
        for value in (
            "not-a-date",
            None,
            "",
            "/Date(999999999999999999999999999999999999999999999999)/",
            "/Date(1791965232702+0060)/",
        ):
            with self.subTest(value=value):
                self.assertEqual(_event_timestamp_values(value), (None, "Unknown"))

    def test_event_query_requests_required_security_and_system_event_ids(self):
        with patch(
            "modules.windows_security._run_powershell_json",
            return_value={"events": [], "errors": [], "days": 1},
        ) as query:
            read_security_events(1)
        script = query.call_args.args[0]
        for event_id in (4624, 4625, 4672, 4720, 4732, 1102):
            self.assertIn(str(event_id), script)
        self.assertIn("Log = 'System'; Ids = @(7045)", script)
        self.assertIn("EventData = $eventData", script)

    def test_read_only_preview_returns_latest_50_events(self):
        start = datetime(2026, 10, 1, tzinfo=timezone.utc)
        events = [
            {"EventId": 4624, "Log": "Security", "Time": (start + timedelta(days=day)).isoformat()}
            for day in range(51)
        ]
        with patch(
            "modules.windows_security._run_powershell_json",
            return_value={"events": events, "errors": [], "days": 30},
        ) as query:
            result = read_latest_windows_security_events()
        self.assertEqual(len(result["events"]), 50)
        self.assertEqual(result["events"][0]["Time"], "2026-11-20T00:00:00+00:00")
        self.assertIn("Log = 'Security'", query.call_args.args[0])
        self.assertIn("Log = 'System'", query.call_args.args[0])
        self.assertNotIn("PowerShell/Operational", query.call_args.args[0])
        self.assertNotIn("StartTime", query.call_args.args[0])
        self.assertIn("-MaxEvents 50", query.call_args.args[0])
        with self.assertRaises(ValueError):
            read_latest_windows_security_events(51)

    def test_event_summary_counts_selected_security_signals(self):
        summary = summarize_security_events([
            {"EventId": 4625},
            {"EventId": "4625"},
            {"EventId": 1116},
            {"EventId": 9999},
        ])
        self.assertEqual(summary["failed_logins"], 2)
        self.assertEqual(summary["defender_detections"], 1)
        self.assertEqual(summary["security_log_cleared"], 0)
        self.assertEqual(summary["privilege_changes"], 0)
        self.assertEqual(summary["account_changes"], 0)

    def test_startup_inventory_flags_review_signals(self):
        with patch(
            "modules.windows_security._run_powershell_json",
            return_value={
                "startup": {"Name": "Updater", "Command": "powershell -EncodedCommand AAA"},
                "tasks": [],
                "totalTasks": 1,
                "errors": None,
            },
        ):
            result = inspect_startup_items()
        self.assertIn(
            "Contains an encoded-command indicator.",
            result["startup"][0]["review_reasons"],
        )
        self.assertEqual(result["total_tasks"], 1)

    def test_process_inventory_flags_encoded_command_indicators(self):
        with patch(
            "modules.windows_security._run_powershell_json",
            return_value={
                "processes": {
                    "ProcessId": 20,
                    "Name": "powershell.exe",
                    "CommandLine": "powershell -EncodedCommand AAA",
                },
                "total": 1,
            },
        ):
            result = inspect_running_processes()
        self.assertEqual(result["total"], 1)
        self.assertIn(
            "Contains an encoded-command indicator.",
            result["processes"][0]["review_reasons"],
        )

    def test_report_describes_scope_and_limits(self):
        report = build_review_report(None, None, None, {"status": "request_accepted"})
        self.assertIn("no changes made", report["scope"])
        self.assertEqual(report["defender_scan"]["status"], "request_accepted")
        self.assertTrue(report["limitations"])

    def test_command_review_heuristics_are_not_overbroad(self):
        self.assertEqual(_review_reasons("C:\\Program Files\\Vendor\\updater.exe"), [])
        self.assertTrue(_review_reasons("powershell -EncodedCommand AAA"))


if __name__ == "__main__":
    unittest.main()
