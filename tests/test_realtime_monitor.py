import tempfile
import hashlib
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from modules.realtime_monitor import (
    RealtimeMonitor,
    _security_alert,
    classify_security_event,
    make_synthetic_security_event,
)
from modules.windows_security import WindowsSecurityError


def event_page(events, after=0):
    records = [{**event, "Fingerprint": hashlib.sha256(str(event).encode()).hexdigest()} for event in events]
    newest = max((event["RecordId"] for event in records), default=0)
    anchor = next((event["Fingerprint"] for event in records if event["RecordId"] == after), "")
    return dict(log="Security", oldest=min((event["RecordId"] for event in records), default=0),
                newest=newest, next_record_id=newest,
                next_fingerprint=records[-1]["Fingerprint"] if records else "",
                anchor_fingerprint=anchor, more=False,
                events=[event for event in records if event["RecordId"] > after])


class FakeScanner:
    ready = True

    def scan_file(self, path, timeout=60):
        return []


class RealtimeMonitorTests(unittest.TestCase):
    def test_failed_login_event_is_reported_with_evidence(self):
        alert = _security_alert({
            "Log": "Security",
            "EventId": 4625,
            "Time": "2026-10-26T10:00:00Z",
            "Provider": "Microsoft-Windows-Security-Auditing",
            "Message": "Logon failure",
        })
        self.assertIsNotNone(alert)
        self.assertEqual(alert["severity"], "Medium")
        self.assertEqual(alert["evidence"]["event_id"], 4625)

    def test_unmonitored_event_is_ignored(self):
        self.assertIsNone(_security_alert({"EventId": 4624}))

    def test_service_logon_is_normal_without_additional_evidence(self):
        event = {
            "Log": "Security",
            "EventId": 4624,
            "LogonType": "5",
            "IpAddress": "-",
        }
        self.assertEqual(classify_security_event(event), ("Normal", []))
        self.assertIsNone(_security_alert(event))

    def test_service_logon_with_non_local_ip_needs_review(self):
        event = {
            "Log": "Security",
            "EventId": 4624,
            "LogonType": "5",
            "IpAddress": "203.0.113.8",
        }
        classification, reasons = classify_security_event(event)
        self.assertEqual(classification, "Suspicious")
        self.assertIn("non-local source IP", reasons[0])
        self.assertEqual(_security_alert(event)["evidence"]["source_ip"], "203.0.113.8")

    def test_synthetic_event_is_marked_and_does_not_read_windows_logs(self):
        with patch("modules.realtime_monitor.read_security_event_page") as read_events:
            event = make_synthetic_security_event(4625)

        self.assertTrue(event["synthetic"])
        self.assertEqual(event["source_type"], "synthetic")
        self.assertEqual(event["Log"], "Synthetic demonstration only")
        self.assertEqual(event["classification"], "Needs review")
        read_events.assert_not_called()
        with self.assertRaises(ValueError):
            make_synthetic_security_event(9999)

    def test_monitor_persists_alerts_when_configured(self):
        with tempfile.TemporaryDirectory() as directory:
            log_path = Path(directory) / "alerts.jsonl"
            monitor = RealtimeMonitor([directory], FakeScanner(), alert_log_path=log_path)
            monitor._add_alert({
                "created_at_utc": "2026-11-02T00:00:00+00:00",
                "severity": "Medium",
                "source": "test",
                "message": "Test alert",
                "evidence": {"path": "example.txt"},
            })

            entry = log_path.read_text(encoding="utf-8").strip()
            snapshot = monitor.snapshot()

        self.assertIn('"message": "Test alert"', entry)
        self.assertIsNone(snapshot["persistence_error"])

    def test_new_events_are_separated_and_not_duplicated_between_polls(self):
        existing_event = {
            "Log": "Security",
            "EventId": 4625,
            "Time": "2026-10-28T09:00:00Z",
            "Provider": "Security-Auditing",
            "RecordId": 1,
            "TargetUserName": "previous",
        }
        service_logon = {
            "Log": "Security",
            "EventId": 4624,
            "Time": "2026-10-28T10:00:00Z",
            "Provider": "Security-Auditing",
            "RecordId": 2,
            "LogonType": "5",
            "IpAddress": "-",
        }
        failed_logon = {
            "Log": "Security",
            "EventId": 4625,
            "Time": "/Date(1791965232702+0530)/",
            "Provider": "Security-Auditing",
            "RecordId": 3,
            "TargetUserName": "alice",
            "LogonType": "3",
            "IpAddress": "192.0.2.10",
        }
        with tempfile.TemporaryDirectory() as directory:
            monitor = RealtimeMonitor([directory], FakeScanner(), cursor_path=Path(directory) / "cursors.json", event_logs=("Security",))
            with patch(
                "modules.realtime_monitor.read_security_event_page",
                side_effect=[
                    event_page([existing_event]),
                    event_page([existing_event, service_logon, failed_logon], after=1),
                    event_page([existing_event, service_logon, failed_logon], after=3),
                ],
            ):
                monitor._poll_security_events()
                monitor._poll_security_events()
                monitor._poll_security_events()

        snapshot = monitor.snapshot()
        self.assertEqual(snapshot["security_event_count"], 3)
        self.assertEqual(snapshot["normal_event_count"], 1)
        self.assertEqual(snapshot["security_alert_count"], 2)
        self.assertEqual(
            [event["classification"] for event in snapshot["security_events"]],
            ["Needs review", "Normal", "Needs review"],
        )
        self.assertEqual(len([alert for alert in snapshot["alerts"] if alert["source"] == "Windows event log"]), 2)
        self.assertEqual(snapshot["security_events"][0]["account"], "alice")
        self.assertEqual(
            snapshot["security_events"][0]["TimeUtc"],
            "2026-10-14T08:07:12.702Z",
        )
        self.assertNotEqual(
            snapshot["security_events"][0]["TimeLocal"],
            snapshot["security_events"][0]["Time"],
        )
        self.assertIsNotNone(snapshot["last_successful_event_read_utc"])

    def test_event_log_permission_errors_are_exposed(self):
        with tempfile.TemporaryDirectory() as directory:
            monitor = RealtimeMonitor([directory], FakeScanner(), cursor_path=Path(directory) / "cursors.json", event_logs=("Security",))
            with patch(
                "modules.realtime_monitor.read_security_event_page",
                side_effect=WindowsSecurityError("Access is denied."),
            ):
                monitor._poll_security_events()

        snapshot = monitor.snapshot()
        self.assertEqual(snapshot["event_log_errors"][0]["Log"], "Security")
        self.assertIsNone(snapshot["last_successful_event_read_utc"])
        self.assertEqual(snapshot["security_event_count"], 0)

    def test_log_permission_recovery_processes_retained_records_without_skipping(self):
        old_event = {
            "Log": "Security",
            "EventId": 4625,
            "Time": "2026-10-28T10:00:00Z",
            "Provider": "Security-Auditing",
            "RecordId": 10,
        }
        new_event = {
            **old_event,
            "Time": "2026-10-28T10:01:00Z",
            "RecordId": 11,
        }
        with tempfile.TemporaryDirectory() as directory:
            monitor = RealtimeMonitor([directory], FakeScanner(), cursor_path=Path(directory) / "cursors.json", event_logs=("Security",))
            with patch(
                "modules.realtime_monitor.read_security_event_page",
                side_effect=[
                    WindowsSecurityError("Access is denied."),
                    event_page([old_event]),
                    event_page([old_event, new_event], after=10),
                ],
            ):
                monitor._poll_security_events()
                monitor._poll_security_events()
                monitor._poll_security_events()

        snapshot = monitor.snapshot()
        self.assertEqual(snapshot["security_event_count"], 2)
        self.assertEqual(snapshot["security_events"][0]["RecordId"], 11)

    def test_watchdog_observes_changed_files_and_stops(self):
        with tempfile.TemporaryDirectory() as directory:
            with patch(
                "modules.realtime_monitor.read_security_event_page",
                return_value=event_page([]),
            ):
                monitor = RealtimeMonitor([directory], FakeScanner(), event_poll_seconds=10,
                                          cursor_path=Path(directory) / "cursors.json", event_logs=("Security",))
                monitor.start()
                Path(directory, "new.txt").write_text("review", encoding="utf-8")
                deadline = time.monotonic() + 6
                while monitor.snapshot()["files_checked"] == 0 and time.monotonic() < deadline:
                    time.sleep(0.1)
                monitor.stop()

        self.assertEqual(monitor.snapshot()["files_checked"], 1)
        self.assertFalse(monitor.running)


if __name__ == "__main__":
    unittest.main()
