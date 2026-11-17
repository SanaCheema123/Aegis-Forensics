"""Incremental polling, cursor durability, replay, coverage and failure tests."""
from copy import deepcopy
import hashlib
import json
import subprocess
from pathlib import Path
import tempfile
import threading
import time
import unittest
from unittest.mock import Mock, patch

from modules.event_polling import persist_event_alerts
from modules.realtime_monitor import RealtimeMonitor, _security_alert
from modules.windows_security import WindowsSecurityError, read_security_event_page


def event(number, epoch="original", log="Security", event_id=4625):
    return {
        "Log": log, "RecordId": number, "EventId": event_id,
        "Time": f"2026-11-12T10:{number // 60 % 60:02d}:{number % 60:02d}.000Z",
        "Provider": "Test provider", "Message": "Test security event",
        "EventData": {"TargetUserName": "alice"},
        "Fingerprint": hashlib.sha256(f"{log}:{epoch}:{number}".encode()).hexdigest(),
    }


class EventSource:
    def __init__(self, records):
        self.records = records

    def page(self, log, after, *, limit=200, timeout=10):
        records = [item for item in self.records if item["Log"] == log]
        records.sort(key=lambda item: item["RecordId"])
        selected = [item for item in records if item["RecordId"] > after]
        more = len(selected) > limit
        rows = selected[:limit]
        newest = records[-1]["RecordId"] if records else 0
        checkpoint = rows[-1] if more else records[-1] if records else None
        return dict(log=log, oldest=records[0]["RecordId"] if records else 0, newest=newest,
                    next_record_id=checkpoint["RecordId"] if checkpoint else 0,
                    next_fingerprint=checkpoint["Fingerprint"] if checkpoint else "",
                    anchor_fingerprint=next((item["Fingerprint"] for item in records
                                             if item["RecordId"] == after), ""),
                    more=more, events=deepcopy(rows))


class EventPollingTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.alerts = self.root / "alerts.jsonl"
        self.cursors = self.root / "event_cursors.json"

    def monitor(self, logs=("Security",)):
        return RealtimeMonitor([self.root], Mock(ready=True), alert_log_path=self.alerts,
                               cursor_path=self.cursors, event_logs=logs)

    def cursor(self, log="Security"):
        return json.loads(self.cursors.read_text())["logs"][log]["record_id"]

    def stored(self):
        return [json.loads(line) for line in self.alerts.read_text().splitlines()] if self.alerts.exists() else []

    def event_alerts(self):
        return [item for item in self.stored() if item["source"] == "Windows event log"]

    def poll(self, monitor, source):
        with patch("modules.realtime_monitor.read_security_event_page", side_effect=source.page):
            monitor._poll_security_events()

    def test_burst_over_50_records_is_paginated_and_not_dropped(self):
        source = EventSource([event(number) for number in range(1, 1002)])
        monitor = self.monitor()
        self.poll(monitor, source)
        self.assertEqual(self.cursor(), 800)
        self.assertIn("backlog", str(monitor.snapshot()["event_log_errors"]).lower())
        self.poll(monitor, source)
        self.assertEqual(self.cursor(), 1001)
        alerts = self.event_alerts()
        self.assertEqual(len(alerts), 1001)
        self.assertEqual(len({item["event_uid"] for item in alerts}), 1001)
        self.assertEqual([item["evidence"]["record_id"] for item in alerts], list(range(1, 1002)))

    def test_restart_resumes_checkpoint_and_does_not_duplicate_events(self):
        source = EventSource([event(number) for number in range(1, 301)])
        with patch("modules.realtime_monitor.MAX_EVENT_PAGES_PER_LOG", 1):
            self.poll(self.monitor(), source)
        self.assertEqual(self.cursor(), 200)
        restarted = self.monitor()
        self.poll(restarted, source)
        self.poll(restarted, source)
        self.assertEqual(self.cursor(), 300)
        self.assertEqual(len(self.event_alerts()), 300)
        self.assertEqual(restarted.snapshot()["security_event_count"], 100)

    def test_failed_second_page_keeps_successful_first_page_and_retries_remainder(self):
        source = EventSource([event(number) for number in range(1, 451)])
        monitor = self.monitor()

        def read(log, after, **kwargs):
            if after == 200:
                raise WindowsSecurityError("PowerShell partial-batch failure")
            return source.page(log, after, **kwargs)

        with patch("modules.realtime_monitor.read_security_event_page", side_effect=read):
            monitor._poll_security_events()
        self.assertEqual(self.cursor(), 200)
        self.assertEqual(len(self.event_alerts()), 200)
        self.assertIn("not advanced", str(monitor.snapshot()["event_log_errors"]))
        self.poll(self.monitor(), source)
        self.assertEqual(self.cursor(), 450)
        self.assertEqual(len(self.event_alerts()), 450)

    def test_classification_failure_does_not_checkpoint_partial_batch(self):
        source = EventSource([event(1), event(2)])
        monitor = self.monitor()

        def classify(record):
            if record["RecordId"] == 2:
                raise ValueError("Could not process record")
            return _security_alert(record)

        with patch("modules.realtime_monitor._security_alert", side_effect=classify):
            self.poll(monitor, source)
        self.assertFalse(self.cursors.exists())
        self.assertEqual(self.event_alerts(), [])
        self.poll(monitor, source)
        self.assertEqual(self.cursor(), 2)
        self.assertEqual(len(self.event_alerts()), 2)

    def test_alerts_published_before_failed_cursor_write_are_idempotent_after_restart(self):
        source = EventSource([event(1), event(2)])
        monitor = self.monitor()
        with patch.object(monitor._event_store, "save", side_effect=OSError("disk failure")):
            self.poll(monitor, source)
        self.assertFalse(self.cursors.exists())
        self.assertEqual(len(self.event_alerts()), 2)
        self.poll(self.monitor(), source)
        self.assertEqual(self.cursor(), 2)
        self.assertEqual(len(self.event_alerts()), 2)

    def test_partially_published_batch_is_retried_without_duplicate_alerts(self):
        source = EventSource([event(1), event(2)])
        monitor = self.monitor()

        def fail_after_one(path, alerts, maximum):
            actual = [alert for alert in alerts if alert["source"] == "Windows event log"]
            persist_event_alerts(path, actual[:1], maximum)
            raise OSError("publication interrupted")

        with patch("modules.realtime_monitor.persist_event_alerts", side_effect=fail_after_one):
            self.poll(monitor, source)
        self.assertFalse(self.cursors.exists())
        self.poll(self.monitor(), source)
        self.assertEqual([alert["evidence"]["record_id"] for alert in self.event_alerts()], [1, 2])

    def test_log_clearing_and_record_id_reuse_are_reported_and_replayed(self):
        monitor = self.monitor()
        self.poll(monitor, EventSource([event(number) for number in range(1, 101)]))
        # A cleared log can grow past the saved ID before the next poll.
        self.poll(monitor, EventSource([event(number, epoch="cleared") for number in range(1, 121)]))
        self.assertEqual(self.cursor(), 120)
        self.assertEqual(len(self.event_alerts()), 220)
        self.assertEqual(monitor.snapshot()["security_event_count"], 220)
        self.assertTrue(any("Record ID reuse" in item["message"] for item in self.stored()))

    def test_reset_to_smaller_or_empty_log_is_detected(self):
        monitor = self.monitor()
        self.poll(monitor, EventSource([event(1), event(2)]))
        self.poll(monitor, EventSource([]))
        self.assertEqual(self.cursor(), 0)
        self.poll(monitor, EventSource([event(1, epoch="new")]))
        self.assertEqual(self.cursor(), 1)
        self.assertEqual(len(self.event_alerts()), 3)

    def test_rotation_reports_unrecoverable_coverage_gap(self):
        monitor = self.monitor()
        self.poll(monitor, EventSource([event(number) for number in range(1, 51)]))
        self.poll(monitor, EventSource([event(number) for number in range(80, 151)]))
        self.assertEqual(self.cursor(), 150)
        self.assertTrue(any("rotation" in item["message"] for item in self.stored()))
        self.assertEqual(len(self.event_alerts()), 121)

    def test_rotation_after_empty_checkpoint_is_not_silent(self):
        monitor = self.monitor()
        self.poll(monitor, EventSource([]))
        self.poll(monitor, EventSource([event(50)]))
        self.assertEqual(self.cursor(), 50)
        self.assertTrue(any("empty-log checkpoint" in item["message"] for item in self.stored()))

    def test_one_inaccessible_log_does_not_block_another_log(self):
        monitor = self.monitor(logs=("Security", "System"))
        source = EventSource([event(1, log="System", event_id=7045)])

        def read(log, after, **kwargs):
            if log == "Security":
                raise WindowsSecurityError("Access denied")
            return source.page(log, after, **kwargs)

        with patch("modules.realtime_monitor.read_security_event_page", side_effect=read):
            monitor._poll_security_events()
        self.assertEqual(self.cursor("System"), 1)
        self.assertNotIn("Security", json.loads(self.cursors.read_text())["logs"])
        self.assertEqual(self.event_alerts()[0]["evidence"]["event_id"], 7045)

    def test_two_monitors_share_cursor_without_duplicate_publication(self):
        source = EventSource([event(number) for number in range(1, 76)])
        monitors = [self.monitor(), self.monitor()]
        with patch("modules.realtime_monitor.read_security_event_page", side_effect=source.page):
            workers = [threading.Thread(target=monitor._poll_security_events) for monitor in monitors]
            for worker in workers:
                worker.start()
            for worker in workers:
                worker.join(timeout=5)
                self.assertFalse(worker.is_alive())
        self.assertEqual(self.cursor(), 75)
        self.assertEqual(len(self.event_alerts()), 75)

    def test_permission_failure_preserves_cursor_then_recovers_without_baseline_skip(self):
        monitor = self.monitor()
        self.poll(monitor, EventSource([event(1)]))
        checkpoint = self.cursors.read_bytes()
        with patch("modules.realtime_monitor.read_security_event_page", side_effect=WindowsSecurityError("Access denied")):
            monitor._poll_security_events()
        self.assertEqual(self.cursors.read_bytes(), checkpoint)
        self.assertIn("Access denied", str(monitor.snapshot()["event_log_errors"]))
        self.poll(monitor, EventSource([event(1), event(2)]))
        self.assertEqual(self.cursor(), 2)
        self.assertEqual(len(self.event_alerts()), 2)

    def test_corrupt_cursor_is_not_silently_reset_or_overwritten(self):
        self.cursors.write_bytes(b'{"logs": broken checkpoint')
        original = self.cursors.read_bytes()
        monitor = self.monitor()
        with patch("modules.realtime_monitor.read_security_event_page") as reader:
            monitor._poll_security_events()
        reader.assert_not_called()
        self.assertEqual(self.cursors.read_bytes(), original)
        self.assertIn("not reset", str(monitor.snapshot()["event_log_errors"]))

    def test_atomic_replace_failure_preserves_previous_checkpoint(self):
        monitor = self.monitor()
        self.poll(monitor, EventSource([event(1)]))
        original = self.cursors.read_bytes()
        with patch("modules.event_polling.os.replace", side_effect=OSError("replace failed")):
            self.poll(monitor, EventSource([event(1), event(2)]))
        self.assertEqual(self.cursors.read_bytes(), original)
        self.poll(monitor, EventSource([event(1), event(2)]))
        self.assertEqual(self.cursor(), 2)
        self.assertEqual(len(self.event_alerts()), 2)

    def test_full_alert_history_prevents_checkpoint_advance(self):
        monitor = self.monitor()
        with patch("modules.realtime_monitor.MAX_PERSISTENT_ALERT_LOG_BYTES", 1):
            self.poll(monitor, EventSource([event(1)]))
        self.assertFalse(self.cursors.exists())
        self.assertIn("20 MB limit", str(monitor.snapshot()["event_log_errors"]))

    def test_existing_legacy_alert_records_are_preserved(self):
        legacy = json.dumps({"source": "Windows event log", "message": "older format", "evidence": {"event_id": 4625}}) + "\n"
        self.alerts.write_text(legacy, encoding="utf-8")
        self.poll(self.monitor(), EventSource([event(1)]))
        self.assertTrue(self.alerts.read_text().startswith(legacy))
        self.assertEqual(len(self.event_alerts()), 2)
        alert = self.event_alerts()[-1]
        self.assertEqual(alert["evidence"]["record_id"], 1)
        self.assertEqual(alert["evidence"]["time"], event(1)["Time"])
        self.assertEqual(alert["evidence"]["event_id"], 4625)
        self.assertEqual(alert["evidence"]["log"], "Security")

    def test_unreadable_alert_history_blocks_checkpoint_with_warning(self):
        original = b'{"partial old alert"'
        self.alerts.write_bytes(original)
        monitor = self.monitor()
        self.poll(monitor, EventSource([event(1)]))
        self.assertFalse(self.cursors.exists())
        self.assertTrue(self.alerts.read_bytes().startswith(original))
        self.assertIn("history is invalid", str(monitor.snapshot()["event_log_errors"]))

    def test_polling_does_not_hold_snapshot_lock_during_slow_reader(self):
        entered = threading.Event()
        release = threading.Event()
        monitor = self.monitor()

        def slow_reader(*args, **kwargs):
            entered.set()
            release.wait(timeout=3)
            return EventSource([]).page(*args, **kwargs)

        with patch("modules.realtime_monitor.read_security_event_page", side_effect=slow_reader):
            worker = threading.Thread(target=monitor._poll_security_events)
            worker.start()
            try:
                self.assertTrue(entered.wait(timeout=2))
                before = time.monotonic()
                monitor.snapshot()
                self.assertLess(time.monotonic() - before, 0.5)
            finally:
                release.set()
                worker.join(timeout=4)
        self.assertFalse(worker.is_alive())


class WindowsEventPageTests(unittest.TestCase):
    def test_powershell_timeout_is_reported_as_retryable_read_failure(self):
        with patch("modules.windows_security._powershell_args", return_value=["powershell.exe"]), patch(
            "modules.windows_security.subprocess.run", side_effect=subprocess.TimeoutExpired("powershell", 10)
        ):
            with self.assertRaisesRegex(WindowsSecurityError, "too long"):
                read_security_event_page("Security")

    def test_reader_requests_ascending_record_range_and_bounded_timeout(self):
        page = EventSource([event(1), event(2)]).page("Security", 1)
        with patch("modules.windows_security._run_powershell_json", return_value=page) as query:
            result = read_security_event_page("Security", 1, limit=200, timeout=7)
        self.assertEqual(result["events"][0]["RecordId"], 2)
        self.assertEqual(query.call_args.kwargs["timeout"], 7)
        script = query.call_args.args[0]
        for text in ("-Oldest", "EventRecordID > 1", "201", "anchorFingerprint", "endAnchor", "endFirst", "4625"):
            self.assertIn(text, script)
        for unsafe in ("Clear-EventLog", "wevtutil cl", "Start-MpScan", "Set-MpPreference"):
            self.assertNotIn(unsafe, script)

    def test_invalid_pages_and_partial_results_are_rejected(self):
        page = EventSource([event(1)]).page("Security", 0)
        for changed in (dict(events="partial"), dict(events=[{}]), dict(next_fingerprint=""),
                        dict(more=True, events=[]), dict(next_record_id=0), dict(log="System")):
            with self.subTest(changed=changed), patch(
                "modules.windows_security._run_powershell_json", return_value={**page, **changed}
            ):
                with self.assertRaises(WindowsSecurityError):
                    read_security_event_page("Security")

    def test_no_automatic_elevation_and_inputs_are_bounded(self):
        with patch("modules.windows_security._run_powershell_json", side_effect=WindowsSecurityError("Access denied")):
            with self.assertRaisesRegex(WindowsSecurityError, "Access denied"):
                read_security_event_page("Security")
        for args in (("untrusted'log",), ("Security", -1), ("Security", 0, 1000), ("Security", 0, 200, 60)):
            with self.assertRaises(ValueError):
                read_security_event_page(*args)


if __name__ == "__main__":
    unittest.main()
