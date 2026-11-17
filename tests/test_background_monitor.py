import json
import os
import subprocess
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import Mock, patch

from modules import background_monitor
from modules.background_monitor import (
    BackgroundMonitorError,
    install_startup_task,
    load_background_alerts,
    start_background_monitor,
    stop_background_monitor,
)


class BackgroundMonitorTests(unittest.TestCase):
    def test_status_check_recognizes_current_process(self):
        with tempfile.TemporaryDirectory() as directory:
            status_path = Path(directory) / "status.json"
            status_path.write_text(json.dumps({
                "state": "running",
                "pid": os.getpid(),
                "heartbeat_utc": datetime.now(timezone.utc).isoformat(),
            }), encoding="utf-8")
            with patch.object(background_monitor, "STATUS_PATH", status_path):
                result = background_monitor.get_background_status()

        self.assertTrue(result["running"])

    def test_status_check_marks_nonexistent_process_stale(self):
        with tempfile.TemporaryDirectory() as directory:
            status_path = Path(directory) / "status.json"
            status_path.write_text(json.dumps({
                "state": "running",
                "pid": 2_147_483_647,
                "heartbeat_utc": datetime.now(timezone.utc).isoformat(),
            }), encoding="utf-8")
            with patch.object(background_monitor, "STATUS_PATH", status_path):
                result = background_monitor.get_background_status()

        self.assertEqual(result["state"], "stale")
        self.assertFalse(result["running"])

    def test_starting_status_without_a_process_id_is_not_running(self):
        with tempfile.TemporaryDirectory() as directory:
            status_path = Path(directory) / "status.json"
            status_path.write_text(json.dumps({
                "state": "starting",
                "running": True,
                "heartbeat_utc": datetime.now(timezone.utc).isoformat(),
            }), encoding="utf-8")
            with patch.object(background_monitor, "STATUS_PATH", status_path):
                result = background_monitor.get_background_status()

        self.assertEqual(result["state"], "starting")
        self.assertFalse(result["running"])

    def test_running_status_with_old_heartbeat_is_not_running_even_when_pid_exists(self):
        with tempfile.TemporaryDirectory() as directory:
            status_path = Path(directory) / "status.json"
            status_path.write_text(json.dumps({
                "state": "running",
                "running": True,
                "pid": os.getpid(),
                "heartbeat_utc": "2026-11-02T00:00:00+00:00",
            }), encoding="utf-8")
            with (
                patch.object(background_monitor, "STATUS_PATH", status_path),
                patch.object(background_monitor, "_process_is_running", return_value=True),
            ):
                result = background_monitor.get_background_status()

        self.assertEqual(result["state"], "stale")
        self.assertFalse(result["running"])

    def test_startup_wait_tracks_the_service_pid_not_the_windows_venv_launcher_pid(self):
        launcher_pid = 1200
        service_pid = 1201
        monitor_id = "monitor-instance"
        with (
            patch("modules.background_monitor.get_background_status", side_effect=[
                {
                    "state": "starting",
                    "running": False,
                    "pid": launcher_pid,
                    "monitor_id": monitor_id,
                },
                {
                    "state": "running",
                    "running": True,
                    "pid": service_pid,
                    "monitor_id": monitor_id,
                },
            ]),
            patch("modules.background_monitor._process_is_running", return_value=True),
            patch("modules.background_monitor.time.sleep"),
        ):
            result = background_monitor._wait_for_startup(launcher_pid, monitor_id)

        self.assertEqual(result["pid"], service_pid)

    def test_start_uses_a_visible_console_and_persists_selected_scope(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            watched = root / "watched"
            watched.mkdir()
            state = root / "state"
            process = Mock(pid=12345)
            with (
                patch.object(background_monitor, "STATE_DIR", state),
                patch.object(background_monitor, "CONFIG_PATH", state / "config.json"),
                patch.object(background_monitor, "STATUS_PATH", state / "status.json"),
                patch.object(background_monitor, "STOP_REQUEST_PATH", state / "stop.request"),
                patch.object(background_monitor, "MONITOR_LOG_PATH", state / "monitor.log"),
                patch.object(background_monitor, "START_LOCK_PATH", state / "start.lock"),
                patch.object(background_monitor, "AUDIT_LOG_PATH", state / "audit.jsonl"),
                patch.object(background_monitor, "_monitor_mutex_exists", return_value=False),
                patch.object(background_monitor, "_wait_for_startup", return_value={
                    "state": "running",
                    "running": True,
                    "pid": 12345,
                }),
                patch("modules.background_monitor.subprocess.Popen", return_value=process) as popen,
            ):
                status = start_background_monitor([watched])

            command = popen.call_args.args[0]
            config = json.loads((state / "config.json").read_text(encoding="utf-8"))

        self.assertEqual(status["state"], "running")
        self.assertEqual(status["pid"], 12345)
        self.assertIn(subprocess.CREATE_NEW_CONSOLE, [popen.call_args.kwargs["creationflags"]])
        self.assertEqual(Path(command[1]).name, "background_monitor.py")
        self.assertEqual(Path(command[0]), Path(background_monitor.ROOT) / ".venv" / "Scripts" / "python.exe")
        self.assertIn("--config", command)
        self.assertEqual(config["directories"], [str(watched.resolve())])

    def test_start_rejects_an_existing_monitor_mutex(self):
        with tempfile.TemporaryDirectory() as directory:
            watched = Path(directory) / "watched"
            watched.mkdir()
            with (
                patch.object(background_monitor, "STATE_DIR", Path(directory) / "state"),
                patch.object(background_monitor, "START_LOCK_PATH", Path(directory) / "state" / "start.lock"),
                patch.object(background_monitor, "_monitor_mutex_exists", return_value=True),
                patch("modules.background_monitor.subprocess.Popen") as popen,
            ):
                with self.assertRaisesRegex(BackgroundMonitorError, "already running"):
                    start_background_monitor([watched])

        popen.assert_not_called()

    def test_service_publishes_worker_health_and_file_counts_each_heartbeat(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            watched = root / "watched"
            watched.mkdir()
            state = root / "state"
            state.mkdir()
            config_path = state / "config.json"
            config_path.write_text(json.dumps({
                "directories": [str(watched)],
                "monitor_id": "test-monitor-id",
            }), encoding="utf-8")
            stop_path = state / "stop.request"

            monitor = Mock()
            monitor.snapshot.return_value = {
                "files_checked": 7,
                "file_observer_status": "running",
                "file_worker_status": "running",
                "event_monitoring_status": "stopped",
                "last_successful_event_read_utc": None,
                "event_log_errors": [{"Log": "Security", "Error": "access denied"}],
                "queue_dropped": 0,
                "persistence_error": None,
                "yara_available": True,
            }
            monitor.running = False

            def request_stop(_seconds):
                stop_path.write_text("stop", encoding="utf-8")

            with (
                patch.object(background_monitor, "STATE_DIR", state),
                patch.object(background_monitor, "CONFIG_PATH", config_path),
                patch.object(background_monitor, "STATUS_PATH", state / "status.json"),
                patch.object(background_monitor, "STOP_REQUEST_PATH", stop_path),
                patch.object(background_monitor, "AUDIT_LOG_PATH", state / "audit.jsonl"),
                patch.object(background_monitor, "ALERT_LOG_PATH", state / "alerts.jsonl"),
                patch.object(background_monitor, "_create_monitor_mutex", return_value=None),
                patch("modules.background_monitor.RealtimeMonitor", return_value=monitor),
                patch("modules.background_monitor.YaraScanner", return_value=Mock()),
                patch("modules.background_monitor.time.sleep", side_effect=request_stop),
            ):
                result = background_monitor.run_service(config_path)
                status = json.loads((state / "status.json").read_text(encoding="utf-8"))

        self.assertEqual(result, 0)
        self.assertEqual(status["state"], "stopped")
        self.assertEqual(status["monitor_id"], "test-monitor-id")
        self.assertEqual(status["files_checked"], 7)
        self.assertEqual(status["health"]["event_monitoring_status"], "stopped")
        self.assertTrue(status["health"]["event_log_errors"])

    def test_stop_requests_and_waits_for_graceful_shutdown_without_killing_process(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            status_path = root / "status.json"
            audit_path = root / "audit.jsonl"
            stop_path = root / "stop.request"
            status = {
                "state": "running",
                "running": True,
                "pid": 42,
                "heartbeat_utc": "2026-11-02T00:00:00+00:00",
                "directories": [str(root)],
            }

            def process_is_running(pid):
                if not stop_path.exists():
                    return True
                status_path.write_text(json.dumps({
                    **status,
                    "state": "stopped",
                    "running": False,
                }), encoding="utf-8")
                return False

            with (
                patch.object(background_monitor, "STATUS_PATH", status_path),
                patch.object(background_monitor, "AUDIT_LOG_PATH", audit_path),
                patch.object(background_monitor, "STOP_REQUEST_PATH", stop_path),
                patch.object(background_monitor, "STOP_TIMEOUT_SECONDS", 1),
                patch.object(background_monitor, "_process_is_running", side_effect=process_is_running),
                patch(
                    "modules.background_monitor.get_background_status",
                    return_value=status,
                ),
            ):
                result = stop_background_monitor()

            self.assertTrue(stop_path.exists())
            self.assertEqual(result["state"], "stopped")
            self.assertIn('"action": "stop_requested"', audit_path.read_text(encoding="utf-8"))

    def test_startup_registration_requires_explicit_approval(self):
        with self.assertRaises(PermissionError):
            install_startup_task([], user_approved=False)

    def test_persistent_alert_history_is_bounded_and_newest_first(self):
        with tempfile.TemporaryDirectory() as directory:
            alert_path = Path(directory) / "alerts.jsonl"
            alert_path.write_text(
                '{"message":"first"}\n{"message":"second"}\n',
                encoding="utf-8",
            )
            with patch.object(background_monitor, "ALERT_LOG_PATH", alert_path):
                alerts = load_background_alerts(limit=1)

        self.assertEqual(alerts, [{"message": "second"}])
        with self.assertRaises(ValueError):
            load_background_alerts(limit=201)

    def test_invalid_persistent_alert_history_is_reported(self):
        with tempfile.TemporaryDirectory() as directory:
            alert_path = Path(directory) / "alerts.jsonl"
            alert_path.write_text("not json\n", encoding="utf-8")
            with patch.object(background_monitor, "ALERT_LOG_PATH", alert_path):
                with self.assertRaises(BackgroundMonitorError):
                    load_background_alerts()


if __name__ == "__main__":
    unittest.main()
