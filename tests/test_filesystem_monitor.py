"""Filesystem coalescing, moves, bounded retries, and harmless watchdog checks."""
import hashlib
import os
import subprocess
from pathlib import Path
import queue
import tempfile
import threading
import time
import unittest
from unittest.mock import Mock, patch

from watchdog.events import FileCreatedEvent, FileDeletedEvent, FileModifiedEvent, FileMovedEvent

from modules.filesystem_monitor import CoalescingFileQueue, bounded_inspection, inspect_candidate
from modules.realtime_monitor import RealtimeMonitor, _ChangeHandler
from modules.yara_scanner import YARA_AVAILABLE, YaraScanner


MARKER = b"HARMLESS_FORENSICS_MARKER"


class MarkerScanner:
    ready = True
    cache_signature = "initial rules"

    def __init__(self):
        self.calls = 0
        self.rule = "Harmless_File_Marker"

    def scan_file(self, path, timeout=5):
        self.calls += 1
        data = Path(path).read_bytes()
        if MARKER not in data:
            return []
        return [{"id": "Y-001", "rule": self.rule, "severity": "High",
                 "description": "Harmless regression marker.", "sha256": hashlib.sha256(data).hexdigest(),
                 "file": Path(path).name, "matches": [{"line": 1, "offset": 0, "string": "$marker"}],
                 "matched_strings": ["$marker"], "custom_metadata": "preserve"}]


class SlowScanner(MarkerScanner):
    def scan_file(self, path, timeout=5):
        time.sleep(60)
        return []


class FilesystemMonitorTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.watched = self.root / "watched"
        self.watched.mkdir()
        self.scanner = MarkerScanner()
        self.monitor = RealtimeMonitor([self.watched], self.scanner,
                                       cursor_path=self.root / "cursors.json", event_logs=())
        quiet = patch("modules.filesystem_monitor.QUIET_SECONDS", 0)
        quiet.start()
        self.addCleanup(quiet.stop)
        retries = patch("modules.realtime_monitor.RETRY_DELAYS", (0, 0, 0))
        retries.start()
        self.addCleanup(retries.stop)
        self.inspector = patch.object(self.monitor, "_inspect_file", side_effect=self.inline_inspect)
        self.inspector.start()
        self.addCleanup(self.inspector.stop)

    def inline_inspect(self, task, previous):
        with patch("modules.filesystem_monitor.time.sleep"):
            return inspect_candidate(task.path, self.scanner, previous, self.monitor.directories, task.is_directory)

    def write(self, name="marker.txt", data=MARKER):
        path = self.watched / name
        path.write_bytes(data)
        return path

    def drain(self, maximum=20):
        for _ in range(maximum):
            if not self.monitor._queue.pending_count():
                return
            task = self.monitor._queue.take(self.monitor._stop)
            self.monitor._scan_changed_file(task.path, task.change, task)
        self.fail("Filesystem work did not finish within its retry bound")

    def detections(self):
        return [item for item in self.monitor.snapshot()["alerts"] if item["source"] == "YARA"]

    def test_watchdog_move_handler_schedules_destination_and_preserves_source(self):
        outside = self.root / "incoming.txt"
        outside.write_bytes(MARKER)
        destination = self.watched / "incoming.txt"
        outside.rename(destination)
        _ChangeHandler(self.monitor._enqueue_file).on_moved(FileMovedEvent(str(outside), str(destination)))
        self.drain()
        evidence = self.detections()[0]["evidence"]
        self.assertEqual(evidence["path"], str(destination))
        self.assertEqual(evidence["original_path"], str(outside))
        self.assertEqual(evidence["destination_path"], str(destination))
        self.assertEqual(evidence["sha256"], hashlib.sha256(MARKER).hexdigest())
        self.assertEqual(evidence["custom_metadata"], "preserve")
        self.assertTrue(evidence["first_seen_utc"])
        self.assertTrue(evidence["file_mtime_utc"])

    def test_internal_rename_rescans_name_context_without_duplicate_threat_alert(self):
        source = self.write()
        self.monitor._enqueue_file(str(source), "created")
        self.drain()
        destination = self.watched / "renamed.txt"
        source.rename(destination)
        self.monitor._enqueue_file(str(destination), "moved", original_path=str(source))
        self.drain()
        self.assertEqual(len(self.detections()), 1)
        notice = next(item for item in self.monitor.snapshot()["alerts"] if "Previously analyzed" in item["message"])
        self.assertEqual(notice["evidence"]["path"], str(destination))
        self.assertEqual(notice["evidence"]["related_findings"][0]["custom_metadata"], "preserve")
        # Watchdog may report the same move more than once; neither the threat
        # nor its relocation notice should be duplicated.
        self.monitor._enqueue_file(str(destination), "moved", original_path=str(source))
        self.drain()
        self.assertEqual(len(self.detections()), 1)
        self.assertEqual(len([item for item in self.monitor.snapshot()["alerts"]
                              if "Previously analyzed" in item["message"]]), 1)

    def test_name_dependent_new_detection_is_not_suppressed(self):
        source = self.write()
        self.monitor._enqueue_file(str(source), "created")
        self.drain()
        destination = self.watched / "document.pdf.exe"
        source.rename(destination)
        self.monitor._enqueue_file(str(destination), "moved", original_path=str(source))
        self.drain()
        self.assertEqual(len(self.detections()), 1)
        heuristics = [item for item in self.monitor.snapshot()["alerts"] if item["source"] == "Static heuristic"]
        self.assertTrue(any("double-extension" in item["message"] for item in heuristics))

    def test_rapid_changes_coalesce_into_final_content_scan(self):
        path = self.write(data=b"initial")
        self.monitor._enqueue_file(str(path), "created")
        for number in range(20):
            path.write_bytes(MARKER + str(number).encode())
            _ChangeHandler(self.monitor._enqueue_file).on_modified(FileModifiedEvent(str(path)))
        self.assertEqual(self.monitor._queue.pending_count(), 1)
        self.drain()
        self.assertEqual(self.scanner.calls, 1)
        self.assertEqual(self.detections()[0]["evidence"]["sha256"], hashlib.sha256(path.read_bytes()).hexdigest())

    def test_event_during_active_scan_retains_a_final_scan(self):
        path = self.write()
        self.monitor._enqueue_file(str(path), "created")
        first = self.monitor._queue.take(self.monitor._stop)
        result = self.inline_inspect(first, None)
        with patch.object(self.monitor, "_inspect_file", return_value=result):
            path.write_bytes(MARKER + b" final content")
            self.monitor._enqueue_file(str(path), "modified")
            self.monitor._scan_changed_file(first.path, first.change, first)
        self.assertEqual(self.monitor._queue.pending_count(), 1)
        self.drain()
        self.assertEqual(len(self.detections()), 2)
        self.assertEqual(self.detections()[0]["evidence"]["sha256"], hashlib.sha256(path.read_bytes()).hexdigest())

    def test_temporarily_locked_file_is_retried_and_eventually_scanned(self):
        path = self.write()
        self.monitor._enqueue_file(str(path), "created")
        result = inspect_candidate(path, self.scanner, roots=self.monitor.directories)
        with patch.object(self.monitor, "_inspect_file", side_effect=[PermissionError("locked"), OSError("incomplete"), result]) as inspect:
            self.drain()
        self.assertEqual(inspect.call_count, 3)
        self.assertEqual(len(self.detections()), 1)
        self.assertEqual(self.detections()[0]["evidence"]["inspection_attempt"], 3)

    def test_retry_exhaustion_is_bounded_and_reported(self):
        path = self.write()
        self.monitor._enqueue_file(str(path), "created")
        with patch.object(self.monitor, "_inspect_file", side_effect=PermissionError("access denied")) as inspect:
            self.drain()
        self.assertEqual(inspect.call_count, 4)
        self.assertEqual(self.monitor._queue.pending_count(), 0)
        self.assertTrue(any("retries exhausted" in item["message"] for item in self.monitor.snapshot()["alerts"]))

    def test_incomplete_results_are_retried_without_duplicate_detections(self):
        path = self.write()
        self.monitor._enqueue_file(str(path), "created")
        result = inspect_candidate(path, self.scanner, roots=self.monitor.directories)
        partial = {**result, "complete": False, "result": {**result["result"], "warnings": ["Archive still incomplete"]}}
        with patch.object(self.monitor, "_inspect_file", side_effect=[partial, partial, result]):
            self.drain()
        self.assertEqual(len(self.detections()), 1)

    def test_new_monitor_instance_does_not_reuse_stale_rule_cache(self):
        path = self.write()
        self.monitor._enqueue_file(str(path), "created")
        self.drain()
        scanner = MarkerScanner()
        scanner.rule = "Updated_After_Restart"
        restarted = RealtimeMonitor([self.watched], scanner, cursor_path=self.root / "cursors.json", event_logs=())
        def inspect(task, previous):
            with patch("modules.filesystem_monitor.time.sleep"):
                return inspect_candidate(task.path, scanner, previous, restarted.directories)
        with patch.object(restarted, "_inspect_file", side_effect=inspect):
            restarted._scan_changed_file(str(path), "modified")
        self.assertEqual(restarted.snapshot()["alerts"][0]["evidence"]["rule"], "Updated_After_Restart")

    def test_unchanged_content_skips_repeat_analysis_but_changed_content_is_scanned(self):
        path = self.write()
        self.monitor._enqueue_file(str(path), "created")
        self.drain()
        path.write_bytes(MARKER)
        self.monitor._enqueue_file(str(path), "modified")
        self.drain()
        self.assertEqual(self.scanner.calls, 1)
        self.assertEqual(len(self.detections()), 1)
        path.write_bytes(MARKER + b" genuinely changed")
        self.monitor._enqueue_file(str(path), "modified")
        self.drain()
        self.assertEqual(self.scanner.calls, 2)
        self.assertEqual(len(self.detections()), 2)

    def test_changed_rules_trigger_new_analysis_and_new_detection(self):
        path = self.write()
        self.monitor._enqueue_file(str(path), "created")
        self.drain()
        self.scanner.cache_signature = "new rules"
        self.scanner.rule = "New_Harmless_Rule"
        self.monitor._enqueue_file(str(path), "modified")
        self.drain()
        self.assertEqual({item["evidence"]["rule"] for item in self.detections()},
                         {"Harmless_File_Marker", "New_Harmless_Rule"})

    def test_identical_copy_at_new_path_is_not_suppressed(self):
        first = self.write()
        self.monitor._enqueue_file(str(first), "created")
        self.drain()
        second = self.write("another.txt")
        self.monitor._enqueue_file(str(second), "created")
        self.drain()
        self.assertEqual(len(self.detections()), 2)

    def test_deleted_queued_file_is_cancelled_without_retry_loop(self):
        path = self.write()
        handler = _ChangeHandler(self.monitor._enqueue_file)
        handler.on_created(FileCreatedEvent(str(path)))
        path.unlink()  # Only this temporary fixture.
        handler.on_deleted(FileDeletedEvent(str(path)))
        self.assertEqual(self.monitor._queue.pending_count(), 0)
        self.assertEqual(self.scanner.calls, 0)
        self.assertTrue(any("deleted" in item["message"] for item in self.monitor.snapshot()["alerts"]))

    def test_disappearing_file_is_reported_and_has_bounded_retries(self):
        path = self.write()
        self.monitor._enqueue_file(str(path), "created")
        path.unlink()
        self.drain()
        self.assertEqual(self.scanner.calls, 0)
        self.assertEqual(self.monitor._queue.pending_count(), 0)

    def test_move_outside_scope_never_scans_the_destination(self):
        source = self.write()
        self.monitor._enqueue_file(str(source), "created")
        destination = self.root / "outside.txt"
        source.rename(destination)
        self.monitor._enqueue_file(str(destination), "moved", original_path=str(source))
        self.assertEqual(self.monitor._queue.pending_count(), 0)
        self.assertEqual(self.scanner.calls, 0)

    def test_moved_directory_enumerates_supported_files(self):
        source = self.root / "outside_folder"
        source.mkdir()
        (source / "marker.txt").write_bytes(MARKER)
        destination = self.watched / "folder"
        source.rename(destination)
        self.monitor._enqueue_file(str(destination), "moved", original_path=str(source), is_directory=True)
        self.drain()
        self.assertEqual(len(self.detections()), 1)
        self.assertEqual(self.detections()[0]["evidence"]["original_path"], str(source / "marker.txt"))

    def test_same_monitor_restart_resumes_cancelled_work_and_shuts_down(self):
        path = self.write()
        self.monitor._enqueue_file(str(path), "created")
        entered = threading.Event()
        def wait_for_stop(task, previous):
            entered.set()
            self.monitor._stop.wait(timeout=3)
            return {"status": "cancelled"}
        with patch.object(self.monitor, "_inspect_file", side_effect=wait_for_stop):
            self.monitor.start()
            self.assertTrue(entered.wait(timeout=2))
            self.monitor.stop()
        self.assertFalse(self.monitor.running)
        self.assertEqual(self.monitor._queue.pending_count(), 1)
        self.monitor.start()
        try:
            deadline = time.monotonic() + 3
            while not self.detections() and time.monotonic() < deadline:
                time.sleep(0.02)
            self.assertEqual(len(self.detections()), 1)
        finally:
            self.monitor.stop()
        self.assertFalse(self.monitor.running)


class CoalescingQueueTests(unittest.TestCase):
    def test_trailing_scan_is_scheduled_after_last_rapid_event(self):
        queue = CoalescingFileQueue(2)
        with patch("modules.filesystem_monitor.time.monotonic", return_value=10):
            queue.schedule("file.txt", "created")
        with patch("modules.filesystem_monitor.time.monotonic", return_value=10.2):
            queue.schedule("file.txt", "modified")
        with patch("modules.filesystem_monitor.time.monotonic", return_value=11):
            task = queue.take(threading.Event())
        self.assertEqual(task.last_seen, 10.2)
        self.assertAlmostEqual(task.due, 10.6)

    def test_full_queue_still_coalesces_existing_path(self):
        work = CoalescingFileQueue(1)
        work.schedule("file.txt", "created")
        work.schedule("file.txt", "modified")
        self.assertEqual(work.pending_count(), 1)
        with self.assertRaises(queue.Full):
            work.schedule("another.txt", "created")

    def test_directory_delete_cancels_pending_children(self):
        work = CoalescingFileQueue(3)
        directory = str(Path.cwd() / "temporary_queue_path")
        work.schedule(str(Path(directory) / "child.txt"), "created")
        self.assertTrue(work.cancel(directory, recursive=True))
        self.assertEqual(work.pending_count(), 0)

    def test_rapid_rename_chain_retains_original_and_intermediate_paths(self):
        work = CoalescingFileQueue(3)
        with patch("modules.filesystem_monitor.QUIET_SECONDS", 0):
            work.schedule("first.txt", "created")
            work.schedule("second.txt", "moved", original_path="first.txt")
            work.schedule("third.txt", "moved", original_path="second.txt")
            task = work.take(threading.Event())
        self.assertEqual(task.original_path, "first.txt")
        self.assertEqual(task.source_path, "second.txt")
        self.assertEqual(task.original_paths, ("first.txt", "second.txt"))


class BoundedInspectionTests(unittest.TestCase):
    def test_slow_scanner_is_terminated_within_bound(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "harmless.txt"
            path.write_bytes(MARKER)
            children = []
            original_popen = subprocess.Popen
            def launch(*args, **kwargs):
                child = original_popen(*args, **kwargs)
                children.append(child)
                self.assertIn("modules.filesystem_monitor", args[0])
                return child
            started = time.monotonic()
            with patch("modules.filesystem_monitor.subprocess.Popen", side_effect=launch):
                result = bounded_inspection(str(path), SlowScanner(), None, [directory], False,
                                            threading.Event(), timeout=0.5)
            self.assertEqual(result["status"], "retry")
            self.assertLess(time.monotonic() - started, 3)
            self.assertTrue(all(child.poll() is not None for child in children))
            self.assertEqual(path.read_bytes(), MARKER)

    def test_stopped_monitor_cancels_helper_without_modifying_file(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "harmless.txt"
            path.write_bytes(MARKER)
            stop = threading.Event()
            stop.set()
            result = bounded_inspection(str(path), SlowScanner(), None, [directory], False, stop)
            self.assertEqual(result["status"], "cancelled")
            self.assertEqual(path.read_bytes(), MARKER)

    def test_python_candidate_is_read_as_data_and_never_executed(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "do_not_execute.py"
            data = b'raise RuntimeError("This candidate must not be executed")\n'
            path.write_bytes(data)
            result = bounded_inspection(str(path), MarkerScanner(), None, [directory], False,
                                        threading.Event(), timeout=4)
            self.assertEqual(result["status"], "scanned")
            self.assertEqual(path.read_bytes(), data)

    @unittest.skipUnless(os.name == "nt", "Windows sharing-lock integration")
    def test_real_windows_sharing_lock_can_be_retried_after_release(self):
        import ctypes
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "locked.txt"
            path.write_bytes(MARKER)
            kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
            kernel32.CreateFileW.argtypes = [ctypes.c_wchar_p, ctypes.c_uint32, ctypes.c_uint32,
                                             ctypes.c_void_p, ctypes.c_uint32, ctypes.c_uint32, ctypes.c_void_p]
            kernel32.CreateFileW.restype = ctypes.c_void_p
            kernel32.CloseHandle.argtypes = [ctypes.c_void_p]
            handle = kernel32.CreateFileW(str(path), 0x80000000, 0, None, 3, 128, None)
            self.assertNotEqual(handle, ctypes.c_void_p(-1).value)
            try:
                locked = bounded_inspection(str(path), MarkerScanner(), None, [directory], False,
                                            threading.Event(), timeout=4)
                self.assertEqual(locked["status"], "retry")
            finally:
                kernel32.CloseHandle(handle)
            released = bounded_inspection(str(path), MarkerScanner(), None, [directory], False,
                                          threading.Event(), timeout=4)
            self.assertEqual(released["status"], "scanned")
            self.assertEqual(path.read_bytes(), MARKER)


@unittest.skipUnless(YARA_AVAILABLE, "yara-python is required for real integration")
class HarmlessFilesystemIntegrationTests(unittest.TestCase):
    def test_real_watchdog_move_in_and_rename_preserve_file_bytes_and_deduplicate(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            watched = root / "watched"
            watched.mkdir()
            source = root / "outside.txt"
            data = b"AEGIS_YARA_TEST_MARKER_2026\n"
            source.write_bytes(data)
            monitor = RealtimeMonitor([watched], YaraScanner(), alert_log_path=root / "alerts.jsonl",
                                       cursor_path=root / "cursors.json", event_logs=())
            monitor.start()
            try:
                destination = watched / "incoming.txt"
                source.rename(destination)
                deadline = time.monotonic() + 10
                while monitor.snapshot()["files_checked"] < 1 and time.monotonic() < deadline:
                    time.sleep(0.05)
                alerts = [item for item in monitor.snapshot()["alerts"] if item["source"] == "YARA"]
                self.assertEqual(len(alerts), 1)
                self.assertEqual(alerts[0]["evidence"]["path"], str(destination))
                renamed = watched / "renamed.txt"
                destination.rename(renamed)
                deadline = time.monotonic() + 10
                while not any("Previously analyzed" in item["message"] for item in monitor.snapshot()["alerts"]) and time.monotonic() < deadline:
                    time.sleep(0.05)
                self.assertTrue(any("Previously analyzed" in item["message"] for item in monitor.snapshot()["alerts"]))
                self.assertEqual(len([item for item in monitor.snapshot()["alerts"] if item["source"] == "YARA"]), 1)
                self.assertEqual(renamed.read_bytes(), data)
            finally:
                monitor.stop()
            self.assertFalse(monitor.running)

    def test_rule_content_changes_invalidate_cache_even_when_mtime_is_preserved(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            watched = root / "watched"
            watched.mkdir()
            rules = root / "rules"
            rules.mkdir()
            rule = rules / "test.yar"
            rule.write_text("rule First { condition: true }", encoding="utf-8")
            path = watched / "harmless.txt"
            path.write_text("harmless fixture", encoding="utf-8")
            monitor = RealtimeMonitor([watched], YaraScanner(rules), cursor_path=root / "cursors.json", event_logs=())
            monitor._scan_changed_file(str(path), "created")
            old_stat = rule.stat()
            rule.write_text("rule Other { condition: true }", encoding="utf-8")
            os.utime(rule, ns=(old_stat.st_atime_ns, old_stat.st_mtime_ns))
            monitor._scan_changed_file(str(path), "modified")
            self.assertEqual({item["evidence"]["rule"] for item in monitor.snapshot()["alerts"] if item["source"] == "YARA"}, {"First", "Other"})


if __name__ == "__main__":
    unittest.main()
