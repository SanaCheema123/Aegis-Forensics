"""Low-overhead local Watchdog and Windows event monitoring."""
from __future__ import annotations

import ipaddress
import hashlib
import json
import os
import queue
import threading
import time
import uuid
from collections.abc import Sequence
from collections import deque, OrderedDict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from watchdog.events import FileSystemEvent, FileSystemEventHandler
from watchdog.observers import Observer

from modules.laptop_scanner import _is_reparse_point
from modules.safety_checks import SCAN_EXTENSIONS
from modules.behavioral_detection import BehavioralDetector
from modules.event_polling import CursorStore, persist_event_alerts
from modules.integrity import audit_lock
from modules.filesystem_monitor import (
    CoalescingFileQueue, FileTask, MAX_CACHE_ENTRIES, RETRY_DELAYS,
    SCAN_TIMEOUT_SECONDS, TASK_TIMEOUT_SECONDS, bounded_inspection, path_key,
)
from modules.windows_security import (
    SECURITY_EVENT_LOGS,
    WindowsSecurityError,
    normalize_security_event,
    read_security_event_page,
)

MAX_ALERTS = 200
MAX_SECURITY_EVENTS = 500
MAX_TRACKED_SECURITY_EVENTS = 10000
MAX_PENDING_FILES = 100
EVENT_POLL_SECONDS = 60
MAX_PERSISTENT_ALERT_LOG_BYTES = 20 * 1024 * 1024
EVENT_PAGE_SIZE = 200
MAX_EVENT_PAGES_PER_LOG = 4
EVENT_POLL_BUDGET_SECONDS = 25
DEFAULT_CURSOR_PATH = Path(__file__).resolve().parents[1] / "reports" / "background_monitor" / "event_cursors.json"
SYNTHETIC_EVENT_TEMPLATES = {
    4624: "Synthetic successful logon event for demonstration.",
    4625: "Synthetic failed logon event for demonstration.",
    4672: "Synthetic special-privileges event for demonstration.",
    4720: "Synthetic account-created event for demonstration.",
    4732: "Synthetic local-group membership event for demonstration.",
    1102: "Synthetic Security-log-cleared event for demonstration.",
    7045: "Synthetic service-install event for demonstration.",
}
SECURITY_EVENT_SEVERITY = {
    4625: "Medium",
    1102: "High",
    4672: "Medium",
    4720: "Medium",
    4722: "Medium",
    4723: "Medium",
    4724: "Medium",
    4725: "Medium",
    4726: "High",
    4728: "High",
    4732: "High",
    4733: "Medium",
    4735: "High",
    4756: "High",
    4757: "High",
    4104: "Medium",
    7045: "Medium",
    1116: "High",
}


def make_synthetic_security_event(event_id: int) -> dict[str, Any]:
    """Create a clearly marked demo record without reading or writing Windows logs."""
    try:
        normalized_id = int(event_id)
    except (TypeError, ValueError) as exc:
        raise ValueError("Choose a supported synthetic event ID.") from exc
    message = SYNTHETIC_EVENT_TEMPLATES.get(normalized_id)
    if message is None:
        raise ValueError("Choose a supported synthetic event ID.")

    event = normalize_security_event({
        "Log": "Synthetic demonstration only",
        "EventId": normalized_id,
        "Time": datetime.now(timezone.utc).isoformat(),
        "RecordId": f"SYNTHETIC-{uuid.uuid4().hex[:12]}",
        "Provider": "Aegis Synthetic Demo",
        "Message": message,
        "EventData": {
            "TargetUserName": "demo-user",
            "TargetDomainName": "AEGIS-DEMO",
            "LogonType": "3",
            "IpAddress": "192.0.2.10",
        },
        "synthetic": True,
        "source_type": "synthetic",
    })
    classification, reasons = classify_security_event(event)
    return {
        **event,
        "synthetic": True,
        "source_type": "synthetic",
        "classification": classification,
        "classification_reasons": reasons,
    }


def _event_key(event: dict[str, Any]) -> tuple[str, str, str, str, str]:
    return (
        str(event.get("Log", "")),
        str(event.get("EventId", "")),
        str(event.get("Time", "")),
        str(event.get("Provider", "")),
        str(event.get("RecordId", "")) + ":" + str(event.get("Fingerprint", "")),
    )


def classify_security_event(event: dict[str, Any]) -> tuple[str, list[str]]:
    event = normalize_security_event(event)
    try:
        event_id = int(event.get("EventId", 0))
    except (TypeError, ValueError):
        return "Normal", []

    if event_id == 4624:
        evidence = []
        if event.get("suspicious_evidence"):
            raw_evidence = event["suspicious_evidence"]
            evidence.extend(raw_evidence if isinstance(raw_evidence, list) else [str(raw_evidence)])
        if str(event.get("logon_type", "")) == "5" and event.get("source_ip"):
            source_ip = str(event["source_ip"])
            try:
                address = ipaddress.ip_address(source_ip)
                if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
                    address = address.ipv4_mapped
                is_local = address.is_loopback or address.is_unspecified
            except ValueError:
                is_local = source_ip.casefold() in {"localhost", "local"}
            if not is_local:
                evidence.append(f"Service logon reported non-local source IP {source_ip}.")
        return ("Suspicious", evidence) if evidence else ("Normal", [])

    if event_id in SECURITY_EVENT_SEVERITY:
        return "Needs review", ["This event type is a security-relevant signal; verify it is expected."]
    return "Normal", []


def _security_alert(event: dict[str, Any]) -> dict[str, Any] | None:
    event = normalize_security_event(event)
    classification, reasons = classify_security_event(event)
    if classification == "Normal":
        return None
    try:
        event_id = int(event.get("EventId", 0))
    except (TypeError, ValueError):
        return None
    severity = SECURITY_EVENT_SEVERITY.get(event_id, "Medium")
    labels = {
        4624: "Windows service logon requires review",
        4625: "Failed Windows logon attempt",
        1102: "Windows Security audit log cleared",
        4672: "Special privileges assigned to a new logon",
        4720: "Windows user account created",
        4722: "Windows user account enabled",
        4723: "Windows account password change attempted",
        4724: "Windows account password reset attempted",
        4725: "Windows user account disabled",
        4726: "Windows user account deleted",
        4728: "Member added to a privileged global group",
        4732: "Member added to a privileged local group",
        4733: "Member removed from a privileged local group",
        4735: "Privileged local group changed",
        4756: "Member added to a privileged universal group",
        4757: "Member removed from a privileged universal group",
        7045: "New Windows service installed",
        4104: "PowerShell script-block event",
        1116: "Microsoft Defender detection event",
    }
    return {
        "created_at_utc": datetime.now(timezone.utc).isoformat(),
        "severity": severity,
        "source": "Windows event log",
        "message": labels[event_id],
        "evidence": {
            "log": event.get("Log"),
            "event_id": event_id,
            "record_id": event.get("RecordId"),
            "time": event.get("Time"),
            "time_utc": event.get("TimeUtc"),
            "provider": event.get("Provider"),
            "event_data": event.get("EventData", {}),
            "account": event.get("account"),
            "logon_type": event.get("logon_type"),
            "source_ip": event.get("source_ip"),
            "description": str(event.get("description", ""))[:1000],
            "classification": classification,
            "classification_reasons": reasons,
        },
    }


class _ChangeHandler(FileSystemEventHandler):
    def __init__(self, enqueue):
        self._enqueue = enqueue

    def on_created(self, event: FileSystemEvent) -> None:
        self._enqueue(event.src_path, "created", is_directory=event.is_directory)

    def on_modified(self, event: FileSystemEvent) -> None:
        if not event.is_directory:
            self._enqueue(event.src_path, "modified")

    def on_moved(self, event: FileSystemEvent) -> None:
        self._enqueue(event.dest_path, "moved", original_path=event.src_path,
                      is_directory=event.is_directory)

    def on_deleted(self, event: FileSystemEvent) -> None:
        self._enqueue(event.src_path, "deleted", is_directory=event.is_directory)


class RealtimeMonitor:
    """Manage an explicitly started observer, bounded work queue, and alert buffer."""

    def __init__(
        self,
        directories: Sequence[str | Path],
        scanner: Any,
        event_poll_seconds: int = EVENT_POLL_SECONDS,
        alert_log_path: str | Path | None = None,
        cursor_path: str | Path | None = None,
        event_logs: Sequence[str] | None = None,
    ):
        expanded = [Path(path).expanduser() for path in directories]
        if not expanded:
            raise ValueError("Choose at least one directory to monitor.")
        for directory in expanded:
            if not directory.is_dir() or _is_reparse_point(directory):
                raise ValueError(f"Cannot monitor this directory: {directory}")
        self.directories = [directory.resolve() for directory in expanded]
        self.scanner = scanner
        self.alert_log_path = Path(alert_log_path) if alert_log_path is not None else None
        self.cursor_path = Path(cursor_path) if cursor_path is not None else (
            self.alert_log_path.parent / "event_cursors.json" if self.alert_log_path else DEFAULT_CURSOR_PATH
        )
        self._event_store = CursorStore(self.cursor_path)
        self._event_alert_path = self.alert_log_path or self.cursor_path.with_suffix(".alerts.jsonl")
        self._event_logs = tuple(event_logs) if event_logs is not None else tuple(SECURITY_EVENT_LOGS)
        if any(name not in SECURITY_EVENT_LOGS for name in self._event_logs):
            raise ValueError("Unsupported event log selected for monitoring.")
        self._poll_failures: dict[str, str] = {}
        self._event_log_offset = 0
        self.event_poll_seconds = max(10, event_poll_seconds)
        self._observer = Observer()
        self._queue = CoalescingFileQueue(MAX_PENDING_FILES)
        self._file_cache = OrderedDict()
        self._alerts: deque[dict[str, Any]] = deque(maxlen=MAX_ALERTS)
        self._security_events: deque[dict[str, Any]] = deque(maxlen=MAX_SECURITY_EVENTS)
        self._lock = threading.Lock()
        self._alert_log_lock = threading.Lock()
        self._stop = threading.Event()
        self._worker: threading.Thread | None = None
        self._event_worker: threading.Thread | None = None
        self._seen_event_keys: set[tuple[str, str, str, str, str]] = set()
        self._seen_event_order: deque[tuple[str, str, str, str, str]] = deque()
        self._event_log_errors: list[dict[str, Any]] = []
        self._last_successful_event_read_utc: str | None = None
        self._security_event_count = 0
        self._normal_event_count = 0
        self._security_alert_count = 0
        self._files_checked = 0
        self._queue_dropped = 0
        self._persistence_error: str | None = None

    @property
    def running(self) -> bool:
        return any(
            worker is not None and worker.is_alive()
            for worker in (self._worker, self._event_worker)
        )

    def start(self) -> None:
        if self.running:
            raise RuntimeError("Real-time monitoring is already running.")
        self._stop.clear()
        self._queue.resume()
        self._observer = Observer()
        handler = _ChangeHandler(self._enqueue_file)
        for directory in self.directories:
            self._observer.schedule(handler, str(directory), recursive=True)
        try:
            self._observer.start()
            self._worker = threading.Thread(
                target=self._run,
                name="aegis-file-monitor",
                daemon=True,
            )
            self._event_worker = threading.Thread(
                target=self._run_event_monitor,
                name="aegis-event-monitor",
                daemon=True,
            )
            self._worker.start()
            self._event_worker.start()
        except RuntimeError:
            self._stop.set()
            self._observer.stop()
            if self._observer.is_alive():
                self._observer.join(timeout=5)
            raise

    def stop(self) -> None:
        self._stop.set()
        self._queue.wake()
        self._observer.stop()
        if self._observer.is_alive():
            self._observer.join(timeout=5)
        if self._worker is not None:
            self._worker.join(timeout=5)
        if self._event_worker is not None:
            self._event_worker.join(timeout=5)

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            return {
                "running": self.running,
                "directories": [str(path) for path in self.directories],
                "alerts": list(reversed(self._alerts)),
                "security_events": list(reversed(self._security_events)),
                "file_observer_status": "running" if self._observer.is_alive() else "stopped",
                "file_worker_status": (
                    "running" if self._worker is not None and self._worker.is_alive() else "stopped"
                ),
                "security_event_count": self._security_event_count,
                "normal_event_count": self._normal_event_count,
                "security_alert_count": self._security_alert_count,
                "event_monitoring_status": (
                    "running"
                    if self._event_worker is not None and self._event_worker.is_alive()
                    else "stopped"
                ),
                "last_successful_event_read_utc": self._last_successful_event_read_utc,
                "event_log_errors": list(self._event_log_errors),
                "files_checked": self._files_checked,
                "queue_dropped": self._queue_dropped,
                "persistence_error": self._persistence_error,
                "yara_available": bool(self.scanner.ready),
            }

    def _add_alert(self, alert: dict[str, Any]) -> None:
        with self._lock:
            self._alerts.append(alert)
        if self.alert_log_path is None:
            return
        try:
            entry = json.dumps(alert, ensure_ascii=True, default=str)
            with self._alert_log_lock, audit_lock(self.alert_log_path, timeout=2):
                self.alert_log_path.parent.mkdir(parents=True, exist_ok=True)
                current_size = (
                    self.alert_log_path.stat().st_size
                    if self.alert_log_path.exists()
                    else 0
                )
                entry_size = len(entry.encode("utf-8")) + 1
                if current_size + entry_size > MAX_PERSISTENT_ALERT_LOG_BYTES:
                    raise OSError(
                        "Persistent alert history reached its 20 MB limit; "
                        "no existing records were removed."
                    )
                with self.alert_log_path.open("a", encoding="utf-8") as log_file:
                    log_file.write(entry + "\n")
            with self._lock:
                self._persistence_error = None
        except OSError as exc:
            with self._lock:
                self._persistence_error = str(exc)

    def _in_scope(self, path):
        absolute = Path(os.path.abspath(str(path)))
        return any(absolute.is_relative_to(root) for root in self.directories)

    def _enqueue_file(self, raw_path: str, change: str, original_path=None, is_directory=False) -> None:
        path = Path(os.path.abspath(str(raw_path)))
        if change == "deleted" or not self._in_scope(path):
            removed = self._queue.cancel(original_path or path, recursive=is_directory)
            with self._lock:
                self._file_cache.pop(path_key(original_path or path), None)
                if is_directory:
                    for cached_path in list(self._file_cache):
                        if Path(cached_path).is_relative_to(Path(path_key(original_path or path))):
                            self._file_cache.pop(cached_path)
            if removed:
                self._add_alert({
                    "created_at_utc": datetime.now(timezone.utc).isoformat(),
                    "severity": "Low", "source": "File monitor",
                    "message": "Queued file was deleted or moved out of scope before inspection completed.",
                    "evidence": {"path": str(path), "original_path": original_path, "change": change},
                })
            return
        if (not is_directory and path.suffix.lower() not in SCAN_EXTENSIONS
                and not (original_path and Path(original_path).suffix.lower() in SCAN_EXTENSIONS)):
            return
        try:
            self._queue.schedule(str(path), change, original_path, is_directory)
        except queue.Full:
            with self._lock:
                self._queue_dropped += 1
            self._add_alert({
                "created_at_utc": datetime.now(timezone.utc).isoformat(),
                "severity": "Medium", "source": "Monitor capacity",
                "message": "Filesystem pending-path limit reached; this path was not scheduled. Coverage is incomplete.",
                "evidence": {"path": str(path), "original_path": original_path},
            })

    @staticmethod
    def _file_event_metadata(task):
        return {
            "original_path": task.original_path, "source_path": task.source_path,
            "original_paths": list(task.original_paths), "destination_path": task.path,
            "change": task.change, "first_seen_utc": task.first_seen_utc,
            "last_seen_utc": task.last_seen_utc, "inspection_attempt": task.attempts + 1,
        }

    @staticmethod
    def _finding_fingerprint(finding):
        # Location changes alone must not create a second copy of a detection.
        excluded = {"path", "file", "container_path", "member_path", "container",
                    "source_filename", "id", "scanned_at_utc"}
        def clean(value):
            if isinstance(value, dict):
                return {key: clean(item) for key, item in value.items() if key not in excluded}
            if isinstance(value, list):
                return [clean(item) for item in value]
            return value
        return hashlib.sha256(json.dumps(clean(finding), sort_keys=True, default=str).encode()).hexdigest()

    def _publish_file_alerts(self, alerts):
        if self.alert_log_path is not None:
            persist_event_alerts(self.alert_log_path, alerts, MAX_PERSISTENT_ALERT_LOG_BYTES)
        with self._lock:
            existing = {item.get("event_uid") for item in self._alerts}
            for alert in alerts:
                if alert["event_uid"] not in existing:
                    self._alerts.append(alert)
                    existing.add(alert["event_uid"])

    def _inspect_file(self, task, expected):
        remaining = TASK_TIMEOUT_SECONDS - (time.monotonic() - task.first_seen)
        if remaining <= 0:
            return {"status": "retry", "reason": "Inspection task reached its lifetime limit."}
        return bounded_inspection(task.path, self.scanner, expected, self.directories,
                                  task.is_directory, self._stop,
                                  timeout=min(SCAN_TIMEOUT_SECONDS, remaining))

    def _scan_changed_file(self, raw_path: str, change: str, task=None) -> None:
        now = time.monotonic()
        timestamp = datetime.now(timezone.utc).isoformat()
        task = task or FileTask(os.path.abspath(str(raw_path)), change, now, now, timestamp, timestamp,
                                now, uuid.uuid4().hex)
        retry_delay = None
        increment = True
        metadata = self._file_event_metadata(task)
        try:
            with self._lock:
                candidates = [task.path, *reversed(task.original_paths)]
                previous = next((self._file_cache[path_key(path)] for path in candidates
                                 if path_key(path) in self._file_cache), None)
            outcome = self._inspect_file(task, previous)
            if self._queue.cancelled(task):
                return
            status = outcome["status"]
            if status == "cancelled":
                retry_delay, increment = 0, False
                return
            if status in {"missing", "skipped"}:
                with self._lock:
                    self._file_cache.pop(path_key(task.path), None)
                self._add_alert({
                    "created_at_utc": datetime.now(timezone.utc).isoformat(),
                    "severity": "Low", "source": "File monitor",
                    "message": outcome["reason"], "evidence": {"path": task.path, **metadata},
                })
                return
            if status == "retry":
                raise OSError(outcome["reason"])
            if status == "directory":
                for filename in outcome["files"]:
                    original = str(Path(task.original_path) / Path(filename).relative_to(task.path)) if task.original_path else None
                    self._enqueue_file(filename, task.change, original_path=original)
                if outcome["truncated"]:
                    self._add_alert({
                        "created_at_utc": datetime.now(timezone.utc).isoformat(),
                        "severity": "Medium", "source": "Monitor capacity",
                        "message": "Moved/created directory enumeration reached its bound; coverage is incomplete.",
                        "evidence": {"path": task.path, **metadata},
                    })
                return

            result = outcome.get("result")
            digest = result["sha256"] if result else outcome["sha256"]
            same_content = bool(previous and tuple(previous["identity"]) == tuple(outcome["identity"])
                                and previous["sha256"] == digest)
            prior_fingerprints = previous["fingerprints"] if same_content else set()
            findings = result["findings"] if result else previous["findings"]
            fingerprints = {self._finding_fingerprint(finding) for finding in findings}
            fresh = [finding for finding in findings if self._finding_fingerprint(finding) not in prior_fingerprints]
            alerts = []
            for finding in fresh:
                fingerprint = self._finding_fingerprint(finding)
                uid = "fs-" + hashlib.sha256(f"{task.path}|{digest}|{fingerprint}|{task.first_seen_utc}".encode()).hexdigest()
                alerts.append({
                    "event_uid": uid, "created_at_utc": datetime.now(timezone.utc).isoformat(),
                    "severity": finding["severity"], "source": finding["source"],
                    "message": f"{task.change.title()} file: {finding['description']}",
                    "evidence": {**finding, **metadata,
                                 "file_mtime_utc": datetime.fromtimestamp(outcome["mtime_ns"] / 1e9, timezone.utc).isoformat()},
                })
            move_identity = (task.original_path, task.path, digest)
            if (task.original_path and same_content and findings and not fresh
                    and previous.get("last_move") != move_identity):
                # Keep historical alerts untouched; a relocation notice links the new
                # real path to the original detection metadata without repeating threats.
                alerts.append({
                    "event_uid": "fs-move-" + hashlib.sha256(f"{task.path}|{digest}|{task.first_seen_utc}".encode()).hexdigest(),
                    "created_at_utc": datetime.now(timezone.utc).isoformat(),
                    "severity": "Low", "source": "File monitor",
                    "message": "Previously analyzed file moved; original detection metadata is retained for review.",
                    "evidence": {"path": task.path, "sha256": digest, **metadata,
                                 "related_findings": findings},
                })
            if alerts:
                self._publish_file_alerts(alerts)
            with self._lock:
                if result:
                    self._files_checked += 1
                for old_path in task.original_paths:
                    self._file_cache.pop(path_key(old_path), None)
                self._file_cache[path_key(task.path)] = {
                    "identity": outcome["identity"], "sha256": digest, "policy": outcome["policy"],
                    "name": Path(task.path).name, "complete": outcome.get("complete", previous["complete"] if previous else False),
                    "fingerprints": fingerprints, "findings": findings,
                    "last_move": move_identity if task.original_path else previous.get("last_move") if same_content else None,
                }
                self._file_cache.move_to_end(path_key(task.path))
                while len(self._file_cache) > MAX_CACHE_ENTRIES:
                    self._file_cache.popitem(last=False)
            if result and result["warnings"]:
                raise OSError("Inspection was incomplete: " + "; ".join(result["warnings"][:3]))
        except Exception as exc:
            if task.attempts < len(RETRY_DELAYS) and time.monotonic() - task.first_seen < TASK_TIMEOUT_SECONDS:
                retry_delay = RETRY_DELAYS[task.attempts]
            else:
                self._add_alert({
                    "created_at_utc": datetime.now(timezone.utc).isoformat(),
                    "severity": "Low", "source": "File monitor",
                    "message": f"Inspection retries exhausted; file was not fully inspected: {exc}",
                    "evidence": {"path": task.path, **metadata},
                })
        finally:
            if not self._queue.finish(task, retry_delay, increment):
                self._add_alert({
                    "created_at_utc": datetime.now(timezone.utc).isoformat(),
                    "severity": "Medium", "source": "Monitor capacity",
                    "message": "Inspection retry could not be scheduled because the pending-path limit was reached.",
                    "evidence": {"path": task.path, **metadata},
                })

    def _poll_security_events(self) -> None:
        errors = []
        deadline = time.monotonic() + EVENT_POLL_BUDGET_SECONDS
        logs = self._event_logs[self._event_log_offset:] + self._event_logs[:self._event_log_offset]
        self._event_log_offset = (self._event_log_offset + 1) % max(1, len(self._event_logs))
        for log_name in logs:
            for page_number in range(MAX_EVENT_PAGES_PER_LOG):
                if self._stop.is_set():
                    break
                if deadline - time.monotonic() < 1:
                    errors.append({"Log": log_name, "Error": "Polling time budget reached; saved cursor will resume next poll."})
                    break
                try:
                    more, gap = self._process_event_page(log_name, deadline)
                    self._poll_failures.pop(log_name, None)
                    if gap:
                        errors.append({"Log": log_name, "Error": gap})
                    if not more:
                        break
                    if page_number == MAX_EVENT_PAGES_PER_LOG - 1:
                        errors.append({"Log": log_name, "Error": "Event backlog remains after bounded pagination; saved cursor will resume next poll."})
                except (OSError, ValueError, RuntimeError) as exc:
                    message = f"Coverage gap / polling incomplete: {exc}. Cursor was not advanced for the failed batch; retry will resume from the saved checkpoint."
                    errors.append({"Log": log_name, "Error": message})
                    if self._poll_failures.get(log_name) != message:
                        self._add_alert({
                            "created_at_utc": datetime.now(timezone.utc).isoformat(),
                            "severity": "Medium", "source": "Windows event monitor",
                            "message": message, "evidence": {"log": log_name, "coverage_gap": True},
                        })
                        self._poll_failures[log_name] = message
                    break
        with self._lock:
            self._event_log_errors = errors

    def _process_event_page(self, log_name, deadline):
        # No dashboard/snapshot lock is held during PowerShell, persistence or retries.
        with self._event_store.locked() as state:
            cursor = state["logs"].get(log_name)
            after = cursor["record_id"] if cursor else 0

            def read(position):
                remaining = int(deadline - time.monotonic())
                if remaining < 1:
                    raise WindowsSecurityError("Polling time budget reached")
                return read_security_event_page(log_name, position, limit=EVENT_PAGE_SIZE, timeout=min(10, remaining))

            page = read(after)
            gap = ""
            reset = False
            if cursor and after:
                if page["newest"] < after or (
                    page["oldest"] <= after <= page["newest"]
                    and page["anchor_fingerprint"] != cursor["fingerprint"]
                ):
                    gap = "Event log cleared, restored, or cursor invalidated (Record ID reuse); replaying retained records. Earlier coverage may be unavailable."
                    reset = True
                elif page["oldest"] > after:
                    gap = "Event log rotation removed the cursor anchor; continuity cannot be verified. Unread overwritten records may be unavailable."
            elif cursor is None:
                gap = "No saved polling cursor: processing all retained records. Events removed before this initial checkpoint cannot be recovered."
            elif after == 0 and page["oldest"] > 1:
                gap = "Event log rotation removed records since the saved empty-log checkpoint; earlier coverage is unavailable."
            if reset:
                page = read(0)
            staged = []
            alerts = []
            if gap:
                identity = json.dumps([log_name, cursor, page["oldest"], gap], sort_keys=True)
                alerts.append({
                    "event_uid": "coverage-" + hashlib.sha256(identity.encode()).hexdigest(),
                    "created_at_utc": datetime.now(timezone.utc).isoformat(),
                    "severity": "Medium", "source": "Windows event monitor",
                    "message": gap,
                    "evidence": {"log": log_name, "coverage_gap": True, "previous_cursor": cursor,
                                 "oldest_record_id": page["oldest"], "newest_record_id": page["newest"]},
                })
            for raw in page["events"]:
                event = normalize_security_event(raw)
                classification, reasons = classify_security_event(event)
                event.update(classification=classification, classification_reasons=reasons)
                uid = hashlib.sha256(json.dumps([log_name, event["RecordId"], event["Fingerprint"]]).encode()).hexdigest()
                event["event_uid"] = uid
                staged.append(event)
                alert = _security_alert(event)
                if alert:
                    alert["event_uid"] = uid
                    alert["evidence"]["fingerprint"] = event["Fingerprint"]
                    alerts.append(alert)
            detector = BehavioralDetector(state=state.get("behavioral"))
            behavioral = detector.feed(staged, now=datetime.now(timezone.utc) if not page["more"] else None)
            if "behavioral" not in state and cursor:
                detector.diagnostics.append(
                    "No saved behavioral context at the existing polling checkpoint; earlier login sequences cannot be reconstructed.")
            for finding in behavioral:
                alerts.append({
                    "event_uid": finding["detection_id"],
                    "created_at_utc": datetime.now(timezone.utc).isoformat(),
                    "severity": finding["severity"], "source": "Behavioral detection",
                    "message": finding["description"], "evidence": finding,
                })
            if detector.diagnostics:
                context = "; ".join(detector.diagnostics)
                alerts.append({
                    "event_uid": "behavior-context-" + hashlib.sha256(
                        json.dumps([log_name, page["next_record_id"], context]).encode()).hexdigest(),
                    "created_at_utc": datetime.now(timezone.utc).isoformat(),
                    "severity": "Low", "source": "Behavioral detection context",
                    "message": context,
                    "evidence": {"log": log_name, "coverage_gap": True},
                })
            # Publish durably BEFORE checkpointing. A crash in between is replayed
            # safely because publication suppresses already-written event_uid values.
            persist_event_alerts(self._event_alert_path, alerts, MAX_PERSISTENT_ALERT_LOG_BYTES)
            state["behavioral"] = detector.export_state()
            state["logs"][log_name] = {"record_id": page["next_record_id"], "fingerprint": page["next_fingerprint"]}
            self._event_store.save(state)
        with self._lock:
            for event in staged:
                if not self._remember_event_key(_event_key(event)):
                    continue
                self._security_events.append(event)
                self._security_event_count += 1
                if event["classification"] == "Normal":
                    self._normal_event_count += 1
                else:
                    self._security_alert_count += 1
            existing = {item.get("event_uid") for item in self._alerts}
            for alert in alerts:
                if alert["event_uid"] not in existing:
                    self._alerts.append(alert)
                    existing.add(alert["event_uid"])
            self._last_successful_event_read_utc = datetime.now(timezone.utc).isoformat()
        return page["more"], gap

    def _remember_event_key(self, key: tuple[str, str, str, str, str]) -> bool:
        if key in self._seen_event_keys:
            return False
        if len(self._seen_event_order) >= MAX_TRACKED_SECURITY_EVENTS:
            oldest = self._seen_event_order.popleft()
            self._seen_event_keys.discard(oldest)
        self._seen_event_order.append(key)
        self._seen_event_keys.add(key)
        return True

    def _run(self) -> None:
        while not self._stop.is_set():
            task = self._queue.take(self._stop)
            if task is not None:
                self._scan_changed_file(task.path, task.change, task)

    def _run_event_monitor(self) -> None:
        while not self._stop.is_set():
            try:
                self._poll_security_events()
            except Exception as exc:
                self._add_alert({
                    "created_at_utc": datetime.now(timezone.utc).isoformat(),
                    "severity": "Low",
                    "source": "Windows event monitor",
                    "message": f"Security event polling failed unexpectedly; the saved cursor will be retried: {exc}",
                    "evidence": {},
                })
            self._stop.wait(self.event_poll_seconds)
