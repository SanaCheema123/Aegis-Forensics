"""Explicit, visible Windows background monitoring controls and service entry point."""
from __future__ import annotations

import argparse
import ctypes
import hashlib
import json
import os
import shutil
import subprocess
import sys
import time
import uuid
from contextlib import contextmanager
from collections import deque
from collections.abc import Sequence
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

if __package__ in {None, ""}:
    project_root = str(Path(__file__).resolve().parent.parent)
    if project_root not in sys.path:
        sys.path.insert(0, project_root)

from modules.laptop_scanner import _is_reparse_point
from modules.realtime_monitor import RealtimeMonitor
from modules.yara_scanner import YaraScanner

ROOT = Path(__file__).resolve().parent.parent
STATE_DIR = ROOT / "reports" / "background_monitor"
CONFIG_PATH = STATE_DIR / "monitor_config.json"
STATUS_PATH = STATE_DIR / "monitor_status.json"
STOP_REQUEST_PATH = STATE_DIR / "stop.request"
ALERT_LOG_PATH = STATE_DIR / "alerts.jsonl"
AUDIT_LOG_PATH = STATE_DIR / "audit.jsonl"
MONITOR_LOG_PATH = STATE_DIR / "monitor.log"
START_LOCK_PATH = STATE_DIR / "start.lock"
STARTUP_TASK_NAME = "AegisForensicsBackgroundMonitor"
HEARTBEAT_SECONDS = 10
STALE_AFTER_SECONDS = 45
STARTUP_TIMEOUT_SECONDS = 30
STOP_TIMEOUT_SECONDS = 25
MAX_ALERT_HISTORY = 200
MONITOR_MUTEX_NAME = (
    "Local\\AegisForensicsBackgroundMonitor-"
    + hashlib.sha256(str(ROOT).casefold().encode("utf-8")).hexdigest()[:16]
)


class BackgroundMonitorError(RuntimeError):
    """Raised when background monitoring cannot be safely controlled."""


class BackgroundMonitorAlreadyRunning(BackgroundMonitorError):
    """Raised when another process already owns this workspace's monitor."""


def _now_utc() -> str:
    return datetime.now(timezone.utc).isoformat()


def _write_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary_path = path.with_suffix(f"{path.suffix}.{os.getpid()}.tmp")
    temporary_path.write_text(
        json.dumps(value, ensure_ascii=True, indent=2, default=str),
        encoding="utf-8",
    )
    temporary_path.replace(path)


def _append_jsonl(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as log_file:
        log_file.write(json.dumps(value, ensure_ascii=True, default=str) + "\n")


def _validate_directories(directories: Sequence[str | Path]) -> list[str]:
    validated = []
    seen = set()
    for raw_path in directories:
        directory = Path(raw_path).expanduser()
        if not directory.is_dir() or _is_reparse_point(directory):
            raise ValueError(f"Cannot monitor this directory: {directory}")
        resolved = directory.resolve()
        identity = str(resolved).casefold()
        if identity not in seen:
            validated.append(str(resolved))
            seen.add(identity)
    if not validated:
        raise ValueError("Choose at least one directory to monitor.")
    return validated


def _python_executable() -> str:
    """Prefer the project's environment over the interpreter that launched Streamlit."""
    project_python = ROOT / ".venv" / "Scripts" / "python.exe"
    if project_python.is_file():
        return str(project_python)
    if sys.executable:
        return sys.executable
    raise BackgroundMonitorError("No Python interpreter is available to run the background monitor.")


@contextmanager
def _monitor_start_lock():
    """Serialize start requests so concurrent Streamlit sessions cannot spawn duplicates."""
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    lock_file = os.open(START_LOCK_PATH, os.O_CREAT | os.O_RDWR, 0o600)
    try:
        if os.fstat(lock_file).st_size == 0:
            os.write(lock_file, b"\0")
        os.lseek(lock_file, 0, os.SEEK_SET)
        if os.name == "nt":
            import msvcrt

            try:
                msvcrt.locking(lock_file, msvcrt.LK_NBLCK, 1)
            except OSError as exc:
                raise BackgroundMonitorAlreadyRunning(
                    "Another Aegis session is currently starting the background monitor."
                ) from exc
        yield
    finally:
        if os.name == "nt":
            import msvcrt

            try:
                os.lseek(lock_file, 0, os.SEEK_SET)
                msvcrt.locking(lock_file, msvcrt.LK_UNLCK, 1)
            except OSError:
                pass
        os.close(lock_file)


def _monitor_mutex_exists() -> bool:
    if os.name != "nt":
        return False
    from ctypes import wintypes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.OpenMutexW.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.LPCWSTR]
    kernel32.OpenMutexW.restype = wintypes.HANDLE
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.CloseHandle.restype = wintypes.BOOL
    ctypes.set_last_error(0)
    handle = kernel32.OpenMutexW(0x001000, False, MONITOR_MUTEX_NAME)
    if not handle:
        error_code = ctypes.get_last_error()
        if error_code == 2:
            return False
        raise ctypes.WinError(error_code)
    kernel32.CloseHandle(handle)
    return True


def _create_monitor_mutex():
    if os.name != "nt":
        return None
    from ctypes import wintypes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.CreateMutexW.argtypes = [
        wintypes.LPVOID,
        wintypes.BOOL,
        wintypes.LPCWSTR,
    ]
    kernel32.CreateMutexW.restype = wintypes.HANDLE
    ctypes.set_last_error(0)
    handle = kernel32.CreateMutexW(None, False, MONITOR_MUTEX_NAME)
    if not handle:
        raise ctypes.WinError(ctypes.get_last_error())
    if ctypes.get_last_error() == 183:
        kernel32.CloseHandle(handle)
        raise BackgroundMonitorAlreadyRunning(
            "An Aegis background monitor process already owns this workspace."
        )
    return handle


def _process_is_running(pid: int) -> bool:
    if os.name != "nt":
        try:
            os.kill(pid, 0)
            return True
        except ProcessLookupError:
            return False
        except PermissionError:
            return True

    from ctypes import wintypes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel32.OpenProcess.restype = wintypes.HANDLE
    kernel32.GetExitCodeProcess.argtypes = [
        wintypes.HANDLE,
        ctypes.POINTER(wintypes.DWORD),
    ]
    kernel32.GetExitCodeProcess.restype = wintypes.BOOL
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.CloseHandle.restype = wintypes.BOOL

    process_handle = kernel32.OpenProcess(0x1000, False, pid)
    if not process_handle:
        error_code = ctypes.get_last_error()
        if error_code == 5:
            return True
        if error_code == 87:
            return False
        raise ctypes.WinError(error_code)

    try:
        exit_code = wintypes.DWORD()
        if not kernel32.GetExitCodeProcess(process_handle, ctypes.byref(exit_code)):
            raise ctypes.WinError(ctypes.get_last_error())
        return exit_code.value == 259
    finally:
        kernel32.CloseHandle(process_handle)


def get_background_status() -> dict[str, Any]:
    if not STATUS_PATH.exists():
        return {"state": "stopped", "running": False, "directories": []}
    try:
        status = json.loads(STATUS_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise BackgroundMonitorError(f"Background monitor status could not be read: {exc}") from exc
    if not isinstance(status, dict):
        raise BackgroundMonitorError("Background monitor status has an invalid format.")

    state = status.get("state", "unknown")
    if state not in {"starting", "running", "stopping"}:
        return {**status, "running": False}
    if state == "starting":
        return {
            **status,
            "running": False,
            "error": status.get("error", "The background monitor is starting and is not ready yet."),
        }

    try:
        heartbeat = datetime.fromisoformat(status["heartbeat_utc"])
        if heartbeat.tzinfo is None:
            heartbeat = heartbeat.replace(tzinfo=timezone.utc)
    except (KeyError, TypeError, ValueError) as exc:
        return {
            **status,
            "state": "stale",
            "running": False,
            "error": f"Monitor status is incomplete: {exc}",
        }

    heartbeat_age = (datetime.now(timezone.utc) - heartbeat.astimezone(timezone.utc)).total_seconds()
    if not status.get("pid"):
        return {
            **status,
            "state": "starting" if heartbeat_age <= STALE_AFTER_SECONDS else "stale",
            "running": False,
            "error": "The monitor has not published a process ID; it is not confirmed running.",
        }
    try:
        pid = int(status["pid"])
    except (TypeError, ValueError) as exc:
        return {
            **status,
            "state": "stale",
            "running": False,
            "error": f"Monitor process ID is invalid: {exc}",
        }
    try:
        process_exists = _process_is_running(pid)
    except OSError as exc:
        return {
            **status,
            "state": "unknown",
            "running": False,
            "error": f"Monitor process health could not be checked: {exc}",
        }

    if not process_exists:
        return {
            **status,
            "state": "stale",
            "running": False,
            "error": (
                f"Background monitor process {pid} is not running. "
                "Check the monitor log for its startup or exit error."
            ),
        }
    if heartbeat_age > STALE_AFTER_SECONDS:
        return {
            **status,
            "state": "stale",
            "running": False,
            "error": (
                f"Background monitor process {pid} has not reported a heartbeat in "
                f"{int(heartbeat_age)} seconds."
            ),
        }
    return {**status, "running": True}


def _monitor_log_tail() -> str:
    if not MONITOR_LOG_PATH.exists():
        return ""
    try:
        lines = MONITOR_LOG_PATH.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return ""
    return "\n".join(lines[-20:])


def _wait_for_startup(
    launcher_pid: int,
    monitor_id: str,
    timeout: float = STARTUP_TIMEOUT_SECONDS,
) -> dict[str, Any]:
    deadline = time.monotonic() + timeout
    latest = {}
    while time.monotonic() < deadline:
        latest = get_background_status()
        if (
            latest.get("monitor_id") == monitor_id
            and latest.get("state") == "running"
            and latest.get("running")
        ):
            return latest
        if latest.get("state") == "failed":
            break
        if (
            latest.get("monitor_id") == monitor_id
            and latest.get("state") == "stale"
            and latest.get("pid")
        ):
            break
        if (
            latest.get("state") != "starting"
            and latest.get("monitor_id") != monitor_id
            and not _process_is_running(launcher_pid)
        ):
            break
        time.sleep(0.25)
    detail = latest.get("error")
    if detail == "The background monitor is starting and is not ready yet.":
        detail = None
    detail = detail or _monitor_log_tail() or "No startup error was reported."
    raise BackgroundMonitorError(
        f"Background monitor launcher {launcher_pid} did not become healthy: {detail}"
    )


def load_background_alerts(limit: int = MAX_ALERT_HISTORY) -> list[dict[str, Any]]:
    if not 1 <= limit <= MAX_ALERT_HISTORY:
        raise ValueError(f"Alert history limit must be between 1 and {MAX_ALERT_HISTORY}.")
    if not ALERT_LOG_PATH.exists():
        return []
    try:
        with ALERT_LOG_PATH.open("r", encoding="utf-8") as alert_log:
            alerts: deque[dict[str, Any]] = deque(maxlen=limit)
            for line_number, line in enumerate(alert_log, start=1):
                if not line.strip():
                    continue
                try:
                    alert = json.loads(line)
                except json.JSONDecodeError as exc:
                    raise BackgroundMonitorError(
                        f"Background alert history is invalid at line {line_number}."
                    ) from exc
                if isinstance(alert, dict):
                    alerts.append(alert)
    except OSError as exc:
        raise BackgroundMonitorError(f"Background alert history could not be read: {exc}") from exc
    return list(reversed(alerts))


def start_background_monitor(directories: Sequence[str | Path]) -> dict[str, Any]:
    if os.name != "nt":
        raise BackgroundMonitorError("Background monitoring is available only on Windows.")
    selected_directories = _validate_directories(directories)
    with _monitor_start_lock():
        current = get_background_status()
        if current.get("running") or _monitor_mutex_exists():
            raise BackgroundMonitorAlreadyRunning(
                "The Aegis background monitor is already running."
            )

        STATE_DIR.mkdir(parents=True, exist_ok=True)
        STOP_REQUEST_PATH.unlink(missing_ok=True)
        monitor_id = uuid.uuid4().hex
        _write_json(CONFIG_PATH, {
            "directories": selected_directories,
            "configured_at_utc": _now_utc(),
            "monitor_id": monitor_id,
        })
        status = {
            "state": "starting",
            "running": False,
            "monitor_id": monitor_id,
            "heartbeat_utc": _now_utc(),
            "directories": selected_directories,
        }
        _write_json(STATUS_PATH, status)
        command = [
            _python_executable(),
            str(Path(__file__).resolve()),
            "--config",
            str(CONFIG_PATH),
        ]
        try:
            with MONITOR_LOG_PATH.open("a", encoding="utf-8") as monitor_log:
                process = subprocess.Popen(
                    command,
                    cwd=ROOT,
                    creationflags=subprocess.CREATE_NEW_CONSOLE,
                    stdin=subprocess.DEVNULL,
                    stdout=monitor_log,
                    stderr=subprocess.STDOUT,
                    close_fds=True,
                )
        except OSError as exc:
            status.update({"state": "failed", "error": str(exc), "running": False})
            _write_json(STATUS_PATH, status)
            _append_jsonl(AUDIT_LOG_PATH, {
                "timestamp_utc": _now_utc(),
                "action": "start_failed",
                "error": str(exc),
            })
            raise BackgroundMonitorError(f"Background monitor could not be started: {exc}") from exc

        status.update({"pid": process.pid, "heartbeat_utc": _now_utc()})
        _write_json(STATUS_PATH, status)
        _append_jsonl(AUDIT_LOG_PATH, {
            "timestamp_utc": _now_utc(),
            "action": "start_requested",
            "pid": process.pid,
            "monitor_id": monitor_id,
            "directories": selected_directories,
            "interpreter": command[0],
        })
        try:
            return _wait_for_startup(process.pid, monitor_id)
        except BackgroundMonitorError as exc:
            try:
                STOP_REQUEST_PATH.write_text(_now_utc(), encoding="utf-8")
            except OSError:
                pass
            failure = {
                **status,
                "state": "failed",
                "running": False,
                "error": str(exc),
                "log_tail": _monitor_log_tail(),
            }
            _write_json(STATUS_PATH, failure)
            _append_jsonl(AUDIT_LOG_PATH, {
                "timestamp_utc": _now_utc(),
                "action": "start_failed",
                "pid": process.pid,
                "error": str(exc),
            })
            raise


def stop_background_monitor() -> dict[str, Any]:
    status = get_background_status()
    if not status.get("running") and not (
        status.get("state") == "stale"
        and status.get("pid")
        and _process_is_running(int(status["pid"]))
        and _monitor_mutex_exists()
    ):
        if status.get("state") == "stale":
            raise BackgroundMonitorError(
                f"{status.get('error', 'The monitor status is stale.')}"
            )
        return status
    STOP_REQUEST_PATH.parent.mkdir(parents=True, exist_ok=True)
    STOP_REQUEST_PATH.write_text(_now_utc(), encoding="utf-8")
    stopping = {
        **status,
        "state": "stopping",
        "running": True,
        "stop_requested_at_utc": _now_utc(),
    }
    _write_json(STATUS_PATH, stopping)
    _append_jsonl(AUDIT_LOG_PATH, {
        "timestamp_utc": _now_utc(),
        "action": "stop_requested",
        "pid": status.get("pid"),
        "directories": status.get("directories", []),
    })
    pid = int(status["pid"])
    deadline = time.monotonic() + STOP_TIMEOUT_SECONDS
    while time.monotonic() < deadline:
        if not _process_is_running(pid):
            final_status = json.loads(STATUS_PATH.read_text(encoding="utf-8"))
            if final_status.get("state") == "stopped":
                return final_status
            break
        time.sleep(0.25)
    if _process_is_running(pid):
        raise BackgroundMonitorError(
            f"Stop was requested for monitor process {pid}, but it is still running after "
            f"{STOP_TIMEOUT_SECONDS} seconds. No process was force-terminated."
        )
    final_status = json.loads(STATUS_PATH.read_text(encoding="utf-8"))
    if final_status.get("state") != "stopped":
        raise BackgroundMonitorError(
            f"Monitor process {pid} exited without confirming a clean shutdown."
        )
    return final_status


def install_startup_task(
    directories: Sequence[str | Path],
    user_approved: bool,
) -> None:
    if not user_approved:
        raise PermissionError("Explicit user approval is required to add the startup task.")
    if os.name != "nt":
        raise BackgroundMonitorError("Windows startup integration is available only on Windows.")
    selected_directories = _validate_directories(directories)
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    _write_json(CONFIG_PATH, {
        "directories": selected_directories,
        "configured_at_utc": _now_utc(),
    })
    executable = shutil.which("schtasks.exe")
    if not executable:
        raise BackgroundMonitorError("schtasks.exe could not be found.")
    action = subprocess.list2cmdline([
        _python_executable(),
        str(Path(__file__).resolve()),
        "--config",
        str(CONFIG_PATH),
    ])
    _run_schtasks([
        executable,
        "/Create",
        "/SC",
        "ONLOGON",
        "/TN",
        STARTUP_TASK_NAME,
        "/TR",
        action,
        "/F",
    ])
    _append_jsonl(AUDIT_LOG_PATH, {
        "timestamp_utc": _now_utc(),
        "action": "startup_task_installed",
        "task_name": STARTUP_TASK_NAME,
        "directories": selected_directories,
        "run_level": "standard user",
    })


def remove_startup_task() -> None:
    if os.name != "nt":
        raise BackgroundMonitorError("Windows startup integration is available only on Windows.")
    executable = shutil.which("schtasks.exe")
    if not executable:
        raise BackgroundMonitorError("schtasks.exe could not be found.")
    _run_schtasks([
        executable,
        "/Delete",
        "/TN",
        STARTUP_TASK_NAME,
        "/F",
    ])
    _append_jsonl(AUDIT_LOG_PATH, {
        "timestamp_utc": _now_utc(),
        "action": "startup_task_removed",
        "task_name": STARTUP_TASK_NAME,
    })


def _run_schtasks(command: list[str]) -> None:
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=30,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise BackgroundMonitorError(f"Windows startup task could not be changed: {exc}") from exc
    if result.returncode != 0:
        detail = result.stderr.strip() or result.stdout.strip()
        raise BackgroundMonitorError(
            detail or f"Windows startup task command failed with exit code {result.returncode}."
        )


def run_service(config_path: str | Path = CONFIG_PATH) -> int:
    if os.name != "nt":
        raise BackgroundMonitorError("Background monitoring is available only on Windows.")
    mutex_handle = _create_monitor_mutex()
    monitor = None
    try:
        try:
            config = json.loads(Path(config_path).read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise BackgroundMonitorError(
                f"Background monitor configuration could not be read: {exc}"
            ) from exc
        if not isinstance(config, dict) or not isinstance(config.get("directories"), list):
            raise BackgroundMonitorError("Background monitor configuration has an invalid format.")
        directories = _validate_directories(config["directories"])
        monitor_id = config.get("monitor_id")
        monitor = RealtimeMonitor(
            directories,
            YaraScanner(),
            alert_log_path=ALERT_LOG_PATH,
        )
        monitor.start()
        started_at = _now_utc()
        _append_jsonl(AUDIT_LOG_PATH, {
            "timestamp_utc": started_at,
            "action": "monitor_started",
            "pid": os.getpid(),
            "monitor_id": monitor_id,
            "directories": directories,
            "alert_log": str(ALERT_LOG_PATH),
        })

        try:
            last_heartbeat = 0.0
            while not STOP_REQUEST_PATH.exists():
                now = time.monotonic()
                if now - last_heartbeat >= HEARTBEAT_SECONDS:
                    snapshot = monitor.snapshot()
                    heartbeat = _now_utc()
                    _write_json(STATUS_PATH, {
                        "state": "running",
                        "running": True,
                        "pid": os.getpid(),
                        "monitor_id": monitor_id,
                        "started_at_utc": started_at,
                        "heartbeat_utc": heartbeat,
                        "directories": directories,
                        "files_checked": snapshot["files_checked"],
                        "health": {
                            key: snapshot[key]
                            for key in (
                                "file_observer_status",
                                "file_worker_status",
                                "event_monitoring_status",
                                "last_successful_event_read_utc",
                                "event_log_errors",
                                "files_checked",
                                "queue_dropped",
                                "persistence_error",
                                "yara_available",
                            )
                        },
                    })
                    last_heartbeat = now
                time.sleep(1)
        except KeyboardInterrupt:
            pass
        finally:
            monitor.stop()

        stopped_at = _now_utc()
        _append_jsonl(AUDIT_LOG_PATH, {
            "timestamp_utc": stopped_at,
            "action": "monitor_stopped",
            "pid": os.getpid(),
            "monitor_id": monitor_id,
            "directories": directories,
        })
        snapshot = monitor.snapshot()
        _write_json(STATUS_PATH, {
            "state": "stopped",
            "running": False,
            "pid": os.getpid(),
            "monitor_id": monitor_id,
            "started_at_utc": started_at,
            "heartbeat_utc": stopped_at,
            "directories": directories,
            "files_checked": snapshot["files_checked"],
            "health": {
                "file_observer_status": snapshot["file_observer_status"],
                "file_worker_status": snapshot["file_worker_status"],
                "event_monitoring_status": snapshot["event_monitoring_status"],
                "last_successful_event_read_utc": snapshot["last_successful_event_read_utc"],
                "event_log_errors": snapshot["event_log_errors"],
                "files_checked": snapshot["files_checked"],
                "queue_dropped": snapshot["queue_dropped"],
                "persistence_error": snapshot["persistence_error"],
                "yara_available": snapshot["yara_available"],
            },
        })
        STOP_REQUEST_PATH.unlink(missing_ok=True)
        return 0
    finally:
        if monitor is not None and monitor.running:
            monitor.stop()
        if mutex_handle is not None:
            from ctypes import wintypes

            kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
            kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
            kernel32.CloseHandle.restype = wintypes.BOOL
            kernel32.CloseHandle(mutex_handle)


def main() -> int:
    parser = argparse.ArgumentParser(description="Run the visible Aegis Windows background monitor.")
    parser.add_argument("--config", type=Path, default=CONFIG_PATH)
    args = parser.parse_args()
    try:
        return run_service(args.config)
    except BackgroundMonitorAlreadyRunning as exc:
        print(f"Aegis background monitor not started: {exc}", file=sys.stderr)
        return 1
    except (BackgroundMonitorError, OSError, RuntimeError, ValueError) as exc:
        STATE_DIR.mkdir(parents=True, exist_ok=True)
        failure = {
            "state": "failed",
            "running": False,
            "pid": os.getpid(),
            "heartbeat_utc": _now_utc(),
            "error": str(exc),
        }
        _write_json(STATUS_PATH, failure)
        _append_jsonl(AUDIT_LOG_PATH, {
            "timestamp_utc": _now_utc(),
            "action": "monitor_failed",
            "pid": os.getpid(),
            "error": str(exc),
        })
        print(f"Aegis background monitor failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
