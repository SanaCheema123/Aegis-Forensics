"""Coalesced filesystem work and cancellable, read-only inspection processes."""
from dataclasses import dataclass, replace
from datetime import datetime, timezone
import hashlib
from contextlib import redirect_stdout
import os
import pickle
from pathlib import Path
import queue
import threading
import time
import subprocess
import sys
import uuid


QUIET_SECONDS = 0.4
MAX_COALESCE_SECONDS = 2.0
TASK_TIMEOUT_SECONDS = 30.0
SCAN_TIMEOUT_SECONDS = 10.0
RETRY_DELAYS = (0.25, 0.75, 1.5)
MAX_CACHE_ENTRIES = 512


def path_key(path):
    return os.path.normcase(os.path.abspath(str(path)))


@dataclass
class FileTask:
    path: str
    change: str
    first_seen: float
    last_seen: float
    first_seen_utc: str
    last_seen_utc: str
    due: float
    token: str
    original_path: str | None = None
    source_path: str | None = None
    original_paths: tuple = ()
    is_directory: bool = False
    attempts: int = 0


class CoalescingFileQueue:
    def __init__(self, capacity):
        self.capacity = capacity
        self._condition = threading.Condition()
        self._pending = {}
        self._active = {}
        self._cancelled = set()

    def schedule(self, path, change, original_path=None, is_directory=False):
        now = time.monotonic()
        timestamp = datetime.now(timezone.utc).isoformat()
        key = path_key(path)
        with self._condition:
            previous = self._pending.get(key)
            moved = None
            if original_path:
                source = path_key(original_path)
                moved = self._pending.pop(source, None)
                if source in self._active:
                    self._cancelled.add(self._active[source].token)
                if is_directory:
                    for old_key in list(self._pending):
                        if Path(old_key).is_relative_to(Path(source)):
                            self._pending.pop(old_key)
                    for old_key, active in self._active.items():
                        if Path(old_key).is_relative_to(Path(source)):
                            self._cancelled.add(active.token)
            previous = previous or moved
            if key not in self._pending and len(self._pending) >= self.capacity:
                raise queue.Full
            if previous:
                origin = previous.original_path or original_path
                origins = tuple(dict.fromkeys((*previous.original_paths, *([original_path] if original_path else []))))[-16:]
                task = replace(
                    previous, path=str(path), change=change if original_path else previous.change,
                    last_seen=now, last_seen_utc=timestamp,
                    due=min(now + QUIET_SECONDS, previous.first_seen + MAX_COALESCE_SECONDS),
                    token=uuid.uuid4().hex, original_path=origin,
                    source_path=original_path or previous.source_path, original_paths=origins,
                    is_directory=is_directory,
                )
            else:
                active = self._active.get(key)
                if active and not original_path:
                    original_path = active.original_path
                task = FileTask(str(path), change, now, now, timestamp, timestamp,
                                now + QUIET_SECONDS, uuid.uuid4().hex,
                                original_path, original_path,
                                active.original_paths if active else (original_path,) if original_path else (), is_directory)
            self._pending[key] = task
            self._condition.notify_all()

    def take(self, stop):
        with self._condition:
            while not stop.is_set():
                if not self._pending:
                    self._condition.wait(timeout=0.2)
                    continue
                key, task = min(self._pending.items(), key=lambda item: item[1].due)
                delay = task.due - time.monotonic()
                if delay > 0:
                    self._condition.wait(timeout=min(delay, 0.2))
                    continue
                self._pending.pop(key)
                self._active[key] = task
                return task
        return None

    def finish(self, task, retry_delay=None, increment=True):
        key = path_key(task.path)
        with self._condition:
            active = self._active.get(key)
            if active and active.token == task.token:
                self._active.pop(key)
            cancelled = task.token in self._cancelled
            self._cancelled.discard(task.token)
            # New events during an inspection always retain their own final scan.
            if retry_delay is not None and not cancelled and key not in self._pending:
                if len(self._pending) < self.capacity:
                    self._pending[key] = replace(task, attempts=task.attempts + int(increment),
                                                 due=time.monotonic() + retry_delay)
                else:
                    self._condition.notify_all()
                    return False
            self._condition.notify_all()
            return True

    def cancel(self, path, recursive=False):
        key = path_key(path)
        with self._condition:
            pending = self._pending.pop(key, None)
            active = self._active.get(key)
            if active:
                self._cancelled.add(active.token)
            if recursive:
                for old_key in list(self._pending):
                    if Path(old_key).is_relative_to(Path(key)):
                        pending = self._pending.pop(old_key)
                for old_key, active_task in self._active.items():
                    if Path(old_key).is_relative_to(Path(key)):
                        self._cancelled.add(active_task.token)
                        active = active_task
            self._condition.notify_all()
            return bool(pending or active)

    def cancelled(self, task):
        with self._condition:
            return task.token in self._cancelled

    def wake(self):
        with self._condition:
            self._condition.notify_all()

    def resume(self):
        with self._condition:
            now = time.monotonic()
            self._pending = {key: replace(task, first_seen=now, due=now + QUIET_SECONDS, attempts=0)
                             for key, task in self._pending.items()}
            self._condition.notify_all()

    def pending_count(self):
        with self._condition:
            return len(self._pending)


def _rules_digest(directory):
    digest = hashlib.sha256()
    for rule in sorted([*directory.rglob("*.yar"), *directory.rglob("*.yara")]):
        digest.update(str(rule.relative_to(directory)).encode())
        with rule.open("rb") as source:
            for chunk in iter(lambda: source.read(65536), b""):
                digest.update(chunk)
    return digest.hexdigest()


def scanner_policy(scanner):
    from modules.yara_scanner import YaraScanner
    if isinstance(scanner, YaraScanner):
        signature = _rules_digest(scanner.rules_dir)
        if getattr(scanner, "_monitor_compiled_signature", signature) != signature:
            raise OSError("Detection rules changed while the inspection engine was loading; retry required.")
        return ("yara", str(scanner.rules_dir), signature, bool(scanner.ready))
    return (type(scanner).__module__, type(scanner).__qualname__,
            str(getattr(scanner, "cache_signature", "")), bool(scanner.ready))


def inspect_candidate(path, scanner, expected=None, roots=(), is_directory=False):
    """Runs only in a killable helper; never executes or modifies candidate files."""
    from modules.laptop_scanner import MAX_LAPTOP_FILE_SIZE, _is_reparse_point, _sha256, analyze_file
    from modules.safety_checks import SCAN_EXTENSIONS

    candidate = Path(path)
    root = next((Path(root) for root in roots if candidate.is_relative_to(Path(root))), None)
    if roots and root is None:
        return {"status": "skipped", "reason": "Destination is outside the monitored directories."}
    current = candidate
    while True:
        if _is_reparse_point(current):
            return {"status": "skipped", "reason": "Symbolic links and reparse points are not followed."}
        if current == root or current.parent == current:
            break
        current = current.parent
    if is_directory:
        candidate.stat()
        files = []
        started = time.monotonic()
        def walk_error(error):
            raise error
        for directory, children, names in os.walk(candidate, followlinks=False, onerror=walk_error):
            children[:] = [name for name in children if not _is_reparse_point(Path(directory) / name)]
            for name in names:
                item = Path(directory) / name
                if item.suffix.lower() in SCAN_EXTENSIONS and not _is_reparse_point(item):
                    files.append(str(item))
                if len(files) >= 100 or time.monotonic() - started > 2:
                    return {"status": "directory", "files": files, "truncated": True}
        return {"status": "directory", "files": files, "truncated": False}

    before = candidate.stat()
    if not candidate.is_file():
        return {"status": "skipped", "reason": "Path is not a regular file."}
    if before.st_size > MAX_LAPTOP_FILE_SIZE:
        return {"status": "skipped", "reason": "Changed file exceeds the 50 MB inspection limit."}
    time.sleep(0.2)
    stable = candidate.stat()
    signature = lambda stat: (stat.st_dev, stat.st_ino, stat.st_size, stat.st_mtime_ns)
    if signature(before) != signature(stable):
        raise OSError("File is still being written.")
    identity = (stable.st_dev, stable.st_ino)
    policy = scanner_policy(scanner)
    digest = _sha256(candidate)
    if signature(stable) != signature(candidate.stat()):
        raise OSError("File changed while its hash was being calculated.")
    if (expected and stable.st_ino and tuple(expected["identity"]) == identity
            and expected["sha256"] == digest and expected["policy"] == policy
            and expected["name"] == candidate.name and expected["complete"]):
        return {"status": "unchanged", "sha256": digest, "identity": identity,
                "policy": policy, "mtime_ns": stable.st_mtime_ns}
    result = analyze_file(candidate, scanner)
    if result.get("skipped"):
        return {"status": "skipped", "reason": result["reason"]}
    if digest != result["sha256"] or signature(stable) != signature(candidate.stat()):
        raise OSError("File changed during inspection.")
    if scanner_policy(scanner) != policy:
        raise OSError("Detection rules changed during inspection; retry required.")
    return {"status": "scanned", "result": result, "identity": identity, "policy": policy,
            "mtime_ns": stable.st_mtime_ns,
            "complete": not result["warnings"] and bool(scanner.ready)}


def _worker_main():
    """Dedicated entry point: never re-import Streamlit's unguarded app script."""
    try:
        request = sys.stdin.buffer.read(4 * 1024 * 1024 + 1)
        if len(request) > 4 * 1024 * 1024:
            raise ValueError("Inspection request exceeds its size bound.")
        # This private pipe contains only parent-generated configuration, never
        # monitored file bytes or externally supplied serialized objects.
        path, scanner_spec, expected, roots, is_directory = pickle.loads(request)
        if scanner_spec[0] == "yara":
            from modules.yara_scanner import YaraScanner
            signature = _rules_digest(Path(scanner_spec[1]))
            scanner = YaraScanner(scanner_spec[1])
            scanner._monitor_compiled_signature = signature
        else:
            scanner = scanner_spec[1]
        with redirect_stdout(sys.stderr):
            result = inspect_candidate(path, scanner, expected, roots, is_directory)
    except FileNotFoundError:
        result = {"status": "missing", "reason": "File was deleted or moved before inspection completed."}
    except Exception as exc:
        result = {"status": "retry", "reason": f"{type(exc).__name__}: {exc}"}
    sys.stdout.buffer.write(pickle.dumps(result))
    sys.stdout.buffer.flush()


def bounded_inspection(path, scanner, expected, roots, is_directory, stop, timeout=SCAN_TIMEOUT_SECONDS):
    from modules.yara_scanner import YaraScanner
    spec = ("yara", str(scanner.rules_dir)) if isinstance(scanner, YaraScanner) else ("object", scanner)
    expected = {key: expected[key] for key in ("identity", "sha256", "policy", "name", "complete")} if expected else None
    request = pickle.dumps((path, spec, expected, tuple(map(str, roots)), is_directory))
    project_root = str(Path(__file__).resolve().parents[1])
    environment = dict(os.environ, PYTHONPATH=os.pathsep.join(dict.fromkeys([project_root, *filter(None, sys.path)])))
    process = subprocess.Popen(
        [sys.executable, "-B", "-m", "modules.filesystem_monitor", "--inspect-worker"],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        cwd=project_root, env=environment,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )
    try:
        deadline = time.monotonic() + timeout
        first = True
        while time.monotonic() < deadline:
            if stop.is_set():
                return {"status": "cancelled", "reason": "Monitoring was stopped before inspection completed."}
            try:
                output, errors = process.communicate(input=request if first else None,
                                                      timeout=min(0.05, max(0, deadline - time.monotonic())))
                if process.returncode:
                    raise OSError("Inspection helper failed: " + errors.decode("utf-8", errors="replace")[:500])
                return pickle.loads(output)
            except subprocess.TimeoutExpired:
                first = False
        return {"status": "retry", "reason": "Read-only inspection exceeded its time limit."}
    finally:
        if process.poll() is None:
            process.terminate()
        try:
            process.communicate(timeout=1)
        except subprocess.TimeoutExpired:
            process.kill()
            process.communicate(timeout=1)


if __name__ == "__main__" and "--inspect-worker" in sys.argv:
    _worker_main()
