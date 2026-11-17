"""Crash-safe cursor checkpoints and idempotent publication of event alerts."""
from contextlib import contextmanager
import json
import os
import re
from pathlib import Path
import uuid

from modules.integrity import audit_lock


class CursorStore:
    def __init__(self, path):
        self.path = Path(path)

    @contextmanager
    def locked(self):
        # Readers and writers across session/background monitors share this lock.
        with audit_lock(self.path, timeout=2):
            if self.path.exists():
                try:
                    state = json.loads(self.path.read_text(encoding="utf-8"))
                    if not isinstance(state, dict) or state.get("version") != 1 or not isinstance(state.get("logs"), dict):
                        raise ValueError("Invalid cursor state format")
                    for name, cursor in state["logs"].items():
                        if (not isinstance(cursor, dict) or type(cursor.get("record_id")) is not int
                                or cursor["record_id"] < 0 or not isinstance(cursor.get("fingerprint"), str)
                                or (cursor["record_id"] > 0 and not re.fullmatch(r"[0-9a-f]{64}", cursor["fingerprint"]))):
                            raise ValueError(f"Invalid cursor for {name}")
                except (ValueError, UnicodeError) as exc:
                    raise ValueError(f"Polling cursor state is unreadable; it was not reset: {exc}") from exc
            else:
                state = {"version": 1, "logs": {}}
            yield state

    def save(self, state):
        """Caller holds locked(); replace only after a fully flushed checkpoint."""
        temporary = self.path.with_name(f"{self.path.name}.{uuid.uuid4().hex}.tmp")
        try:
            with temporary.open("x", encoding="utf-8") as stream:
                json.dump(state, stream, sort_keys=True)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, self.path)
        finally:
            # Only our temporary checkpoint is removed; never existing history.
            temporary.unlink(missing_ok=True)


def persist_event_alerts(path, alerts, maximum_bytes):
    """Publish before checkpointing; event_uid makes crash/retry replay idempotent.

    Existing alert JSONL records remain unchanged and need no migration. A
    partial/corrupt history blocks publication rather than silently losing alerts.
    """
    path = Path(path)
    with audit_lock(path, timeout=2):
        identities = set()
        current_size = path.stat().st_size if path.exists() else 0
        if path.exists():
            with path.open("r", encoding="utf-8") as source:
                for number, line in enumerate(source, 1):
                    if not line.strip():
                        continue
                    try:
                        record = json.loads(line)
                        if not isinstance(record, dict):
                            raise ValueError("not an alert object")
                    except ValueError as exc:
                        raise ValueError(f"Alert history is invalid at line {number}; polling checkpoint was not advanced.") from exc
                    if record.get("event_uid"):
                        identities.add(record["event_uid"])
        pending = []
        for alert in alerts:
            if alert["event_uid"] not in identities:
                pending.append(alert)
                identities.add(alert["event_uid"])
        if not pending:
            return
        separator = ""
        if current_size:
            with path.open("rb") as source:
                source.seek(-1, os.SEEK_END)
                separator = "" if source.read(1) == b"\n" else "\n"
        data = separator + "".join(json.dumps(alert, ensure_ascii=True, default=str) + "\n" for alert in pending)
        if current_size + len(data.encode("utf-8")) > maximum_bytes:
            raise OSError("Persistent alert history reached its 20 MB limit; polling checkpoint was not advanced.")
        with path.open("a", encoding="utf-8") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
