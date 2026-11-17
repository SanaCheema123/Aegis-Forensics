"""Local-only persistence for completed laptop scan summaries."""
from __future__ import annotations

import json
import threading
from collections import deque
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
HISTORY_PATH = ROOT / "reports" / "security_scan_history.jsonl"
_HISTORY_LOCK = threading.Lock()


def save_scan_report(report: dict[str, Any]) -> None:
    """Append one completed scan report without replacing previous records."""
    HISTORY_PATH.parent.mkdir(parents=True, exist_ok=True)
    entry = json.dumps(report, ensure_ascii=True, default=str)
    with _HISTORY_LOCK, HISTORY_PATH.open("a", encoding="utf-8") as history:
        history.write(entry + "\n")


def load_scan_history(limit: int = 100) -> list[dict[str, Any]]:
    """Return the newest valid stored reports, preserving evidence references."""
    if limit < 1:
        raise ValueError("History limit must be positive.")
    if not HISTORY_PATH.exists():
        return []
    with _HISTORY_LOCK, HISTORY_PATH.open("r", encoding="utf-8") as history:
        entries: deque[dict[str, Any]] = deque(maxlen=limit)
        for line_number, line in enumerate(history, start=1):
            if not line.strip():
                continue
            try:
                entry = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"Security scan history is invalid at line {line_number}.") from exc
            if isinstance(entry, dict):
                entries.append(entry)
    return list(reversed(entries))
