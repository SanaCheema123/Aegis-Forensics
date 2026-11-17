"""Local-only persistence for generated forensic reports."""
from __future__ import annotations

import json
import threading
from collections import deque
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
REPORT_HISTORY_PATH = ROOT / "reports" / "forensic_report_history.jsonl"
_REPORT_LOCK = threading.Lock()


def save_forensic_report(report: dict[str, Any]) -> None:
    """Append a generated report so it remains available after the browser session."""
    REPORT_HISTORY_PATH.parent.mkdir(parents=True, exist_ok=True)
    entry = json.dumps(report, ensure_ascii=True, default=str)
    with _REPORT_LOCK, REPORT_HISTORY_PATH.open("a", encoding="utf-8") as history:
        history.write(entry + "\n")


def load_forensic_reports(limit: int = 50) -> list[dict[str, Any]]:
    """Return the newest archived reports."""
    if limit < 1:
        raise ValueError("Report history limit must be positive.")
    if not REPORT_HISTORY_PATH.exists():
        return []
    with _REPORT_LOCK, REPORT_HISTORY_PATH.open("r", encoding="utf-8") as history:
        reports: deque[dict[str, Any]] = deque(maxlen=limit)
        for line_number, line in enumerate(history, start=1):
            if not line.strip():
                continue
            try:
                report = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"Forensic report history is invalid at line {line_number}.") from exc
            if isinstance(report, dict):
                reports.append(report)
    return list(reversed(reports))
