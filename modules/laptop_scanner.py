"""Bounded, read-only local file and Windows context scanning."""
from __future__ import annotations

import hashlib
import os
import stat
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from modules.safety_checks import (
    SCAN_EXTENSIONS,
    _file_type,
    inspect_content,
    inspect_pdf_content,
    scan_embedded_content,
)

MAX_LAPTOP_FILES = 3000
MAX_LAPTOP_FILE_SIZE = 50 * 1024 * 1024
MAX_SCAN_SECONDS = 15 * 60
MAX_FINDINGS = 1000
SEVERITY_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            size += len(chunk)
            if size > MAX_LAPTOP_FILE_SIZE:
                raise ValueError("File exceeded the 50 MB scan limit while being read.")
            digest.update(chunk)
    return digest.hexdigest()


def _is_reparse_point(path: Path) -> bool:
    try:
        attributes = path.stat(follow_symlinks=False).st_file_attributes
    except (AttributeError, OSError):
        return path.is_symlink()
    return bool(attributes & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))


def analyze_file(
    path: str | Path,
    scanner: Any,
    timeout: int = 5,
    max_file_size: int = MAX_LAPTOP_FILE_SIZE,
) -> dict[str, Any]:
    """Inspect a file without executing it; return evidence-backed indicators."""
    file_path = Path(path)
    before = file_path.stat()
    size = before.st_size
    if size > max_file_size:
        return {
            "path": str(file_path),
            "skipped": True,
            "reason": f"File exceeds the {max_file_size // (1024 * 1024)} MB scan limit.",
        }

    with file_path.open("rb") as source:
        prefix = source.read(256 * 1024)
    digest = _sha256(file_path)
    indicators = inspect_content(file_path.name, prefix)
    pdf_warnings = []
    if file_path.suffix.lower() == ".pdf":
        pdf_indicators, pdf_warnings = inspect_pdf_content(file_path.read_bytes())
        indicators.extend(pdf_indicators)
    yara_findings = scanner.scan_file(file_path, timeout=timeout) if scanner.ready else []
    embedded_warnings = []
    if prefix.startswith(b"PK\x03\x04"):
        embedded_findings, embedded_warnings = scan_embedded_content(
            str(file_path),
            file_path.read_bytes(),
            scanner,
        )
        for finding in embedded_findings:
            yara_findings.append({
                **finding,
                "rule": f"Embedded content: {finding.get('rule', 'YARA match')}",
                "description": (
                    f"{finding.get('description', 'YARA match')} "
                    f"Matched archive member: {finding.get('member', 'unknown member')}."
                ),
                "container_sha256": digest,
            })
    after = file_path.stat()
    if (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
        raise OSError("File changed during inspection; wait for it to become stable and retry.")
    findings = [
        {
            "severity": indicator["severity"],
            "source": "Static heuristic",
            "rule": indicator["description"],
            "description": indicator["description"],
            "path": str(file_path),
            "sha256": digest,
            "evidence": (
                [{"file": str(file_path), "line": indicator["line"]}]
                if "line" in indicator
                else [{"file": str(file_path), "page": indicator["page"]}]
                if "page" in indicator
                else []
            ),
            "matches": (
                [{"offset": indicator["offset"]}]
                if "offset" in indicator
                else [{"page": indicator["page"]}]
                if "page" in indicator
                else []
            ),
            "recommended_action": (
                "Preserve the file, avoid opening it, and validate the indicator with trusted security tooling."
                if indicator["severity"] in {"High", "Critical"}
                else "Review the referenced file content and verify its origin before opening."
            ),
        }
        for indicator in indicators
    ]
    for finding in yara_findings:
        findings.append({
            **finding,
            "severity": finding.get("severity", "Medium"),
            "source": "YARA",
            "rule": finding.get("rule", "YARA match"),
            "description": finding.get("description", ""),
            "confidence": finding.get("confidence", "rule match"),
            "content_type": finding.get("content_type", "unknown"),
            "severity_reason": finding.get("severity_reason", ""),
            "matched_strings": finding.get("matched_strings", []),
            "match_count": finding.get("match_count", len(finding.get("matches", []))),
            "matches_truncated": finding.get("matches_truncated", False),
            "path": (
                f"{file_path}!{finding['member']}"
                if finding.get("member")
                else str(file_path)
            ),
            "sha256": finding.get("sha256", digest),
            "container_sha256": finding.get("container_sha256", digest),
            **({
                "container_path": str(file_path),
                "member": finding["member"],
                "member_path": f"{file_path}!{finding['member']}",
                "member_sha256": finding.get("sha256"),
            } if finding.get("member") else {}),
            "evidence": finding.get("matches", []),
            "matches": finding.get("matches", []),
            "recommended_action": (
                "Preserve the file and validate this rule match before considering remediation."
            ),
        })
    return {
        "path": str(file_path),
        "size": size,
        "sha256": digest,
        "detected_type": _file_type(prefix),
        "findings": findings,
        "warnings": pdf_warnings + embedded_warnings,
        "skipped": False,
    }


def scan_laptop(
    root: str | Path,
    scanner: Any,
    progress_callback: Callable[[int, int, str], None] | None = None,
    max_files: int = MAX_LAPTOP_FILES,
    max_file_size: int = MAX_LAPTOP_FILE_SIZE,
    max_seconds: int = MAX_SCAN_SECONDS,
    max_findings: int = MAX_FINDINGS,
) -> dict[str, Any]:
    """Recursively inspect supported files under one user-selected directory."""
    scan_root = Path(root).expanduser()
    if not scan_root.exists() or not scan_root.is_dir():
        raise ValueError("Choose an existing directory on this computer.")
    if scan_root.is_symlink() or _is_reparse_point(scan_root):
        raise ValueError("The selected directory is a symbolic link or Windows reparse point.")
    if not 1 <= max_files <= MAX_LAPTOP_FILES:
        raise ValueError(f"The scan file limit must be between 1 and {MAX_LAPTOP_FILES}.")
    if not 1 <= max_file_size <= MAX_LAPTOP_FILE_SIZE:
        raise ValueError(
            f"The per-file limit must be between 1 byte and {MAX_LAPTOP_FILE_SIZE} bytes."
        )
    if not 1 <= max_seconds <= MAX_SCAN_SECONDS:
        raise ValueError(
            f"The scan duration must be between 1 and {MAX_SCAN_SECONDS} seconds."
        )
    if not 1 <= max_findings <= MAX_FINDINGS:
        raise ValueError(f"The findings limit must be between 1 and {MAX_FINDINGS}.")

    started = datetime.now(timezone.utc).isoformat()
    start_clock = time.monotonic()
    findings: list[dict[str, Any]] = []
    errors: list[str] = []
    warnings: list[str] = []
    checked = 0
    skipped = 0
    files_seen = 0
    supported_files_seen = 0
    unsupported_files = 0
    directories_skipped = 0
    error_count = 0
    limit_reached = False
    traversal_complete = True

    def record_walk_error(error: OSError) -> None:
        nonlocal error_count, traversal_complete
        error_count += 1
        traversal_complete = False
        errors.append(str(error))

    for directory, child_dirs, filenames in os.walk(
        scan_root,
        topdown=True,
        onerror=record_walk_error,
        followlinks=False,
    ):
        if time.monotonic() - start_clock >= max_seconds:
            limit_reached = True
            traversal_complete = False
            break
        current_dir = Path(directory)
        skipped_dirs = [
            name for name in child_dirs
            if _is_reparse_point(current_dir / name)
        ]
        directories_skipped += len(skipped_dirs)
        child_dirs[:] = [
            name for name in child_dirs
            if not _is_reparse_point(current_dir / name)
        ]
        for filename in filenames:
            path = current_dir / filename
            files_seen += 1
            if path.suffix.lower() not in SCAN_EXTENSIONS:
                unsupported_files += 1
                skipped += 1
                continue
            supported_files_seen += 1
            if _is_reparse_point(path):
                skipped += 1
                continue
            if checked + (skipped - unsupported_files) >= max_files:
                skipped += 1
                limit_reached = True
                traversal_complete = False
                break
            if time.monotonic() - start_clock >= max_seconds:
                skipped += 1
                limit_reached = True
                traversal_complete = False
                break
            try:
                result = analyze_file(path, scanner, max_file_size=max_file_size)
                if result["skipped"]:
                    skipped += 1
                else:
                    checked += 1
                    findings.extend(result["findings"])
                    warnings.extend(result["warnings"])
                    if len(findings) > max_findings:
                        findings = findings[:max_findings]
                        limit_reached = True
                        traversal_complete = False
                        break
                if progress_callback and (checked + skipped - unsupported_files) % 10 == 0:
                    progress_callback(
                        checked + skipped - unsupported_files,
                        max_files,
                        str(path),
                    )
            except Exception as exc:
                error_count += 1
                errors.append(f"{path}: {exc}")
                skipped += 1
                if len(errors) > 200:
                    errors.pop()
        if limit_reached:
            break

    if progress_callback:
        progress_callback(
            checked + skipped - unsupported_files,
            max_files,
            "Scan complete" if traversal_complete else "Scan stopped before the selected scope was complete",
        )
    findings.sort(key=lambda item: (
        SEVERITY_ORDER.get(item["severity"], 9),
        item["path"].lower(),
        item["rule"],
    ))
    coverage_percent = (
        round(checked / supported_files_seen * 100, 2)
        if traversal_complete and supported_files_seen
        else 100.0 if traversal_complete else None
    )
    scan_complete = (
        traversal_complete
        and not limit_reached
        and skipped == 0
        and error_count == 0
    )
    return {
        "root": str(scan_root.resolve()),
        "started_at_utc": started,
        "completed_at_utc": datetime.now(timezone.utc).isoformat(),
        "files_seen": files_seen,
        "supported_files_seen": supported_files_seen,
        "unsupported_files": unsupported_files,
        "files_checked": checked,
        "files_skipped": skipped,
        "directories_skipped": directories_skipped,
        "error_count": error_count,
        "findings": findings,
        "errors": errors[:200],
        "warnings": warnings[:200],
        "limit_reached": limit_reached,
        "traversal_complete": traversal_complete,
        "scan_complete": scan_complete,
        "coverage_percent": coverage_percent,
        "max_files": max_files,
        "max_file_size": max_file_size,
        "max_seconds": max_seconds,
        "max_findings": max_findings,
        "yara_available": bool(scanner.ready),
        "scope": "Read-only local file review; no file was executed, deleted, or quarantined.",
    }
