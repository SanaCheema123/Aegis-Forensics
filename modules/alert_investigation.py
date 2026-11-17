"""Adapters for explicitly promoting saved monitor alerts to case evidence."""
from __future__ import annotations

import hashlib
import io
import json
import re
import zipfile
import zlib
from pathlib import Path
from typing import Any, Callable, Mapping

from modules.integrity import EvidenceIntegrity
from modules.scanned_evidence import add_scanned_evidence
from modules.safety_checks import MAX_ARCHIVE_MEMBER_SIZE


def alert_identity(alert: Mapping[str, Any]) -> str:
    canonical = json.dumps(alert, sort_keys=True, default=str)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:16]


def _archive_details(evidence: Mapping[str, Any]) -> tuple[str, str, str]:
    """Explicit container metadata wins over the legacy virtual-path notation."""
    virtual = str(evidence.get("member_path") or evidence.get("path") or evidence.get("file") or "")
    container = str(evidence.get("container_path") or "")
    member = str(evidence.get("member") or "")
    if container and member:
        return container, member, str(evidence.get("member_path") or f"{container}!{member}")
    boundary = re.search(r"\.(?:zip|jar|apk|docx|docm|xlsx|xlsm|pptx|pptm|msix)!", virtual, re.I)
    if boundary:
        return virtual[:boundary.end() - 1], virtual[boundary.end():], virtual
    return "", "", ""


def _validated_hash(value: Any) -> str | None:
    if value is None:
        return None
    digest = str(value).casefold()
    if not re.fullmatch(r"[0-9a-f]{64}", digest):
        raise ValueError("The saved alert contains an invalid SHA-256 value.")
    return digest


def alert_file_details(alert: Mapping[str, Any]) -> tuple[str, str, str | None]:
    evidence = alert.get("evidence")
    evidence = evidence if isinstance(evidence, Mapping) else {}
    raw_path = evidence.get("path") or evidence.get("file") or alert.get("path")
    container, member, _ = _archive_details(evidence)
    full_path = container or str(raw_path or "")
    filename = Path(full_path).name if full_path else "Unknown file"
    expected_hash = _validated_hash(evidence.get("container_sha256") if member else evidence.get("sha256"))
    if member:
        _validated_hash(evidence.get("member_sha256") or evidence.get("sha256"))
    return filename, full_path, expected_hash


def alert_finding(
    alert: Mapping[str, Any],
    *,
    filename: str,
    full_path: str,
    sha256_hash: str,
) -> dict[str, Any]:
    evidence = alert.get("evidence")
    evidence = evidence if isinstance(evidence, Mapping) else {}
    rule = str(evidence.get("rule") or alert.get("source") or "Monitor alert")
    container, member, virtual_path = _archive_details(evidence)
    recorded_matches = evidence.get("evidence", [])
    matches = evidence.get("matches", [])
    report_evidence = []
    if isinstance(recorded_matches, list):
        for item in recorded_matches:
            if not isinstance(item, Mapping):
                continue
            report_evidence.append({
                **dict(item),
                "file": item.get("file", filename) if evidence.get("detection_id") else (virtual_path if member else filename),
            })
    return {
        **dict(evidence),
        "id": f"MON-{alert_identity(alert)}",
        "source": "yara" if str(alert.get("source", "")).casefold() == "yara" else str(
            alert.get("source") or "monitor"
        ),
        "rule": rule,
        "severity": str(alert.get("severity") or "Unknown"),
        "description": str(alert.get("message") or "Saved monitor alert."),
        "file": filename,
        "source_filename": filename,
        "path": full_path,
        "sha256": sha256_hash,
        **({
            "container_path": container,
            "container_sha256": sha256_hash,
            "member": member,
            "member_path": virtual_path,
            "member_sha256": _validated_hash(evidence.get("member_sha256") or evidence.get("sha256")),
        } if member else {}),
        "scanned_at_utc": str(alert.get("created_at_utc") or "Not recorded"),
        "evidence": report_evidence,
        "matches": matches if isinstance(matches, list) else [],
        "matched_strings": evidence.get("matched_strings", []),
        "technical_record": dict(alert),
    }


def promote_alert_to_evidence(
    alert: Mapping[str, Any],
    data: bytes | bytearray | memoryview,
    *,
    filename: str,
    case_id: str,
    evidence_directory: str | Path,
    audit_log_path: str | Path,
    audit_logger: Callable[[str, str, str], dict[str, object]] = EvidenceIntegrity.log_audit_trail,
) -> dict[str, Any]:
    evidence_bytes = bytes(data)
    sha256_hash = hashlib.sha256(evidence_bytes).hexdigest()
    _, full_path, expected_hash = alert_file_details(alert)
    evidence = alert.get("evidence")
    evidence = evidence if isinstance(evidence, Mapping) else {}
    _, member, _ = _archive_details(evidence)
    if member and not expected_hash:
        raise ValueError("This archive alert has no container SHA-256. Rescan the original archive before promotion.")
    if expected_hash and sha256_hash != expected_hash:
        raise ValueError(
            "The selected file does not match the SHA-256 recorded with this alert. "
            "No evidence was added."
        )
    if member:
        member_hash = _validated_hash(evidence.get("member_sha256") or evidence.get("sha256"))
        if not member_hash:
            raise ValueError("This archive alert has no embedded member SHA-256. Rescan before promotion.")
        try:
            with zipfile.ZipFile(io.BytesIO(evidence_bytes)) as archive:
                members = [info for info in archive.infolist() if info.filename == member]
                if len(members) != 1:
                    raise ValueError("The archive member is missing or ambiguous.")
                info = members[0]
                if info.file_size > MAX_ARCHIVE_MEMBER_SIZE:
                    raise ValueError("The archive member exceeds the verification size limit.")
                with archive.open(info) as stream:
                    member_bytes = stream.read(MAX_ARCHIVE_MEMBER_SIZE + 1)
                if len(member_bytes) > MAX_ARCHIVE_MEMBER_SIZE:
                    raise ValueError("The archive member exceeds the verification size limit.")
        except (OSError, EOFError, zipfile.BadZipFile, RuntimeError, zlib.error) as exc:
            raise ValueError(f"The archive member could not be verified: {exc}") from exc
        if hashlib.sha256(member_bytes).hexdigest() != member_hash:
            raise ValueError("The embedded member does not match the SHA-256 recorded with this alert. No evidence was added.")
    finding = alert_finding(
        alert,
        filename=Path(filename).name,
        full_path=full_path,
        sha256_hash=sha256_hash,
    )
    record = add_scanned_evidence(
        evidence_directory,
        filename,
        evidence_bytes,
        [finding],
        case_id=case_id,
        scanned_at_utc=finding["scanned_at_utc"],
        audit_log_path=audit_log_path,
        audit_logger=audit_logger,
    )
    return record
