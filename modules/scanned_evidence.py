"""Persistence helpers for explicitly promoted scanner results."""
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Mapping, Sequence

from modules.evidence_storage import evidence_id_for_file, save_evidence_copy
from modules.integrity import EvidenceIntegrity


AuditLogger = Callable[[str, str, str], dict[str, object]]


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as evidence_file:
        for chunk in iter(lambda: evidence_file.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _audit_entries(path: Path) -> list[dict[str, object]]:
    if not path.exists():
        return []
    return EvidenceIntegrity.read_verified_audit(path.name.removesuffix("_audit.log"), path)


def _matching_evidence_file(directory: Path, sha256_hash: str) -> Path | None:
    if not directory.exists():
        return None
    for candidate in sorted(directory.iterdir()):
        if candidate.is_file() and _sha256_file(candidate) == sha256_hash:
            return candidate
    return None


def add_scanned_evidence(
    directory: str | Path,
    filename: str,
    data: bytes | bytearray | memoryview,
    findings: Sequence[Mapping[str, object]],
    *,
    case_id: str,
    scanned_at_utc: str,
    audit_log_path: str | Path,
    audit_logger: AuditLogger = EvidenceIntegrity.log_audit_trail,
) -> dict:
    """Persist one scan result, reusing identical evidence and appending its audit link."""
    original_filename = Path(filename).name or "evidence"
    evidence_bytes = bytes(data)
    sha256_hash = hashlib.sha256(evidence_bytes).hexdigest()
    evidence_dir = Path(directory)
    audit_path = Path(audit_log_path)
    existing_entries = _audit_entries(audit_path)

    linked_findings = [{**dict(finding), "file": original_filename,
        "source_filename": original_filename, "sha256": sha256_hash,
        "scanned_at_utc": scanned_at_utc, "case_id": case_id} for finding in findings]

    for entry in existing_entries:
        if entry.get("action") != "SCANNED_EVIDENCE_ADDED":
            continue
        try:
            prior = json.loads(entry.get("details", ""))
        except (TypeError, json.JSONDecodeError) as exc:
            raise ValueError("A scanner evidence audit entry contains invalid details.") from exc
        if not isinstance(prior, dict):
            raise ValueError("A scanner evidence audit entry is not a JSON object.")
        if (
            prior.get("case_id") == case_id
            and prior.get("original_filename") == original_filename
            and prior.get("sha256") == sha256_hash
            and prior.get("scanned_at_utc") == scanned_at_utc
            and prior.get("findings") == linked_findings
        ):
            saved_path = _matching_evidence_file(evidence_dir, sha256_hash)
            if saved_path is not None:
                if _sha256_file(saved_path) != sha256_hash:
                    raise RuntimeError(
                        f"Evidence file {saved_path.name} changed while it was being verified."
                    )
                return {
                    **prior,
                    "stored_filename": saved_path.name,
                    "evidence_id": evidence_id_for_file(evidence_dir, saved_path),
                    "duplicate": True,
                }

    saved_path = _matching_evidence_file(evidence_dir, sha256_hash)
    created = saved_path is None
    if saved_path is None:
        saved_path = save_evidence_copy(evidence_dir, original_filename, evidence_bytes)
    if _sha256_file(saved_path) != sha256_hash:
        raise RuntimeError(
            f"Saved evidence file {saved_path.name} does not match the scanned SHA-256."
        )

    linked_findings = []
    for finding in findings:
        linked_findings.append({
            **dict(finding),
            "file": original_filename,
            "source_filename": original_filename,
            "sha256": sha256_hash,
            "scanned_at_utc": scanned_at_utc,
            "case_id": case_id,
        })

    record = {
        "case_id": case_id,
        "original_filename": original_filename,
        "stored_filename": saved_path.name,
        "evidence_id": evidence_id_for_file(evidence_dir, saved_path),
        "sha256": sha256_hash,
        "scanned_at_utc": scanned_at_utc,
        "findings": linked_findings,
        "duplicate": not created,
    }

    record["scan_id"] = scan_record_id(record)

    upload_details = f"File uploaded: {saved_path.name} | SHA256: {sha256_hash}"
    if not any(
        entry.get("action") == "EVIDENCE_UPLOAD"
        and entry.get("details") == upload_details
        for entry in existing_entries
    ):
        audit_logger(case_id, "EVIDENCE_UPLOAD", upload_details)

    audit_logger(
        case_id,
        "SCANNED_EVIDENCE_ADDED",
        json.dumps(record, sort_keys=True, separators=(",", ":"), default=str),
    )
    return record


def load_scanned_evidence_records(
    cases_directory: str | Path,
    sha256_hash: str | None = None,
    *, verification_warnings: list[str] | None = None, case_ids=None,
) -> list[dict]:
    """Load scanner findings from the append-only case audit logs."""
    records = []
    for audit_path in sorted(Path(cases_directory).glob("*_audit.log")):
        case_id = audit_path.name.removesuffix("_audit.log")
        if case_ids is not None and case_id not in case_ids:
            continue
        try:
            entries = _audit_entries(audit_path)
        except (OSError, ValueError) as exc:
            if verification_warnings is None:
                raise
            verification_warnings.append(str(exc))
            continue
        for entry in entries:
            if entry.get("action") != "SCANNED_EVIDENCE_ADDED":
                continue
            try:
                record = json.loads(entry.get("details", ""))
            except (TypeError, json.JSONDecodeError) as exc:
                raise ValueError(
                    f"Scanner evidence details in {audit_path.name} are invalid."
                ) from exc
            if not isinstance(record, dict):
                raise ValueError(
                    f"Scanner evidence details in {audit_path.name} are not a JSON object."
                )
            if record.get("case_id") != case_id:
                raise ValueError(f"Saved finding case ID does not match {audit_path.name}.")
            if sha256_hash is None or record.get("sha256") == sha256_hash:
                records.append(record)
    return records


def load_scanned_evidence_aliases(
    cases_directory: str | Path,
    *, verification_warnings: list[str] | None = None,
) -> dict[str, tuple[str, ...]]:
    """Map each stored evidence filename to its scanner-recorded original filenames."""
    aliases: dict[str, set[str]] = {}
    for record in load_scanned_evidence_records(cases_directory, verification_warnings=verification_warnings):
        stored_filename = record.get("stored_filename")
        original_filename = record.get("original_filename")
        if (
            isinstance(stored_filename, str)
            and Path(stored_filename).name == stored_filename
            and isinstance(original_filename, str)
            and original_filename
            and original_filename != stored_filename
        ):
            aliases.setdefault(stored_filename, set()).add(original_filename)
    return {
        stored_filename: tuple(sorted(names))
        for stored_filename, names in aliases.items()
    }


def evidence_matches_search(
    filename: str,
    aliases: Sequence[str],
    cases: str,
    query: str,
) -> bool:
    """Match vault searches against a stored filename, its scan aliases, or case IDs."""
    normalized_query = query.casefold()
    return (
        not normalized_query
        or normalized_query in filename.casefold()
        or any(normalized_query in alias.casefold() for alias in aliases)
        or normalized_query in cases.casefold()
    )


def evidence_search_display_name(
    filename: str,
    aliases: Sequence[str],
    query: str,
) -> str:
    """Prefer the matching original scan filename when a vault search finds an alias."""
    normalized_query = query.casefold()
    return next(
        (
            alias for alias in aliases
            if normalized_query and normalized_query in alias.casefold()
        ),
        filename,
    )


def scan_record_id(record):
    """Stable content identity for legacy snapshots, without modifying their audit data."""
    if record.get("scan_id"):
        return str(record["scan_id"])
    snapshot = {k: v for k, v in record.items() if k not in {"scan_id", "duplicate"}}
    return "SCAN-" + hashlib.sha256(json.dumps(snapshot, sort_keys=True,
        separators=(",", ":"), default=str).encode()).hexdigest()


def _scan_time(record):
    try:
        stamp = datetime.fromisoformat(str(record.get("scanned_at_utc", "")).replace("Z", "+00:00"))
        if stamp.tzinfo is None:
            return None
        return stamp.astimezone(timezone.utc)
    except (ValueError, TypeError):
        return None


def select_saved_scan(cases_directory, sha256_hash, *, case_ids=None, scan_id=None,
                      source_path=None):
    """Resolve a snapshot or fail closed; never fall back past an invalid latest scan.

    Equal UTC timestamps use the stable snapshot ID as a deterministic tie-break.
    Unknown times require explicit historical selection, since recency is unknown.
    All requested case chains must verify, including histories not ultimately selected.
    """
    records = load_scanned_evidence_records(cases_directory, sha256_hash, case_ids=case_ids)
    identities = {}
    for record in records:
        identity = scan_record_id(record)
        snapshot = json.dumps(record, sort_keys=True)
        if identity in identities and identities[identity] != snapshot:
            raise ValueError("Conflicting snapshots share a scan ID; selection is unavailable.")
        identities[identity] = snapshot
    if scan_id is not None:
        matches = [r for r in records if scan_record_id(r) == scan_id]
        if not matches:
            raise ValueError("The selected historical scan is unavailable or changed.")
        if len({json.dumps(r, sort_keys=True) for r in matches}) != 1:
            raise ValueError("Conflicting snapshots share the selected scan ID.")
        selected = matches[0]
    else:
        if not records:
            return None
        if any(_scan_time(r) is None for r in records):
            raise ValueError("Scan history has missing or invalid timestamps; current scan cannot be determined. Select a historical scan explicitly.")
        selected = max(records, key=lambda r: (_scan_time(r), scan_record_id(r)))
    if not isinstance(selected.get("findings"), list) or any(
        not isinstance(f, dict) or not f.get("id") or
        f.get("sha256", sha256_hash) != sha256_hash
        for f in selected["findings"]
    ):
        raise ValueError("Selected scan snapshot has invalid findings; current findings are unavailable.")
    if source_path is not None:
        EvidenceIntegrity.require_evidence(selected["case_id"], source_path,
            audit_path=Path(cases_directory) / f"{selected['case_id']}_audit.log",
            expected_hash=sha256_hash, scanned_record=selected)
    return selected


def invalidate_scan_session(state, record):
    """Discard derived session data when the complete scan snapshot changes."""
    identity = scan_record_id(record) if record else None
    if state.get("saved_scan_identity") != identity:
        for key in ("ai_report", "investigation_selected_finding", "investigation_focus",
                    "investigation_search_result"):
            state.pop(key, None)
        state["saved_scan_identity"] = identity
    return identity
