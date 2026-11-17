"""Build evidence-grounded reports from findings already linked to saved evidence."""
from __future__ import annotations

from datetime import datetime, timezone
import json
from pathlib import Path
import re
from typing import Any, Mapping

from modules.ai_reporter import DEFAULT_RECOMMENDATION, LocalLLMReporter
from modules.integrity import EvidenceIntegrity
from modules.event_timestamps import CHRONOLOGY_VERSION
from modules.report_validation import bind_report_context
from modules.scanned_evidence import scan_record_id


YARA_RECOMMENDATION = (
    "Review the matched content and verify whether this match is expected. "
    "A YARA match alone does not prove that the file is unsafe."
)


def merge_investigation_findings(saved_findings, generated_findings=()):
    """Keep saved findings authoritative; deduplicate and namespace new ID collisions."""
    merged = []
    seen = set()
    behavioral_references = set()
    used_ids = {str(item["id"]) for item in saved_findings}
    for saved, items in ((True, saved_findings), (False, generated_findings)):
        for original in items:
            finding = dict(original)
            source = str(finding.get("source") or "rule").casefold()
            rule = str(finding.get("rule", "")).removeprefix("YARA: ")
            identity = json.dumps([
                source, rule, finding.get("sha256", ""),
                finding.get("file", ""),
                finding.get("evidence") or finding.get("matches", []),
            ], sort_keys=True, default=str)
            identity = finding.get("detection_id") or identity
            references = finding.get("evidence", [])
            behavioral_reference = None
            if (rule in {"Brute force login attempts", "Successful login after brute force"}
                    and references and all(isinstance(e, dict) and 'file' in e and 'line' in e for e in references)):
                behavioral_reference = json.dumps([rule, sorted(
                    (str(e['file']), int(e['line'])) for e in references)], sort_keys=True)
            if behavioral_reference in behavioral_references:
                continue
            if identity in seen:
                continue
            seen.add(identity)
            if behavioral_reference is not None:
                behavioral_references.add(behavioral_reference)
            if not saved and str(finding["id"]) in used_ids:
                prefix = str(finding["id"]).rsplit("-", 1)[0]
                number = 1
                while f"{prefix}-{number:03d}" in used_ids:
                    number += 1
                finding["id"] = f"{prefix}-{number:03d}"
            used_ids.add(str(finding["id"]))
            merged.append(finding)
    return merged


def saved_evidence_findings(scanned_record):
    """Adapt every saved scanner finding without dropping its forensic metadata."""
    filename = scanned_record.get("original_filename")
    sha256_hash = scanned_record.get("sha256")
    scanned_at_utc = scanned_record.get("scanned_at_utc")
    report_findings = []
    for finding in scanned_record.get("findings", []):
        if not isinstance(finding, Mapping):
            continue
        if not finding.get("id"):
            raise ValueError("A saved evidence finding is missing its recorded finding ID.")
        is_yara = (
            str(finding.get("source", "")).casefold() == "yara"
            or bool(finding.get("yara_rule"))
            or str(finding["id"]).startswith("Y-")
        )
        rule = str(finding.get("yara_rule") or finding.get("rule") or "Recorded scanner finding")
        if is_yara:
            rule = rule.removeprefix("YARA: ")
        report_findings.append({
            **dict(finding),
            "source": "yara" if is_yara else str(finding.get("source") or "rule").casefold(),
            "rule": f"YARA: {rule}" if is_yara else rule,
            "yara_rule": rule if is_yara else None,
            "mitre": finding.get("mitre") or "n/a",
            "first_seen": finding.get("first_seen"),
            "last_seen": finding.get("last_seen"),
            "description": finding.get("description") or "Recorded scanner finding.",
            "users": finding.get("users", ""),
            "source_ips": finding.get("source_ips", ""),
            "hosts": finding.get("hosts", ""),
            "file": finding.get("source_filename") or finding.get("file") or filename,
            "sha256": finding.get("sha256") or sha256_hash,
            "evidence": finding.get("evidence", []),
            "matches": finding.get("matches", []),
            "recommendation": finding.get("recommendation") or (
                YARA_RECOMMENDATION if is_yara else DEFAULT_RECOMMENDATION
            ),
            "scanned_at_utc": finding.get("scanned_at_utc") or scanned_at_utc,
        })
    return merge_investigation_findings(report_findings)


def build_saved_evidence_report(
    scanned_record: Mapping[str, Any],
    evidence_id: int | str,
    source_path: str | Path,
    *,
    generated_at_utc: str | None = None,
    audit_path: str | Path | None = None,
) -> dict[str, Any]:
    """Create the existing report shape using only findings stored with the evidence."""
    case_id = scanned_record.get("case_id")
    filename = scanned_record.get("original_filename")
    sha256_hash = scanned_record.get("sha256")
    scanned_at_utc = scanned_record.get("scanned_at_utc")
    if not all((case_id, filename, sha256_hash, scanned_at_utc)):
        raise ValueError("The saved evidence record is missing required case or integrity metadata.")
    if not re.fullmatch(r"[0-9a-fA-F]{64}", str(sha256_hash)):
        raise ValueError("The saved evidence record does not contain a valid SHA-256 value.")

    audit_path = audit_path or Path(source_path).parent.parent / "cases" / f"{case_id}_audit.log"
    EvidenceIntegrity.require_evidence(
        case_id, source_path, audit_path=audit_path, expected_hash=sha256_hash,
        scanned_record=scanned_record,
    )

    report_findings = saved_evidence_findings(scanned_record)

    if not report_findings:
        raise ValueError("No recorded scan findings are linked to this saved evidence.")

    reporter = LocalLLMReporter()
    report_text = reporter.generate_grounded_report(
        "",
        "",
        findings=report_findings,
        use_llm=False,
    )
    generated_at = generated_at_utc or datetime.now(timezone.utc).isoformat()
    evidence_metadata = (
        "## Saved Evidence Record\n"
        f"- Evidence ID: {evidence_id}\n"
        f"- Filename: {filename}\n"
        f"- SHA-256: {sha256_hash}\n"
        f"- Scan timestamp (UTC): {scanned_at_utc}\n"
    )
    report_text = f"{evidence_metadata}\n{report_text}"
    EvidenceIntegrity.require_evidence(
        case_id, source_path, audit_path=audit_path, expected_hash=sha256_hash,
        scanned_record=scanned_record,
    )
    report = {
        "case_id": str(case_id),
        "chronology_version": CHRONOLOGY_VERSION,
        "evidence_id": str(evidence_id),
        "scan_id": scan_record_id(scanned_record),
        "filename": str(filename),
        "generated_at_utc": generated_at,
        "scanned_at_utc": str(scanned_at_utc),
        "investigation_started_at_utc": str(scanned_at_utc),
        "investigation_completed_at_utc": generated_at,
        "source_paths": [str(source_path)],
        "sha256": str(sha256_hash),
        "audit_verification": "Internally consistent chain and matching evidence bytes; not independently anchored authenticity.",
        "findings": reporter.last_report_findings,
        "finding_summary": reporter.last_finding_summary,
        "limitations": [
            "A YARA signature match is an investigative indicator and does not prove that the file is unsafe.",
            "This report includes only findings already linked to the selected saved evidence.",
            "A scan timestamp records when the check ran; it is not the time of the matched activity.",
        ],
        "mode": reporter.last_mode,
        "note": reporter.last_note,
        "validation": reporter.last_validation,
        "text": report_text,
    }

    entry = EvidenceIntegrity.log_audit_trail(str(case_id), "AI_REPORT_GENERATED",
        f"mode={reporter.last_mode}; source={Path(source_path).name}; findings={len(report_findings)}; "
        f"validation_passed={reporter.last_validation.get('passed')}", audit_path=audit_path)
    report["audit_trail"] = [entry]
    return bind_report_context(report, report_findings, audit_path=audit_path, scanned_record=dict(scanned_record))


def build_laptop_scan_report(scan_report, *, audit_path=None, generated_at_utc=None):
    """Report all dashboard findings from an unchanged, verified scan snapshot."""
    from modules.laptop_findings import (
        collect_laptop_findings, laptop_coverage_text, laptop_event_references, laptop_source_coverage,
    )
    EvidenceIntegrity.require_scan_report(scan_report, audit_path)
    findings = collect_laptop_findings(scan_report)
    reporter = LocalLLMReporter()
    text = reporter.generate_grounded_report('', '', findings=findings, use_llm=False, include_all_findings=True)
    coverage = laptop_source_coverage(scan_report)
    record = dict(
        case_id=scan_report['case_id'], chronology_version=CHRONOLOGY_VERSION,
        generated_at_utc=generated_at_utc or datetime.now(timezone.utc).isoformat(),
        investigation_started_at_utc=scan_report.get('started_at_utc'),
        investigation_completed_at_utc=scan_report.get('completed_at_utc'),
        source_paths=[scan_report['root']] if scan_report.get('root') else [],
        sha256='', scan_snapshot_sha256=EvidenceIntegrity.scan_snapshot_hash(scan_report),
        findings=findings, finding_summary=reporter.last_finding_summary,
        source_coverage=coverage, windows_event_references=laptop_event_references(findings),
        limitations=[
            'Automated findings are investigative indicators and do not establish compromise.',
            'File hashes are verified against current accessible bytes at export; a hash does not establish independent authenticity.',
            'System observations describe the recorded scan snapshot and are not immutable forensic artifacts or claims about the current live system.',
            'Missing hashes, event identifiers and collection timestamps are not inferred.',
            'Source collection uses bounded queries. Unavailable, partial and unrecorded data do not imply a clean result.',
        ],
        text=laptop_coverage_text(scan_report) + text,
        mode=reporter.last_mode, note=reporter.last_note, validation=reporter.last_validation,
    )
    EvidenceIntegrity.require_scan_report(scan_report, audit_path)
    entry = EvidenceIntegrity.log_audit_trail(scan_report['case_id'], 'LAPTOP_FORENSIC_REPORT_GENERATED',
        f"findings={len(findings)}; source={scan_report.get('root', 'not recorded')}; "
        f"snapshot_sha256={record['scan_snapshot_sha256']}", audit_path=audit_path)
    record['audit_trail'] = [*scan_report.get('audit_trail', []), entry]
    return bind_report_context(record, findings, audit_path=audit_path, scan_report=scan_report)
