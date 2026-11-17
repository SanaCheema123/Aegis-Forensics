"""Pending review notes persisted in verified, append-only case audit chains."""
import hashlib
import json
from pathlib import Path

from modules.integrity import EvidenceIntegrity

ACTION = "FINDING_MARKED_FALSE_POSITIVE_FOR_REVIEW"


def review_identity(finding, case_id):
    if not case_id:
        raise ValueError("A case ID is required to add an audited review note.")
    if finding.get("case_id") and finding["case_id"] != case_id:
        raise ValueError("The finding belongs to a different case.")
    payload = json.dumps(dict(case_id=case_id, finding=finding), sort_keys=True, default=str)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def review_status(finding, case_id, *, audit_path=None):
    key = review_identity(finding, case_id)
    path = Path(audit_path or EvidenceIntegrity._audit_path(case_id))
    if not path.exists():
        return None
    for entry in EvidenceIntegrity.read_verified_audit(case_id, path):
        if entry.get("action") != ACTION:
            continue
        try:
            note = json.loads(entry.get("details", ""))
        except (ValueError, TypeError):
            continue  # Legacy notes lack sufficient identity; do not guess.
        if isinstance(note, dict) and note.get("review_identity") == key:
            return entry
    return None


def mark_for_review(finding, case_id, *, audit_path=None):
    details = json.dumps(dict(review_identity=review_identity(finding, case_id),
        finding=finding, status="pending_false_positive_review"), sort_keys=True, default=str)
    return EvidenceIntegrity.log_audit_trail(case_id, ACTION, details,
        audit_path=audit_path, deduplicate=True)
