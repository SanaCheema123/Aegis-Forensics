import hashlib
import json
import os
import re
import threading
import time
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path

GENESIS_HASH = "0" * 64
CASES_DIR = Path(__file__).resolve().parents[1] / "data" / "cases"
_LOCKS = {}
_LOCKS_GUARD = threading.Lock()


class AuditVerificationError(ValueError):
    """A case cannot be trusted; its original records remain untouched."""


@contextmanager
def audit_lock(path, timeout=10):
    """Serialize readers/writers using a sidecar byte lock across Windows processes."""
    path = Path(path).resolve()
    path.parent.mkdir(parents=True, exist_ok=True)
    with _LOCKS_GUARD:
        lock = _LOCKS.setdefault(str(path).casefold(), threading.RLock())
    if not lock.acquire(timeout=timeout):
        raise TimeoutError(f"Timed out acquiring audit lock: {path.name}")
    try:
        with Path(str(path) + ".lock").open("a+b") as stream:
            stream.seek(0, os.SEEK_END)
            if stream.tell() == 0:
                stream.write(b"\0")
                stream.flush()
            deadline = time.monotonic() + timeout
            while True:
                try:
                    stream.seek(0)
                    if os.name == "nt":
                        import msvcrt
                        msvcrt.locking(stream.fileno(), msvcrt.LK_NBLCK, 1)
                    else:
                        import fcntl
                        fcntl.flock(stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                    break
                except OSError:
                    if time.monotonic() >= deadline:
                        raise TimeoutError(f"Timed out acquiring audit lock: {path.name}")
                    time.sleep(0.05)
            try:
                yield
            finally:
                stream.seek(0)
                if os.name == "nt":
                    import msvcrt
                    msvcrt.locking(stream.fileno(), msvcrt.LK_UNLCK, 1)
                else:
                    import fcntl
                    fcntl.flock(stream.fileno(), fcntl.LOCK_UN)
    finally:
        lock.release()


class EvidenceIntegrity:
    @staticmethod
    def calculate_sha256(file_path: str) -> str:
        """Calculates SHA-256 hash of digital evidence to ensure chain of custody."""
        sha256_hash = hashlib.sha256()
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(65536), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()

    @staticmethod
    def verify_file(file_path: str, expected_hash: str) -> bool:
        """True if the file still matches the hash recorded at upload time."""
        actual = EvidenceIntegrity.calculate_sha256(file_path)
        return actual.lower() == expected_hash.lower()

    @staticmethod
    def _audit_path(case_id: str) -> str:
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]*", str(case_id)):
            raise ValueError("Invalid case ID.")
        return str(CASES_DIR / f"{case_id}_audit.log")

    @staticmethod
    def _entry_hash(entry: dict) -> str:
        """Hash of an entry (without its own entry_hash field)."""
        body = {k: v for k, v in entry.items() if k != "entry_hash"}
        canonical = json.dumps(body, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    @staticmethod
    def _read_chain(path, case_id):
        """Read and validate one snapshot while the caller holds its audit lock."""
        entries = []
        previous = GENESIS_HASH
        with Path(path).open("r", encoding="utf-8") as stream:
            for number, line in enumerate(stream, 1):
                if not line.strip():
                    continue
                try:
                    entry = json.loads(line)
                except (ValueError, TypeError) as exc:
                    raise AuditVerificationError(f"Invalid audit JSON at entry {number}.") from exc
                if not isinstance(entry, dict):
                    raise AuditVerificationError(f"Invalid audit record at entry {number}.")
                if not {"prev_hash", "entry_hash"} <= entry.keys():
                    raise AuditVerificationError(f"Legacy unchained record at entry {number}; verification unavailable. Original records were not changed.")
                if entry.get("case_id") != case_id:
                    raise AuditVerificationError(f"Case ID mismatch at entry {number}.")
                if entry["prev_hash"] != previous:
                    raise AuditVerificationError(f"Chain broken at entry {number} (entry changed or removed).")
                if EvidenceIntegrity._entry_hash(entry) != entry["entry_hash"]:
                    raise AuditVerificationError(f"Entry {number} was modified.")
                previous = entry["entry_hash"]
                entries.append(entry)
        if not entries:
            raise AuditVerificationError("Audit log is empty; verification unavailable.")
        return entries

    @staticmethod
    def log_audit_trail(case_id: str, action: str, details: str, *, audit_path=None, deduplicate=False) -> dict:
        """Append under lock only to a valid chain; never repair existing records.

        Without an external anchor, tail truncation or a complete rewrite may
        remain internally consistent and cannot establish authenticity.
        """
        audit_file = Path(audit_path or EvidenceIntegrity._audit_path(case_id))
        with audit_lock(audit_file):
            entries = EvidenceIntegrity._read_chain(audit_file, case_id) if audit_file.exists() else []
            if deduplicate:
                for prior in entries:
                    if prior.get("action") == action and prior.get("details") == details:
                        return prior
            entry = {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "case_id": case_id,
                "action": action,
                "details": details,
                "prev_hash": entries[-1]["entry_hash"] if entries else GENESIS_HASH,
            }
            entry["entry_hash"] = EvidenceIntegrity._entry_hash(entry)
            # Preserve a valid last record even if its final newline is absent.
            separator = ""
            if audit_file.exists():
                with audit_file.open("rb") as source:
                    source.seek(-1, os.SEEK_END)
                    separator = "" if source.read(1) == b"\n" else "\n"
            with audit_file.open("a", encoding="utf-8") as stream:
                stream.write(separator + json.dumps(entry) + "\n")
                stream.flush()
                os.fsync(stream.fileno())
        return entry

    @staticmethod
    def verify_audit_trail(case_id: str, audit_path=None):
        """Re-check the whole chain. Returns (is_valid, message)."""
        audit_file = Path(audit_path or EvidenceIntegrity._audit_path(case_id))
        if not audit_file.exists():
            return False, "Audit log not found"
        try:
            with audit_lock(audit_file):
                EvidenceIntegrity._read_chain(audit_file, case_id)
        except (OSError, ValueError, UnicodeError) as exc:
            return False, str(exc)
        return True, "Audit chain internally consistent. An unanchored chain does not prove authenticity or detect all truncation by a privileged attacker."

    @staticmethod
    def read_verified_audit(case_id, audit_path=None):
        path = Path(audit_path or EvidenceIntegrity._audit_path(case_id))
        valid, message = EvidenceIntegrity.verify_audit_trail(case_id, path)
        if not valid:
            raise AuditVerificationError(f"Case {case_id}: {message}")
        # Revalidate the consumed snapshot under lock, rather than trusting a prior check.
        with audit_lock(path):
            return EvidenceIntegrity._read_chain(path, case_id)

    @staticmethod
    def require_evidence(case_id, file_path, *, audit_path=None, expected_hash=None, scanned_record=None):
        """Require a verified case, a recorded upload, and matching current bytes."""
        entries = EvidenceIntegrity.read_verified_audit(case_id, audit_path)
        path = Path(file_path)
        digest = EvidenceIntegrity.calculate_sha256(str(path))
        if expected_hash is not None and digest != str(expected_hash).lower():
            raise AuditVerificationError("Evidence bytes do not match the expected SHA-256.")
        upload = f"File uploaded: {path.name} | SHA256: {digest}"
        if not any(entry.get("action") == "EVIDENCE_UPLOAD" and entry.get("details") == upload
                   for entry in entries):
            raise AuditVerificationError("Evidence has no matching upload in the verified case audit chain.")
        if scanned_record is not None and not any(
            entry.get("action") == "SCANNED_EVIDENCE_ADDED"
            and json.loads(entry.get("details", "null")) == dict(scanned_record)
            for entry in entries
        ):
            raise AuditVerificationError("Saved findings do not match the verified case audit record.")
        return digest

    @staticmethod
    def scan_snapshot_hash(report):
        snapshot = {key: value for key, value in report.items() if key != "audit_trail"}
        return hashlib.sha256(json.dumps(snapshot, sort_keys=True, default=str).encode("utf-8")).hexdigest()

    @staticmethod
    def require_scan_report(report, audit_path=None):
        """Bind laptop report findings to a scan snapshot recorded in a valid chain."""
        entries = EvidenceIntegrity.read_verified_audit(report.get("case_id"), audit_path)
        suffix = f"; snapshot_sha256={EvidenceIntegrity.scan_snapshot_hash(report)}"
        if not any(entry.get("action") == "LAPTOP_SCAN_COMPLETED"
                   and str(entry.get("details", "")).endswith(suffix) for entry in entries):
            raise AuditVerificationError("Scan snapshot is unverified or legacy (no matching snapshot hash). Run a new scan; existing history was not changed.")
